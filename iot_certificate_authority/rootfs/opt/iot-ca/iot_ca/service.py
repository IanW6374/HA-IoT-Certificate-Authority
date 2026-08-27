"""Certificate inventory and export orchestration."""

from __future__ import annotations

import base64
import io
import json
import os
import re
import secrets
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .database import Inventory, utc_now
from .engine import StepCAEngine
from .external_acme import ExternalACME
from .profiles import PROFILES, validate_request


class CertificateService:
    EXPORT_LIFETIME = timedelta(minutes=15)
    ROOT_EXPORT_LIFETIME = timedelta(days=7)
    DEVICE_ENROLLMENT_LIFETIME = timedelta(minutes=30)
    PORTAL_HOST = re.compile(
        r"^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$"
    )
    REVOCABLE_PUBLIC_PROVISIONER = "letsencrypt-cloudflare-dns01-account-v1"

    def __init__(
        self, data_root: Path | str, *, engine=None, inventory=None,
        external_acme=None,
    ):
        self.data_root = Path(data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.exports_path = self.data_root / "exports"
        self.exports_path.mkdir(mode=0o700, exist_ok=True)
        self.engine = engine or StepCAEngine(self.data_root)
        self.inventory = inventory or Inventory(self.data_root / "inventory.db")
        self.external_acme = external_acme or ExternalACME(self.data_root)

    @property
    def initialized(self):
        return self.engine.initialized

    def settings(self):
        values = self.engine.settings()
        values["external_acme"] = self.external_acme.settings()
        return values

    def configure_external_acme(self, **values):
        try:
            settings = self.external_acme.configure(**values)
            self.inventory.audit(
                "external-acme.configure",
                detail={
                    "enabled": settings["enabled"],
                    "provider": settings["provider"],
                    "zone": settings["zone"],
                    "environment": settings["environment"],
                    "dns_token_configured": settings["dns_token_configured"],
                    "zone_token_configured": settings["zone_token_configured"],
                    "auto_enroll_enabled": settings["auto_enroll_enabled"],
                    "auto_enroll_minutes": settings["auto_enroll_minutes"],
                    "provisioning_host": settings["provisioning_host"],
                    "provisioning_port": settings["provisioning_port"],
                },
            )
            return settings
        except Exception as exc:
            self.inventory.audit(
                "external-acme.configure", success=False,
                detail={"error": str(exc)},
            )
            raise

    def configure_service_ports(self, **values):
        try:
            settings = self.engine.configure_service_ports(**values)
            self.inventory.audit(
                "ca.service-ports.configure",
                detail={
                    "ca_port": settings["ca_port"],
                    "provisioning_port": settings["provisioning_port"],
                },
            )
            return settings
        except Exception as exc:
            self.inventory.audit(
                "ca.service-ports.configure", success=False,
                detail={"error": str(exc)},
            )
            raise

    def set_automatic_enrollment(self, enabled: bool):
        try:
            settings = self.external_acme.set_auto_enrollment(enabled)
            self.inventory.audit(
                "device-enrollment.window-open" if enabled
                else "device-enrollment.window-close",
                detail={
                    "duration_minutes": settings["auto_enroll_minutes"],
                    "open_until": settings["auto_enroll_until"],
                },
            )
            return settings
        except Exception as exc:
            self.inventory.audit(
                "device-enrollment.window-open" if enabled
                else "device-enrollment.window-close",
                success=False, detail={"error": str(exc)},
            )
            raise

    def _authorize_device_enrollment(self, portal_host: str, source="manual"):
        external = self.external_acme.settings()
        ca_settings = self.engine.settings()
        if not external.get("enabled"):
            raise ValueError("Enable public ACME issuance before creating an enrollment")
        portal_host = str(portal_host or "").strip().lower()
        if not self.PORTAL_HOST.fullmatch(portal_host):
            raise ValueError(
                "The portal host must be one DNS label containing only letters, "
                "numbers, or internal hyphens"
            )
        enrollment_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        portal_hostname = portal_host + "." + external["zone"]
        api_hostname = portal_host + ".local"
        renewal_name = "iotmd-renewal-" + enrollment_id
        expires = datetime.now(timezone.utc) + self.DEVICE_ENROLLMENT_LIFETIME
        expires_at = expires.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.inventory.add_device_enrollment(
            enrollment_id=enrollment_id,
            token=token,
            portal_hostname=portal_hostname,
            api_hostname=api_hostname,
            renewal_name=renewal_name,
            expires_at=expires_at,
        )
        root = x509.load_pem_x509_certificate(self.engine.root_certificate())
        package = {
            "protocol": "iotmd-enrollment-v1",
            "enrollment_id": enrollment_id,
            "endpoint": (
                "https://" + ca_settings["ca_dns"] + ":" +
                str(ca_settings["provisioning_port"])
            ),
            "token": token,
            "portal_hostname": portal_hostname,
            "api_hostname": api_hostname,
            "renewal_name": renewal_name,
            "ca_root_der": self._b64(
                root.public_bytes(serialization.Encoding.DER)
            ),
            "expires_at": expires_at,
        }
        self.inventory.audit(
            "device-enrollment.authorize", enrollment_id,
            detail={
                "portal_hostname": portal_hostname,
                "api_hostname": api_hostname,
                "expires_at": expires_at,
                "source": source,
            },
        )
        return enrollment_id, package

    def create_device_enrollment(self, portal_host: str):
        enrollment_id, package = self._authorize_device_enrollment(portal_host)
        export_token = self._store_export(
            (json.dumps(package, indent=2, sort_keys=True) + "\n").encode(),
            kind="device-enrollment",
            filename=portal_host + ".iotenroll",
            lifetime=self.DEVICE_ENROLLMENT_LIFETIME,
        )
        return enrollment_id, export_token

    def create_automatic_device_enrollment(self, api_hostname: str):
        external = self.external_acme.settings()
        if not external.get("auto_enroll_enabled"):
            raise PermissionError("Automatic IoT MD enrollment is not enabled")
        api_hostname = str(api_hostname or "").strip().lower().rstrip(".")
        if not api_hostname.endswith(".local") or api_hostname.count(".") != 1:
            raise ValueError("The Device API hostname must be one .local host name")
        portal_host = api_hostname[:-6]
        _enrollment_id, package = self._authorize_device_enrollment(
            portal_host, source="automatic-lan"
        )
        return package

    def claim_device_enrollment(self, enrollment_id, token, request_value):
        enrollment = self.inventory.claim_device_enrollment(
            str(enrollment_id), str(token), request_value
        )
        if not enrollment:
            raise PermissionError("Unknown enrollment or invalid token")
        if enrollment["status"] == "expired":
            raise PermissionError("Enrollment authorization has expired")
        return enrollment

    def device_enrollment_status(self, enrollment_id, token):
        enrollment = self.inventory.device_enrollment(str(enrollment_id), str(token))
        if not enrollment:
            raise PermissionError("Unknown enrollment or invalid token")
        return {
            "status": enrollment["status"],
            "error": enrollment.get("error"),
            "result": enrollment.get("result"),
        }

    def fulfill_device_enrollment(self, enrollment_id):
        enrollment = self.inventory.device_enrollment_by_id(str(enrollment_id))
        if not enrollment or enrollment["status"] != "pending":
            return
        try:
            request_value = enrollment.get("request") or {}
            portal_csr = self._enrollment_csr(
                request_value.get("portal_csr"), enrollment["portal_hostname"],
                require_san=True, required_usage=ExtendedKeyUsageOID.SERVER_AUTH,
            )
            api_csr = self._enrollment_csr(
                request_value.get("api_csr"), enrollment["api_hostname"],
                require_san=True, required_usage=ExtendedKeyUsageOID.SERVER_AUTH,
            )
            renewal_csr = self._enrollment_csr(
                request_value.get("renewal_csr"), enrollment["renewal_name"],
                require_san=False, required_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            public_certificate_id = str(uuid.uuid4())
            public = self.external_acme.issue_csr(
                portal_csr.public_bytes(serialization.Encoding.PEM),
                certificate_id=public_certificate_id,
            )
            api_pem = self.engine.sign(
                csr_pem=api_csr.public_bytes(serialization.Encoding.PEM),
                common_name=enrollment["api_hostname"],
                sans=[enrollment["api_hostname"]],
                validity_days=365,
            )
            renewal_pem = self.engine.sign(
                csr_pem=renewal_csr.public_bytes(serialization.Encoding.PEM),
                common_name=enrollment["renewal_name"], sans=[], validity_days=365,
            )
            api_certificate = x509.load_pem_x509_certificate(api_pem)
            renewal_certificate = x509.load_pem_x509_certificate(renewal_pem)
            self._record_enrolled_certificate(
                public.certificate, "public-portal", enrollment["portal_hostname"],
                [enrollment["portal_hostname"]], "external-acme",
                self.REVOCABLE_PUBLIC_PROVISIONER, public.certificate_pem,
                certificate_id=public_certificate_id,
            )
            self._record_enrolled_certificate(
                api_certificate, "tls-server", enrollment["api_hostname"],
                [enrollment["api_hostname"]], "manual",
                "iotmd-device-enrollment", api_pem,
            )
            self._record_enrolled_certificate(
                renewal_certificate, "tls-client", enrollment["renewal_name"],
                [], "manual", "iotmd-renewal-identity", renewal_pem,
            )
            root = x509.load_pem_x509_certificate(self.engine.root_certificate())
            intermediate = x509.load_pem_x509_certificate(
                self.engine.intermediate_certificate()
            )
            api_chain_pem = (
                api_pem.rstrip() + b"\n" +
                self.engine.intermediate_certificate().lstrip()
            )
            result = {
                "protocol": "iotmd-enrollment-v1",
                "portal_hostname": enrollment["portal_hostname"],
                "api_hostname": enrollment["api_hostname"],
                "portal_certificate_pem": self._b64(public.fullchain_pem),
                "api_certificate_pem": self._b64(api_chain_pem),
                "renewal_certificate_der": self._b64(
                    renewal_certificate.public_bytes(serialization.Encoding.DER)
                ),
                "ca_root_der": self._b64(
                    root.public_bytes(serialization.Encoding.DER)
                ),
                "ca_intermediate_der": self._b64(
                    intermediate.public_bytes(serialization.Encoding.DER)
                ),
                "portal_not_after": self._certificate_time(
                    public.certificate, "not_valid_after"
                ),
            }
            self.inventory.complete_device_enrollment(enrollment_id, result)
            self.inventory.audit(
                "device-enrollment.complete", enrollment_id,
                detail={
                    "portal_hostname": enrollment["portal_hostname"],
                    "api_hostname": enrollment["api_hostname"],
                },
            )
        except Exception as exc:
            self.inventory.fail_device_enrollment(enrollment_id, str(exc))
            self.inventory.audit(
                "device-enrollment.complete", enrollment_id, success=False,
                detail={"error": str(exc)},
            )
            raise

    def _enrollment_csr(self, encoded, expected_name, *, require_san, required_usage):
        try:
            payload = base64.b64decode(str(encoded), validate=True)
            csr = x509.load_der_x509_csr(payload)
        except Exception as exc:
            raise ValueError("Enrollment contains an invalid certificate request") from exc
        if not csr.is_signature_valid:
            raise ValueError("Enrollment certificate request signature is invalid")
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_names) != 1 or common_names[0].value != expected_name:
            raise ValueError("Enrollment certificate request identity does not match authorization")
        try:
            sans = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        if (require_san and sans != [expected_name]) or (not require_san and sans):
            raise ValueError("Enrollment certificate request SAN does not match authorization")
        try:
            usages = csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            usages = []
        if required_usage not in usages:
            raise ValueError("Enrollment certificate request has the wrong key usage")
        if not isinstance(csr.public_key(), ec.EllipticCurvePublicKey) or not isinstance(
            csr.public_key().curve, ec.SECP256R1
        ):
            raise ValueError("Enrollment certificate requests must use P-256 keys")
        return csr

    def _record_enrolled_certificate(
        self, certificate, profile, common_name, sans, source, provisioner,
        certificate_pem, certificate_id=None,
    ):
        validity = max(
            1,
            (
                self._certificate_datetime(certificate, "not_valid_after") -
                self._certificate_datetime(certificate, "not_valid_before")
            ).days,
        )
        self.inventory.add_certificate({
            "id": str(certificate_id or uuid.uuid4()), "profile": profile,
            "common_name": common_name, "sans_json": json.dumps(sans),
            "key_type": "ec-p256", "validity_days": validity,
            "serial": str(certificate.serial_number),
            "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": self._certificate_time(certificate, "not_valid_before"),
            "not_after": self._certificate_time(certificate, "not_valid_after"),
            "status": "active", "certificate_pem": certificate_pem,
            "created_at": utc_now(), "renewed_from": None, "revoked_at": None,
            "source": source, "provisioner": provisioner,
        })

    @staticmethod
    def _b64(value):
        return base64.b64encode(bytes(value)).decode("ascii")

    def initialize(self, **values):
        try:
            archive, settings = self.engine.initialize(**values)
            token = self._store_export(
                archive,
                kind="offline-root",
                filename="iot-ca-offline-root.zip",
                lifetime=self.ROOT_EXPORT_LIFETIME,
            )
            self.inventory.audit(
                "ca.initialize",
                success=True,
                detail={
                    "ca_name": settings["ca_name"],
                    "ca_dns": settings["ca_dns"],
                    "allowed_dns_suffix": settings["allowed_dns_suffix"],
                },
            )
            return token
        except Exception as exc:
            self.inventory.audit("ca.initialize", success=False, detail={"error": str(exc)})
            raise

    def issue(
        self,
        *,
        profile_slug: str,
        common_name: str,
        sans,
        key_type: str,
        validity_days: int,
        export_format: str,
        export_password: str = "",
        renewed_from: str | None = None,
    ):
        if profile_slug == "public-portal":
            raise ValueError("Use the public portal issuance workflow for external ACME")
        if not self.initialized:
            raise ValueError("Initialize the certificate authority before issuing certificates")
        settings = self.settings()
        request = validate_request(
            profile_slug=profile_slug,
            common_name=common_name,
            sans=sans,
            key_type=key_type,
            validity_days=validity_days,
            export_format=export_format,
            allowed_suffix=settings["allowed_dns_suffix"],
            allow_public=bool(settings.get("allow_public_sans", False)),
        )
        if export_format == "pkcs12" and len(export_password or "") < 12:
            raise ValueError("PKCS#12 exports require a password of at least 12 characters")
        profile = request["profile"]
        issuance_sans = request["sans"] or [request["common_name"]]
        certificate_id = str(uuid.uuid4())
        try:
            private_key = self._private_key(request["key_type"])
            csr = self._csr(
                private_key,
                common_name=request["common_name"],
                sans=issuance_sans,
                server_auth=profile.server_auth,
                client_auth=profile.client_auth,
            )
            certificate_pem = self.engine.sign(
                csr_pem=csr.public_bytes(serialization.Encoding.PEM),
                common_name=request["common_name"],
                sans=issuance_sans,
                validity_days=request["validity_days"],
            )
            certificate = x509.load_pem_x509_certificate(certificate_pem)
            archive, extension = self._export(
                export_format=request["export_format"],
                common_name=request["common_name"],
                profile_slug=profile.slug,
                certificate=certificate,
                certificate_pem=certificate_pem,
                private_key=private_key,
                export_password=export_password,
            )
            record = {
                "id": certificate_id,
                "profile": profile.slug,
                "common_name": request["common_name"],
                "sans_json": json.dumps(issuance_sans),
                "key_type": request["key_type"],
                "validity_days": request["validity_days"],
                "serial": str(certificate.serial_number),
                "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
                "not_before": self._certificate_time(certificate, "not_valid_before"),
                "not_after": self._certificate_time(certificate, "not_valid_after"),
                "status": "active",
                "certificate_pem": certificate_pem,
                "created_at": utc_now(),
                "renewed_from": renewed_from,
                "revoked_at": None,
                "source": "manual",
                "provisioner": StepCAEngine.PROVISIONER,
            }
            self.inventory.add_certificate(record)
            profile_filename = profile.slug.replace("_", "-")
            filename = f"{self._safe_filename(request['common_name'])}-{profile_filename}.{extension}"
            token = self._store_export(archive, kind="certificate", filename=filename)
            self.inventory.audit(
                "certificate.issue",
                certificate_id,
                detail={
                    "profile": profile.slug,
                    "common_name": request["common_name"],
                    "sans": issuance_sans,
                    "key_type": request["key_type"],
                    "validity_days": request["validity_days"],
                    "export_format": request["export_format"],
                    "renewed_from": renewed_from,
                },
            )
            return certificate_id, token
        except Exception as exc:
            self.inventory.audit(
                "certificate.issue",
                certificate_id,
                success=False,
                detail={"profile": profile_slug, "common_name": common_name, "error": str(exc)},
            )
            raise

    def issue_public_portal(self, *, common_name: str, api_hostname: str, sans=""):
        values = [common_name]
        values.extend(
            item.strip() for item in str(sans or "").replace("\r", "\n").replace(",", "\n").split("\n")
            if item.strip()
        )
        certificate_id = str(uuid.uuid4())
        api_certificate_id = str(uuid.uuid4())
        try:
            api_hostname = str(api_hostname or "").strip().lower().rstrip(".")
            if not api_hostname.endswith(".local") or "." in api_hostname[:-6]:
                raise ValueError(
                    "The private Device API hostname must be a single-label .local name"
                )
            result = self.external_acme.issue(
                values, certificate_id=certificate_id
            )
            certificate = result.certificate
            names = self._certificate_dns_names(certificate) or values
            common_name = names[0]
            api_private_key = self._private_key("rsa-2048")
            api_csr = self._csr(
                api_private_key, common_name=api_hostname, sans=[api_hostname],
                server_auth=True, client_auth=False,
            )
            api_certificate_pem = self.engine.sign(
                csr_pem=api_csr.public_bytes(serialization.Encoding.PEM),
                common_name=api_hostname, sans=[api_hostname], validity_days=365,
            )
            api_certificate = x509.load_pem_x509_certificate(api_certificate_pem)
            validity = max(
                1,
                (self._certificate_datetime(certificate, "not_valid_after") -
                 self._certificate_datetime(certificate, "not_valid_before")).days,
            )
            record = {
                "id": certificate_id,
                "profile": "public-portal",
                "common_name": common_name,
                "sans_json": json.dumps(names),
                "key_type": "rsa-2048",
                "validity_days": validity,
                "serial": str(certificate.serial_number),
                "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
                "not_before": self._certificate_time(certificate, "not_valid_before"),
                "not_after": self._certificate_time(certificate, "not_valid_after"),
                "status": "active",
                "certificate_pem": result.certificate_pem,
                "created_at": utc_now(),
                "renewed_from": None,
                "revoked_at": None,
                "source": "external-acme",
                "provisioner": self.REVOCABLE_PUBLIC_PROVISIONER,
            }
            archive = self._public_portal_export(
                result, names, api_hostname, api_certificate,
                api_certificate_pem, api_private_key,
            )
            self.inventory.add_certificate(record)
            self.inventory.add_certificate({
                "id": api_certificate_id,
                "profile": "tls-server",
                "common_name": api_hostname,
                "sans_json": json.dumps([api_hostname]),
                "key_type": "rsa-2048",
                "validity_days": 365,
                "serial": str(api_certificate.serial_number),
                "fingerprint": api_certificate.fingerprint(hashes.SHA256()).hex(),
                "not_before": self._certificate_time(api_certificate, "not_valid_before"),
                "not_after": self._certificate_time(api_certificate, "not_valid_after"),
                "status": "active",
                "certificate_pem": api_certificate_pem,
                "created_at": utc_now(),
                "renewed_from": None,
                "revoked_at": None,
                "source": "manual",
                "provisioner": "iot-md-public-profile",
            })
            token = self._store_export(
                archive, kind="certificate",
                filename=f"{self._safe_filename(common_name)}-public-portal.zip",
            )
            self.inventory.audit(
                "external-acme.issue", certificate_id,
                detail={
                    "common_name": common_name,
                    "sans": names,
                    "api_hostname": api_hostname,
                    "api_certificate_id": api_certificate_id,
                    "environment": self.external_acme.settings()["environment"],
                    "provider": "cloudflare",
                },
            )
            return certificate_id, token
        except Exception as exc:
            self.inventory.audit(
                "external-acme.issue", certificate_id, success=False,
                detail={"common_name": str(common_name), "error": str(exc)},
            )
            raise

    def renew(self, certificate_id: str, *, export_format: str, export_password: str = ""):
        original = self.inventory.certificate(certificate_id)
        if not original:
            raise ValueError("Certificate not found")
        if original["status"] != "active":
            raise ValueError("Only active certificates can be renewed")
        renewal_sans = original["sans"]
        if (
            not PROFILES[original["profile"]].require_san
            and renewal_sans == [original["common_name"]]
        ):
            renewal_sans = []
        new_id, token = self.issue(
            profile_slug=original["profile"],
            common_name=original["common_name"],
            sans=renewal_sans,
            key_type=original["key_type"],
            validity_days=original["validity_days"],
            export_format=export_format,
            export_password=export_password,
            renewed_from=certificate_id,
        )
        try:
            self.engine.revoke(original["serial"], reason="superseded")
            self.inventory.set_certificate_status(
                certificate_id, "superseded", revoked_at=utc_now()
            )
            self.inventory.audit(
                "certificate.supersede",
                certificate_id,
                detail={"replacement": new_id},
            )
        except Exception as exc:
            self.inventory.audit(
                "certificate.supersede",
                certificate_id,
                success=False,
                detail={"replacement": new_id, "error": str(exc)},
            )
            raise RuntimeError(
                f"Replacement {new_id} was issued, but the old certificate could not be revoked: {exc}"
            ) from exc
        return new_id, token

    def revoke(self, certificate_id: str):
        certificate = self.inventory.certificate(certificate_id)
        if not certificate:
            raise ValueError("Certificate not found")
        if certificate["status"] != "active":
            raise ValueError("Only active certificates can be revoked")
        try:
            if certificate.get("source") == "external-acme":
                if certificate.get("provisioner") != self.REVOCABLE_PUBLIC_PROVISIONER:
                    raise ValueError(
                        "This public certificate predates managed revocation. Issue a "
                        "replacement with the current IoT CA release, then retire the "
                        "older certificate."
                    )
                self.external_acme.revoke(certificate_id)
            else:
                self.engine.revoke(certificate["serial"])
            self.inventory.set_certificate_status(certificate_id, "revoked", revoked_at=utc_now())
            self.inventory.audit(
                "certificate.revoke", certificate_id,
                detail={"source": certificate.get("source", "manual")},
            )
        except Exception as exc:
            self.inventory.audit(
                "certificate.revoke", certificate_id, success=False, detail={"error": str(exc)}
            )
            raise

    def certificate(self, certificate_id):
        return self.inventory.certificate(certificate_id)

    def certificate_public_bytes(self, certificate_id, encoding="pem"):
        record = self.certificate(certificate_id)
        if not record:
            raise ValueError("Certificate not found")
        certificate = x509.load_pem_x509_certificate(record["certificate_pem"])
        return certificate.public_bytes(self._public_certificate_encoding(encoding))

    def certificates(self):
        return self.inventory.certificates()

    def audit_log(self):
        return self.inventory.audit_log()

    def dashboard(self):
        now = datetime.now(timezone.utc)
        soon = now + timedelta(days=30)
        certificates = self.certificates()
        expiring = [
            item for item in certificates
            if item["status"] == "active" and self._parse_time(item["not_after"]) <= soon
        ]
        return {
            "counts": self.inventory.dashboard_counts(),
            "expiring": expiring,
            "recent": certificates[:8],
            "ca_health": self.engine.health(),
            "root_export_pending": bool(self.inventory.pending_export("offline-root")),
        }

    def root_trust(self, encoding="pem"):
        certificate = x509.load_pem_x509_certificate(self.engine.root_certificate())
        return certificate.public_bytes(self._public_certificate_encoding(encoding))

    def intermediate_trust(self, encoding="pem"):
        certificate = x509.load_pem_x509_certificate(self.engine.intermediate_certificate())
        return certificate.public_bytes(self._public_certificate_encoding(encoding))

    def ca_chain(self):
        return self.intermediate_trust("pem") + self.root_trust("pem")

    def export_for_token(self, token: str):
        self.cleanup_exports()
        record = self.inventory.export_for_token(token)
        if not record or not Path(record["path"]).is_file():
            return None
        return record

    def complete_export(self, record: dict):
        path = Path(record["path"])
        path.unlink(missing_ok=True)
        self.inventory.consume_export(record["id"])
        self.inventory.audit("export.consume", record["id"], detail={"kind": record["kind"]})

    def recover_root_export(self):
        record = self.inventory.pending_export("offline-root")
        if not record or not Path(record["path"]).is_file():
            raise ValueError("No pending offline-root export is available")
        token = self.inventory.replace_export_token(record["id"])
        self.inventory.audit("export.recover-link", record["id"], detail={"kind": record["kind"]})
        return token

    def cleanup_exports(self):
        for record in self.inventory.expired_exports():
            Path(record["path"]).unlink(missing_ok=True)
            self.inventory.consume_export(record["id"])
            self.inventory.audit("export.expire", record["id"], detail={"kind": record["kind"]})

    def _store_export(self, data: bytes, *, kind: str, filename: str, lifetime=None):
        export_id = str(uuid.uuid4())
        path = self.exports_path / f"{export_id}.download"
        path.write_bytes(data)
        path.chmod(0o600)
        expires = datetime.now(timezone.utc) + (lifetime or self.EXPORT_LIFETIME)
        return self.inventory.add_export(
            export_id=export_id,
            kind=kind,
            path=str(path),
            filename=filename,
            expires_at=expires.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        )

    def _export(
        self,
        *,
        export_format,
        common_name,
        profile_slug,
        certificate,
        certificate_pem,
        private_key,
        export_password,
    ):
        root_pem = self.engine.root_certificate()
        intermediate_pem = self.engine.intermediate_certificate()
        root = x509.load_pem_x509_certificate(root_pem)
        intermediate = x509.load_pem_x509_certificate(intermediate_pem)
        metadata = json.dumps(
            {
                "common_name": common_name,
                "profile": profile_slug,
                "serial": str(certificate.serial_number),
                "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "private_key_retained_by_ca": False,
            },
            indent=2,
            sort_keys=True,
        ).encode() + b"\n"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("certificate-info.json", metadata)
            if export_format == "pem":
                archive.writestr("certificate.pem", certificate_pem)
                archive.writestr("private-key.pem", self._private_key_bytes(private_key, "pem"))
                archive.writestr("intermediate-ca.pem", intermediate_pem)
                archive.writestr("root-ca.pem", root_pem)
            elif export_format == "der":
                archive.writestr("certificate.der", certificate.public_bytes(serialization.Encoding.DER))
                archive.writestr("private-key.der", self._private_key_bytes(private_key, "der"))
                archive.writestr("intermediate-ca.der", intermediate.public_bytes(serialization.Encoding.DER))
                archive.writestr("root-ca.der", root.public_bytes(serialization.Encoding.DER))
            elif export_format == "iot_md":
                archive.writestr("web.crt.der", certificate.public_bytes(serialization.Encoding.DER))
                archive.writestr("web.key.der", self._private_key_bytes(private_key, "der"))
                archive.writestr("mqtt-ca.der", root.public_bytes(serialization.Encoding.DER))
                archive.writestr("update-ca.der", root.public_bytes(serialization.Encoding.DER))
                archive.writestr("intermediate-ca.der", intermediate.public_bytes(serialization.Encoding.DER))
            elif export_format == "pkcs12":
                password = export_password.encode()
                archive.writestr(
                    "identity.p12",
                    pkcs12.serialize_key_and_certificates(
                        common_name.encode(),
                        private_key,
                        certificate,
                        [intermediate, root],
                        serialization.BestAvailableEncryption(password),
                    ),
                )
                archive.writestr("root-ca.pem", root_pem)
            else:
                raise ValueError("Unsupported export format")
        return output.getvalue(), "zip"

    def _public_portal_export(
        self, result, names, api_hostname, api_certificate,
        api_certificate_pem, api_private_key,
    ):
        certificate = result.certificate
        metadata = json.dumps(
            {
                "common_name": names[0],
                "sans": names,
                "profile": "public-portal",
                "serial": str(certificate.serial_number),
                "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "issuer": "Let's Encrypt via Cloudflare DNS-01",
                "private_key_retained_by_ca": False,
                "installation": "Install web.crt.pem and web.key.der as the public portal identity, and api-server.* as the private API identity.",
                "private_api_hostname": api_hostname,
            },
            indent=2,
            sort_keys=True,
        ).encode() + b"\n"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("certificate-info.json", metadata)
            archive.writestr("web.crt.pem", result.fullchain_pem)
            archive.writestr(
                "web.key.der", self._private_key_bytes(result.private_key, "der")
            )
            archive.writestr(
                "api-server.crt.der",
                api_certificate.public_bytes(serialization.Encoding.DER),
            )
            archive.writestr(
                "api-server.key.der", self._private_key_bytes(api_private_key, "der")
            )
            archive.writestr("api-server.crt.pem", api_certificate_pem)
            root = x509.load_pem_x509_certificate(self.engine.root_certificate())
            intermediate = x509.load_pem_x509_certificate(
                self.engine.intermediate_certificate()
            )
            archive.writestr(
                "mqtt-ca.der", root.public_bytes(serialization.Encoding.DER)
            )
            archive.writestr(
                "update-ca.der", root.public_bytes(serialization.Encoding.DER)
            )
            archive.writestr(
                "intermediate-ca.der",
                intermediate.public_bytes(serialization.Encoding.DER),
            )
        return output.getvalue()

    @staticmethod
    def _certificate_dns_names(certificate):
        try:
            extension = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            return []
        return extension.value.get_values_for_type(x509.DNSName)

    @staticmethod
    def _certificate_datetime(certificate, attribute):
        value = getattr(certificate, attribute + "_utc", None) or getattr(
            certificate, attribute
        )
        return value.replace(tzinfo=value.tzinfo or timezone.utc)

    @staticmethod
    def _private_key(key_type):
        if key_type == "ec-p256":
            return ec.generate_private_key(ec.SECP256R1())
        if key_type == "rsa-2048":
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if key_type == "rsa-3072":
            return rsa.generate_private_key(public_exponent=65537, key_size=3072)
        raise ValueError("Unsupported key type")

    @staticmethod
    def _csr(private_key, *, common_name, sans, server_auth, client_auth):
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        if sans:
            names = []
            for value in sans:
                try:
                    import ipaddress
                    names.append(x509.IPAddress(ipaddress.ip_address(value)))
                except ValueError:
                    names.append(x509.DNSName(value))
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        usages = []
        if server_auth:
            usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client_auth:
            usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        if usages:
            builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
        return builder.sign(private_key, hashes.SHA256())

    @staticmethod
    def _private_key_bytes(private_key, encoding):
        if encoding == "der":
            output_encoding = serialization.Encoding.DER
            output_format = (
                serialization.PrivateFormat.TraditionalOpenSSL
                if isinstance(private_key, rsa.RSAPrivateKey)
                else serialization.PrivateFormat.PKCS8
            )
        else:
            output_encoding = serialization.Encoding.PEM
            output_format = serialization.PrivateFormat.PKCS8
        return private_key.private_bytes(
            output_encoding, output_format, serialization.NoEncryption()
        )

    @staticmethod
    def _public_certificate_encoding(encoding):
        normalized = str(encoding or "").strip().lower()
        if normalized == "pem":
            return serialization.Encoding.PEM
        if normalized == "der":
            return serialization.Encoding.DER
        raise ValueError("Unsupported certificate format; choose PEM or DER")

    @staticmethod
    def _certificate_time(certificate, attribute):
        utc_attribute = attribute + "_utc"
        value = getattr(certificate, utc_attribute, None) or getattr(certificate, attribute)
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse_time(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _safe_filename(value):
        return "".join(character if character.isalnum() or character in "-." else "-" for character in value)
