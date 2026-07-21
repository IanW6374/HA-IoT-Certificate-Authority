"""Certificate inventory and export orchestration."""

from __future__ import annotations

import io
import json
import os
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
from .profiles import PROFILES, validate_request


class CertificateService:
    EXPORT_LIFETIME = timedelta(minutes=15)
    ROOT_EXPORT_LIFETIME = timedelta(days=7)

    def __init__(self, data_root: Path | str, *, engine=None, inventory=None):
        self.data_root = Path(data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.exports_path = self.data_root / "exports"
        self.exports_path.mkdir(mode=0o700, exist_ok=True)
        self.engine = engine or StepCAEngine(self.data_root)
        self.inventory = inventory or Inventory(self.data_root / "inventory.db")

    @property
    def initialized(self):
        return self.engine.initialized

    def settings(self):
        return self.engine.settings()

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
            }
            self.inventory.add_certificate(record)
            filename = f"{self._safe_filename(request['common_name'])}-{profile.slug}.{extension}"
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
            self.engine.revoke(certificate["serial"])
            self.inventory.set_certificate_status(certificate_id, "revoked", revoked_at=utc_now())
            self.inventory.audit("certificate.revoke", certificate_id)
        except Exception as exc:
            self.inventory.audit(
                "certificate.revoke", certificate_id, success=False, detail={"error": str(exc)}
            )
            raise

    def certificate(self, certificate_id):
        return self.inventory.certificate(certificate_id)

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
        return certificate.public_bytes(
            serialization.Encoding.DER if encoding == "der" else serialization.Encoding.PEM
        )

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
            elif export_format == "hamd":
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
