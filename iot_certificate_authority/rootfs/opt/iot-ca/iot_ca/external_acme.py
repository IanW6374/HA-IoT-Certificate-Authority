"""Public ACME issuance through Cloudflare DNS-01 without retaining portal keys."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


LOGGER = logging.getLogger(__name__)


DNS_NAME = re.compile(
    r"^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DIRECTORIES = {
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "production": "https://acme-v02.api.letsencrypt.org/directory",
}
DEFAULT_AUTO_ENROLLMENT_MINUTES = 5
MIN_AUTO_ENROLLMENT_MINUTES = 1
MAX_AUTO_ENROLLMENT_MINUTES = 60
ACCOUNT_KEY_TYPES = {
    "EC256", "EC384", "RSA2048", "RSA3072", "RSA4096", "RSA8192",
}


@dataclass(frozen=True)
class PublicCertificate:
    certificate: x509.Certificate
    certificate_pem: bytes
    fullchain_pem: bytes
    private_key: object | None


class ExternalACME:
    """Persist non-secret policy and invoke a pinned lego ACME client safely."""

    def __init__(self, data_root: Path | str, *, runner=None, binary="lego"):
        self.root = Path(data_root) / "external-acme"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.settings_path = self.root / "settings.json"
        self.dns_token_path = self.root / "cloudflare-dns-token"
        self.zone_token_path = self.root / "cloudflare-zone-token"
        self.storage_path = self.root / "lego"
        self.storage_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.certificate_accounts_path = self.root / "certificate-accounts"
        self.certificate_accounts_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runner = runner or subprocess.run
        self.binary = binary

    def settings(self):
        values = {
            "enabled": False,
            "provider": "cloudflare",
            "email": "",
            "zone": "",
            "environment": "staging",
            "terms_accepted": False,
            "auto_enroll_until": "",
            "auto_enroll_minutes": DEFAULT_AUTO_ENROLLMENT_MINUTES,
            "provisioning_host": "homeassistant.local",
            "provisioning_port": 9010,
        }
        try:
            loaded = json.loads(self.settings_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                values.update(loaded)
        except (OSError, ValueError):
            pass
        values["directory_url"] = DIRECTORIES.get(
            values.get("environment"), DIRECTORIES["staging"]
        )
        values["dns_token_configured"] = self._has_secret(self.dns_token_path)
        values["zone_token_configured"] = self._has_secret(self.zone_token_path)
        try:
            until = datetime.fromisoformat(
                str(values.get("auto_enroll_until", "")).replace("Z", "+00:00")
            )
            values["auto_enroll_enabled"] = until > datetime.now(timezone.utc)
        except (TypeError, ValueError):
            values["auto_enroll_enabled"] = False
        try:
            minutes = int(values.get(
                "auto_enroll_minutes", DEFAULT_AUTO_ENROLLMENT_MINUTES
            ))
        except (TypeError, ValueError):
            minutes = DEFAULT_AUTO_ENROLLMENT_MINUTES
        values["auto_enroll_minutes"] = max(
            MIN_AUTO_ENROLLMENT_MINUTES,
            min(minutes, MAX_AUTO_ENROLLMENT_MINUTES),
        )
        values["auto_enroll_remaining_seconds"] = max(
            0,
            int((until - datetime.now(timezone.utc)).total_seconds())
            if values["auto_enroll_enabled"] else 0,
        )
        try:
            provisioning_port = int(values.get("provisioning_port", 9010))
        except (TypeError, ValueError):
            provisioning_port = 9010
        values["provisioning_port"] = (
            provisioning_port if 1 <= provisioning_port <= 65535 else 9010
        )
        return values

    def configure(
        self, *, enabled, email, zone, environment, terms_accepted,
        dns_token="", zone_token="", auto_enroll_minutes=DEFAULT_AUTO_ENROLLMENT_MINUTES,
        provisioning_host="homeassistant.local", provisioning_port=9010,
    ):
        enabled = bool(enabled)
        email = str(email or "").strip().lower()
        zone = str(zone or "").strip().lower().rstrip(".")
        environment = str(environment or "staging").strip().lower()
        provisioning_host = str(
            provisioning_host or "homeassistant.local"
        ).strip().lower().rstrip(".")
        try:
            provisioning_port = int(provisioning_port or 9010)
        except (TypeError, ValueError) as exc:
            raise ValueError("IoT CA provisioning port must be a whole number") from exc
        if environment not in DIRECTORIES:
            raise ValueError("Public ACME environment must be staging or production")
        if enabled:
            if not EMAIL.fullmatch(email):
                raise ValueError("A valid ACME account email address is required")
            if not DNS_NAME.fullmatch(zone) or zone.startswith("*."):
                raise ValueError("A valid Cloudflare DNS zone is required")
            if not terms_accepted:
                raise ValueError("Accept the ACME subscriber agreement before enabling issuance")
            if not str(dns_token or "").strip() and not self._has_secret(self.dns_token_path):
                raise ValueError("A Cloudflare DNS API token is required")
        if not DNS_NAME.fullmatch(provisioning_host) or provisioning_host.startswith("*."):
            raise ValueError("A valid IoT CA provisioning server name is required")
        if provisioning_port < 1 or provisioning_port > 65535:
            raise ValueError("IoT CA provisioning port must be between 1 and 65535")
        try:
            auto_enroll_minutes = int(auto_enroll_minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("Automatic IoT CA enrollment duration must be a whole number") from exc
        if not MIN_AUTO_ENROLLMENT_MINUTES <= auto_enroll_minutes <= MAX_AUTO_ENROLLMENT_MINUTES:
            raise ValueError(
                "Automatic IoT CA enrollment duration must be between 1 and 60 minutes"
            )
        current = self.settings()
        self._store_secret(self.dns_token_path, dns_token)
        self._store_secret(self.zone_token_path, zone_token)
        values = {
            "enabled": enabled,
            "provider": "cloudflare",
            "email": email,
            "zone": zone,
            "environment": environment,
            "terms_accepted": bool(terms_accepted),
            "provisioning_host": provisioning_host,
            "provisioning_port": provisioning_port,
            "auto_enroll_minutes": auto_enroll_minutes,
            "auto_enroll_until": current.get("auto_enroll_until", "") if enabled else "",
        }
        self._write_settings(values)
        return self.settings()

    def set_auto_enrollment(self, enabled: bool):
        values = self.settings()
        if enabled and not values["enabled"]:
            raise ValueError("Enable public ACME issuance before Automatic IoT CA enrollment")
        values.pop("directory_url", None)
        values.pop("dns_token_configured", None)
        values.pop("zone_token_configured", None)
        values.pop("auto_enroll_enabled", None)
        values.pop("auto_enroll_remaining_seconds", None)
        values["auto_enroll_until"] = (
            (
                datetime.now(timezone.utc) +
                timedelta(minutes=values["auto_enroll_minutes"])
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            if enabled else ""
        )
        self._write_settings(values)
        return self.settings()

    def _write_settings(self, values):
        temporary = self.settings_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.settings_path)

    def issue(self, names, certificate_id=None) -> PublicCertificate:
        return self._issue(names, csr_pem=None, certificate_id=certificate_id)

    def issue_csr(self, csr_pem: bytes, certificate_id=None) -> PublicCertificate:
        csr = x509.load_pem_x509_csr(bytes(csr_pem))
        if not csr.is_signature_valid:
            raise ValueError("Public portal CSR signature is invalid")
        try:
            names = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        if not names:
            names = [
                attribute.value for attribute in csr.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME
                )
            ]
        return self._issue(
            names, csr_pem=bytes(csr_pem), certificate_id=certificate_id
        )

    def _issue(self, names, csr_pem=None, certificate_id=None) -> PublicCertificate:
        csr = x509.load_pem_x509_csr(csr_pem) if csr_pem is not None else None
        settings = self.settings()
        if not settings["enabled"]:
            raise ValueError("Public ACME issuance is not enabled")
        names = self._validate_names(names, settings["zone"])
        certificate_id = str(certificate_id or uuid.uuid4())
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", certificate_id):
            raise ValueError("Public certificate storage ID is invalid")
        account = self._account_for_issue(settings)
        work = Path(tempfile.mkdtemp(prefix="issuance-", dir=self.root))
        try:
            environment = os.environ.copy()
            environment.update({
                "CF_DNS_API_TOKEN_FILE": str(self.dns_token_path),
                "LEGO_LOG_LEVEL": "warn",
            })
            if self._has_secret(self.zone_token_path):
                environment["CF_ZONE_API_TOKEN_FILE"] = str(self.zone_token_path)
            command = [
                self.binary, "run", "--path", str(self.storage_path),
                "--account-id", account["id"], "--email", account["email"],
                "--server", account["server"], "--dns", "cloudflare",
                "--dns.resolvers", "1.1.1.1:53,1.0.0.1:53",
                "--dns.propagation.disable-rns",
                "--accept-tos", "--key-type", account["key_type"],
                "--cert.name", certificate_id,
            ]
            if csr_pem is None:
                for name in names:
                    command.extend(("--domains", name))
            else:
                csr_path = work / "request.csr"
                csr_path.write_bytes(csr_pem)
                command.extend(("--csr", str(csr_path)))
            try:
                completed = self.runner(
                    command, env=environment, capture_output=True, text=True,
                    timeout=360, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                LOGGER.error(
                    "Public ACME request timed out after 360 seconds for %s",
                    ", ".join(names),
                )
                raise RuntimeError(
                    "Public ACME request timed out after 360 seconds"
                ) from exc
            if completed.returncode:
                detail = self._safe_error(completed.stderr or completed.stdout)
                LOGGER.error(
                    "Public ACME request failed for %s: %s",
                    ", ".join(names), detail or "lego returned no error detail",
                )
                raise RuntimeError(
                    "Public ACME request failed" + (": " + detail if detail else "")
                )
            certificate_path = self._issued_certificate_path(
                self.storage_path, certificate_id
            )
            fullchain_pem = certificate_path.read_bytes()
            certificate_pem = self._first_certificate_pem(fullchain_pem)
            certificate = x509.load_pem_x509_certificate(certificate_pem)
            private_key = None
            if csr_pem is None:
                key_path = certificate_path.with_suffix(".key")
                if not key_path.is_file():
                    raise RuntimeError("Public ACME client did not produce a private key")
                private_key = serialization.load_pem_private_key(
                    key_path.read_bytes(), password=None
                )
                if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
                    raise RuntimeError("Public ACME certificate and private key do not match")
            elif certificate.public_key().public_numbers() != csr.public_key().public_numbers():
                raise RuntimeError("Public ACME certificate does not match the submitted CSR")
            self._store_certificate_account(certificate_id, account)
            return PublicCertificate(certificate, certificate_pem, fullchain_pem, private_key)
        finally:
            self._remove_leaf_private_material(certificate_id)
            shutil.rmtree(work, ignore_errors=True)

    def revoke(self, certificate_id: str):
        certificate_id = str(certificate_id or "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", certificate_id):
            raise ValueError("Public certificate storage ID is invalid")
        certificate_path = self.storage_path / "certificates" / (certificate_id + ".crt")
        if not certificate_path.is_file():
            raise ValueError(
                "This public certificate predates managed revocation. Issue a replacement "
                "with the current IoT CA release, then retire the older certificate."
            )
        accounts = self._revocation_accounts(certificate_id, certificate_path)
        if not accounts:
            raise RuntimeError(
                "Public certificate revocation failed: the retained issuing ACME "
                "account could not be found. Issue a replacement before retiring "
                "this certificate."
            )
        failures = []
        for account in accounts:
            command = [
                self.binary, "certificates", "revoke", "--path",
                str(self.storage_path), "--account-id", account["id"],
                "--email", account["email"], "--server", account["server"],
                "--key-type", account["key_type"], "--cert.name",
                certificate_id, "--reason", "0", "--keep",
            ]
            try:
                completed = self.runner(
                    command, capture_output=True, text=True, timeout=120,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                failures.append("request timed out")
                continue
            if not completed.returncode:
                self._store_certificate_account(certificate_id, account)
                return
            detail = self._safe_error(completed.stderr or completed.stdout)
            failures.append(detail or "lego returned no error detail")
        raise RuntimeError(
            "Public certificate revocation failed using the retained issuing "
            "ACME account" + (": " + failures[-1] if failures else "")
        )

    def _account_for_issue(self, settings):
        configured = {
            "id": settings["email"],
            "email": settings["email"],
            "server": settings["directory_url"],
            "key_type": "RSA2048",
        }
        for account in self._registered_accounts():
            if (
                self._same_server(account["server"], configured["server"]) and
                (account["id"] == configured["id"] or
                 account["email"] == configured["email"])
            ):
                return account
        return configured

    def _revocation_accounts(self, certificate_id, certificate_path):
        accounts = self._registered_accounts()
        if not accounts:
            return []
        retained = self._load_certificate_account(certificate_id)
        settings = self.settings()
        try:
            certificate = x509.load_pem_x509_certificate(
                self._first_certificate_pem(certificate_path.read_bytes())
            )
            certificate_is_staging = "STAGING" in certificate.issuer.rfc4514_string().upper()
            environment_matches = [
                account for account in accounts
                if ("staging" in account["server"].lower()) == certificate_is_staging
            ]
            if environment_matches:
                accounts = environment_matches
        except (OSError, RuntimeError, ValueError):
            pass

        def score(account):
            retained_match = bool(retained) and all(
                account.get(field) == retained.get(field)
                for field in ("id", "server", "key_type")
            )
            configured_match = (
                self._same_server(account["server"], settings["directory_url"]) and
                (account["id"] == settings["email"] or
                 account["email"] == settings["email"])
            )
            return (int(retained_match), int(configured_match))

        return sorted(accounts, key=score, reverse=True)

    def _registered_accounts(self):
        result = []
        accounts_root = self.storage_path / "accounts"
        if not accounts_root.is_dir():
            return result
        for account_path in accounts_root.glob("*/*/account.json"):
            try:
                account = json.loads(account_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            registration = account.get("registration")
            account_id = str(account.get("id") or account_path.parent.name)
            key_type = str(account.get("keyType") or "").upper()
            key_path = account_path.parent / (account_id + ".key")
            if (
                not isinstance(registration, dict) or not registration or
                not key_path.is_file() or key_type not in ACCOUNT_KEY_TYPES
            ):
                continue
            server = str(account.get("server") or "").strip()
            if not server:
                continue
            result.append({
                "id": account_id,
                "email": str(account.get("email") or "").strip().lower(),
                "server": server,
                "key_type": key_type,
            })
        return result

    def _store_certificate_account(self, certificate_id, account):
        path = self.certificate_accounts_path / (certificate_id + ".json")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(account, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)

    def _load_certificate_account(self, certificate_id):
        try:
            value = json.loads(
                (self.certificate_accounts_path / (certificate_id + ".json"))
                .read_text(encoding="utf-8")
            )
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None

    @staticmethod
    def _same_server(first, second):
        return str(first).rstrip("/") == str(second).rstrip("/")

    @staticmethod
    def _validate_names(names, zone):
        result = []
        for raw in names:
            name = str(raw or "").strip().lower().rstrip(".")
            if not DNS_NAME.fullmatch(name):
                raise ValueError("Public portal names must be valid DNS names")
            base = name[2:] if name.startswith("*.") else name
            if base == zone or not base.endswith("." + zone):
                raise ValueError("Public portal names must be within the configured DNS suffix")
            if name not in result:
                result.append(name)
        if not result or len(result) > 10:
            raise ValueError("Provide between 1 and 10 public portal DNS names")
        return result

    @staticmethod
    def _issued_certificate_path(storage, certificate_id):
        certificate = storage / "certificates" / (certificate_id + ".crt")
        if certificate.is_file():
            return certificate
        raise RuntimeError("Public ACME client did not produce a certificate")

    def _remove_leaf_private_material(self, certificate_id):
        certificates = self.storage_path / "certificates"
        for suffix in (".key", ".pem", ".pfx"):
            try:
                (certificates / (certificate_id + suffix)).unlink(missing_ok=True)
            except OSError:
                LOGGER.exception("Could not remove public portal private material")

    @staticmethod
    def _first_certificate_pem(fullchain):
        marker = b"-----END CERTIFICATE-----"
        end = fullchain.find(marker)
        if end < 0:
            raise RuntimeError("Public ACME client returned an invalid certificate chain")
        return fullchain[:end + len(marker)] + b"\n"

    @staticmethod
    def _safe_error(value):
        lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
        return (lines[-1] if lines else "")[:400]

    @staticmethod
    def _has_secret(path):
        try:
            return path.is_file() and bool(path.read_text(encoding="utf-8").strip())
        except OSError:
            return False

    @staticmethod
    def _store_secret(path, value):
        value = str(value or "").strip()
        if not value:
            return
        temporary = path.with_suffix(".tmp")
        temporary.write_text(value + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, path)
