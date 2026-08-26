"""Public ACME issuance through Cloudflare DNS-01 without retaining portal keys."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
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
AUTO_ENROLLMENT_WINDOW = timedelta(minutes=15)


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
            "provisioning_host": "homeassistant.local",
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
        return values

    def configure(
        self, *, enabled, email, zone, environment, terms_accepted,
        dns_token="", zone_token="", auto_enroll_enabled=False,
        provisioning_host="homeassistant.local",
    ):
        enabled = bool(enabled)
        email = str(email or "").strip().lower()
        zone = str(zone or "").strip().lower().rstrip(".")
        environment = str(environment or "staging").strip().lower()
        provisioning_host = str(
            provisioning_host or "homeassistant.local"
        ).strip().lower().rstrip(".")
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
        if auto_enroll_enabled and not enabled:
            raise ValueError("Enable public ACME issuance before automatic enrollment")
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
            "auto_enroll_until": (
                (datetime.now(timezone.utc) + AUTO_ENROLLMENT_WINDOW)
                .replace(microsecond=0).isoformat().replace("+00:00", "Z")
                if auto_enroll_enabled else ""
            ),
        }
        temporary = self.settings_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.settings_path)
        return self.settings()

    def issue(self, names) -> PublicCertificate:
        return self._issue(names, csr_pem=None)

    def issue_csr(self, csr_pem: bytes) -> PublicCertificate:
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
        return self._issue(names, csr_pem=bytes(csr_pem))

    def _issue(self, names, csr_pem=None) -> PublicCertificate:
        csr = x509.load_pem_x509_csr(csr_pem) if csr_pem is not None else None
        settings = self.settings()
        if not settings["enabled"]:
            raise ValueError("Public ACME issuance is not enabled")
        names = self._validate_names(names, settings["zone"])
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
                self.binary, "run", "--path", str(work), "--email", settings["email"],
                "--server", settings["directory_url"], "--dns", "cloudflare",
                "--dns.resolvers", "1.1.1.1:53,1.0.0.1:53",
                "--dns.propagation.disable-rns",
                "--accept-tos", "--key-type", "RSA2048",
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
            certificate_path = self._issued_certificate_path(work)
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
            return PublicCertificate(certificate, certificate_pem, fullchain_pem, private_key)
        finally:
            shutil.rmtree(work, ignore_errors=True)

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
    def _issued_certificate_path(work):
        certificates = [
            path for path in work.rglob("*.crt")
            if "certificates" in path.parts and not path.name.endswith(".issuer.crt")
        ]
        if certificates:
            return certificates[0]
        raise RuntimeError("Public ACME client did not produce a certificate")

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
