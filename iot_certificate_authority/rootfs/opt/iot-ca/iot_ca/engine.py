"""Smallstep CA lifecycle and command adapter."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization


SAFE_CA_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{2,63}$")
SAFE_DNS = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-_])")


class StepCAError(RuntimeError):
    """Raised when step-ca cannot complete an operation."""


class StepCAEngine:
    INTERNAL_URL = "https://127.0.0.1:9000"
    PROVISIONER = "iot-ca-admin"

    def __init__(self, data_root: Path | str, *, command_runner=None):
        self.data_root = Path(data_root)
        self.step_path = self.data_root / "step"
        self.config_path = self.step_path / "config" / "ca.json"
        self.root_cert_path = self.step_path / "certs" / "root_ca.crt"
        self.intermediate_cert_path = self.step_path / "certs" / "intermediate_ca.crt"
        self.root_key_path = self.step_path / "secrets" / "root_ca_key"
        self.password_path = self.data_root / "secrets" / "intermediate-password"
        self.settings_path = self.data_root / "settings.json"
        self._run_command = command_runner or self._subprocess
        self._lock = threading.RLock()

    @property
    def initialized(self) -> bool:
        return self.config_path.is_file() and self.settings_path.is_file()

    def settings(self) -> dict:
        if not self.settings_path.is_file():
            return {}
        return json.loads(self.settings_path.read_text())

    def initialize(
        self,
        *,
        ca_name: str,
        ca_dns: str,
        allowed_dns_suffix: str,
        root_export_passphrase: str,
        allow_public_sans: bool = False,
    ) -> tuple[bytes, dict]:
        with self._lock:
            if self.initialized or self.config_path.exists():
                raise StepCAError("The certificate authority is already initialized")
            ca_name = str(ca_name or "").strip()
            ca_dns = str(ca_dns or "").strip().lower().rstrip(".")
            allowed_dns_suffix = str(allowed_dns_suffix or "").strip().lower().strip(".")
            if not SAFE_CA_NAME.fullmatch(ca_name):
                raise StepCAError("CA name must be 3-64 plain text characters")
            if not SAFE_DNS.fullmatch(ca_dns) or "." not in ca_dns:
                raise StepCAError("CA DNS name must be a fully qualified local DNS name")
            if not SAFE_DNS.fullmatch(allowed_dns_suffix) or "." not in allowed_dns_suffix:
                raise StepCAError("Allowed DNS suffix must be a valid suffix such as home.arpa")
            if ca_dns != allowed_dns_suffix and not ca_dns.endswith("." + allowed_dns_suffix):
                raise StepCAError("CA DNS name must be within the allowed DNS suffix")
            if len(root_export_passphrase or "") < 16:
                raise StepCAError("Offline-root export passphrase must be at least 16 characters")

            self.data_root.mkdir(parents=True, exist_ok=True)
            (self.data_root / "secrets").mkdir(mode=0o700, exist_ok=True)
            password = secrets.token_urlsafe(48)
            self.password_path.write_text(password)
            self.password_path.chmod(0o600)
            env = self._environment()
            try:
                self._execute(
                    [
                        "step", "ca", "init",
                        "--deployment-type=standalone",
                        f"--name={ca_name}",
                        f"--dns={ca_dns}",
                        "--dns=127.0.0.1",
                        "--address=:9000",
                        f"--provisioner={self.PROVISIONER}",
                        f"--password-file={self.password_path}",
                        f"--provisioner-password-file={self.password_path}",
                        "--acme",
                    ],
                    env=env,
                    timeout=90,
                )
                self.apply_provisioner_policy()
                root_export = self._offline_root_export(root_export_passphrase)
                self.root_key_path.unlink(missing_ok=True)
                settings = {
                    "ca_name": ca_name,
                    "ca_dns": ca_dns,
                    "allowed_dns_suffix": allowed_dns_suffix,
                    "allow_public_sans": bool(allow_public_sans),
                    "public_ca_url": f"https://{ca_dns}:9000",
                    "acme_directory": f"https://{ca_dns}:9000/acme/acme/directory",
                    "initialized_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                }
                self._write_json_atomic(self.settings_path, settings)
                return root_export, settings
            except Exception:
                if not self.settings_path.exists():
                    shutil.rmtree(self.step_path, ignore_errors=True)
                    self.password_path.unlink(missing_ok=True)
                raise

    def health(self) -> dict:
        if not self.initialized:
            return {"initialized": False, "online": False}
        try:
            context = ssl.create_default_context(cafile=str(self.root_cert_path))
            with urllib.request.urlopen(
                f"{self.INTERNAL_URL}/health", context=context, timeout=2
            ) as response:
                payload = json.loads(response.read())
            return {"initialized": True, "online": payload.get("status") == "ok"}
        except Exception as exc:
            return {"initialized": True, "online": False, "error": str(exc)}

    def apply_provisioner_policy(self):
        """Persist the certificate lifetime policy before step-ca starts."""
        with self._lock:
            for provisioner, default_hours in ((self.PROVISIONER, 2160), ("acme", 24)):
                self._execute(
                    [
                        "step", "ca", "provisioner", "update", provisioner,
                        "--x509-min-dur=5m",
                        "--x509-max-dur=19800h",
                        f"--x509-default-dur={default_hours}h",
                        f"--ca-config={self.config_path}",
                    ],
                    env=self._environment(),
                )

    def wait_until_ready(self, timeout: float = 20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.health().get("online"):
                return
            time.sleep(0.5)
        raise StepCAError("step-ca did not become ready within the expected time")

    def sign(self, *, csr_pem: bytes, common_name: str, sans: list[str], validity_days: int) -> bytes:
        with self._lock, tempfile.TemporaryDirectory(prefix="iot-ca-sign-") as temporary:
            self.wait_until_ready()
            temporary_path = Path(temporary)
            csr_path = temporary_path / "request.csr"
            cert_path = temporary_path / "certificate.pem"
            csr_path.write_bytes(csr_pem)
            token_command = [
                "step", "ca", "token", common_name,
                f"--issuer={self.PROVISIONER}",
                f"--provisioner-password-file={self.password_path}",
                f"--ca-url={self.INTERNAL_URL}",
                f"--root={self.root_cert_path}",
            ]
            for san in sans:
                token_command.append(f"--san={san}")
            token = self._execute(token_command, env=self._environment()).strip()
            if not token:
                raise StepCAError("step-ca returned an empty authorization token")
            self._execute(
                [
                    "step", "ca", "sign", str(csr_path), str(cert_path),
                    f"--token={token}",
                    f"--not-after={int(validity_days) * 24}h",
                    f"--ca-url={self.INTERNAL_URL}",
                    f"--root={self.root_cert_path}",
                ],
                env=self._environment(),
            )
            return cert_path.read_bytes()

    def revoke(self, serial: str, reason: str = "keyCompromise"):
        with self._lock:
            self.wait_until_ready()
            token = self._execute(
                [
                    "step", "ca", "token", str(serial), "--revoke",
                    f"--issuer={self.PROVISIONER}",
                    f"--provisioner-password-file={self.password_path}",
                    f"--ca-url={self.INTERNAL_URL}",
                    f"--root={self.root_cert_path}",
                ],
                env=self._environment(),
            ).strip()
            self._execute(
                [
                    "step", "ca", "revoke", str(serial),
                    f"--token={token}",
                    f"--reason={reason}",
                    f"--ca-url={self.INTERNAL_URL}",
                    f"--root={self.root_cert_path}",
                ],
                env=self._environment(),
            )

    def root_certificate(self) -> bytes:
        return self.root_cert_path.read_bytes()

    def intermediate_certificate(self) -> bytes:
        return self.intermediate_cert_path.read_bytes()

    def _offline_root_export(self, passphrase: str) -> bytes:
        root_key = serialization.load_pem_private_key(
            self.root_key_path.read_bytes(),
            password=self.password_path.read_text().encode(),
        )
        encrypted_key = root_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode()),
        )
        root_certificate = self.root_cert_path.read_bytes()
        checksums = (
            f"{hashlib.sha256(root_certificate).hexdigest()}  root_ca.crt\n"
            f"{hashlib.sha256(encrypted_key).hexdigest()}  root_ca_key.encrypted.pem\n"
        ).encode()
        instructions = (
            "OFFLINE ROOT CA EXPORT\n\n"
            "Store this archive and its passphrase offline in separate secure locations.\n"
            "The encrypted root key is not required for day-to-day certificate issuance.\n"
            "It is required to replace the online intermediate after compromise or loss.\n"
        ).encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("root_ca.crt", root_certificate)
            archive.writestr("root_ca_key.encrypted.pem", encrypted_key)
            archive.writestr("SHA256SUMS", checksums)
            archive.writestr("README.txt", instructions)
        return output.getvalue()

    def _environment(self):
        environment = os.environ.copy()
        environment["STEPPATH"] = str(self.step_path)
        environment["NO_COLOR"] = "1"
        return environment

    def _execute(self, command: list[str], *, env: dict, timeout: int = 45) -> str:
        try:
            return self._run_command(command, env=env, timeout=timeout)
        except subprocess.CalledProcessError as exc:
            detail = ANSI_ESCAPE.sub("", exc.stderr or exc.stdout or str(exc)).strip()
            raise StepCAError(f"Smallstep command failed: {detail}") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise StepCAError(f"Could not run Smallstep command: {exc}") from exc

    @staticmethod
    def _subprocess(command: list[str], *, env: dict, timeout: int) -> str:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
        return result.stdout

    @staticmethod
    def _write_json_atomic(path: Path, value: dict):
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.replace(path)
