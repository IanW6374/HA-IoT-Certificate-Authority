"""Create the private-CA TLS identity for the LAN provisioning API."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .engine import StepCAEngine
from .service import CertificateService


def ensure_identity(data_root=None):
    root = Path(data_root or os.environ.get("IOT_CA_DATA_ROOT", "/config/iot-ca"))
    engine = StepCAEngine(root)
    engine.wait_until_ready(timeout=600)
    identity = root / "provisioning-api"
    identity.mkdir(mode=0o700, parents=True, exist_ok=True)
    certificate_path = identity / "server.crt.pem"
    key_path = identity / "server.key.pem"
    settings = CertificateService(root).settings()
    hostname = settings["ca_dns"]
    names = list(dict.fromkeys((
        hostname, settings["external_acme"].get(
            "provisioning_host", "homeassistant.local"
        ),
    )))
    if certificate_path.is_file() and key_path.is_file():
        try:
            certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
            expiry = getattr(certificate, "not_valid_after_utc", None)
            if expiry is None:
                expiry = certificate.not_valid_after.replace(tzinfo=timezone.utc)
            sans = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            if (
                expiry and expiry > datetime.now(timezone.utc) + timedelta(days=30) and
                set(names).issubset(set(sans))
            ):
                return certificate_path, key_path
        except (OSError, ValueError):
            pass

    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = CertificateService._csr(
        private_key, common_name=hostname, sans=names,
        server_auth=True, client_auth=False,
    )
    leaf = engine.sign(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM),
        common_name=hostname, sans=names, validity_days=365,
    )
    fullchain = leaf.rstrip() + b"\n" + engine.intermediate_certificate().lstrip()
    key = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    temporary_certificate = certificate_path.with_suffix(".tmp")
    temporary_key = key_path.with_suffix(".tmp")
    temporary_certificate.write_bytes(fullchain)
    temporary_key.write_bytes(key)
    temporary_certificate.chmod(0o600)
    temporary_key.chmod(0o600)
    os.replace(temporary_certificate, certificate_path)
    os.replace(temporary_key, key_path)
    return certificate_path, key_path


if __name__ == "__main__":
    ensure_identity()
