"""Import certificates returned through the Smallstep ACME endpoint."""

from __future__ import annotations

import base64
import json
import math
import os
import sys
import uuid
from datetime import timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .database import Inventory


def _certificate_time(certificate, attribute):
    value = (
        getattr(certificate, attribute + "_utc", None)
        or getattr(certificate, attribute)
    )
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _time(certificate, attribute):
    value = _certificate_time(certificate, attribute)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _key_type(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"rsa-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name == "secp256r1":
            return "ec-p256"
        return "ec-" + public_key.curve.name
    return public_key.__class__.__name__.lower()


def _profile(certificate):
    try:
        usages = set(
            certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        )
    except x509.ExtensionNotFound:
        usages = set()
    if ExtendedKeyUsageOID.CLIENT_AUTH in usages and ExtendedKeyUsageOID.SERVER_AUTH not in usages:
        return "tls-client"
    return "tls-server"


def certificate_record(certificate, *, provisioner="acme"):
    try:
        common_name = certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value
    except IndexError:
        common_name = ""
    try:
        alternative_names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        sans = (
            alternative_names.get_values_for_type(x509.DNSName)
            + [str(value) for value in alternative_names.get_values_for_type(x509.IPAddress)]
        )
    except x509.ExtensionNotFound:
        sans = []
    if not common_name:
        common_name = sans[0] if sans else str(certificate.serial_number)
    sans = sorted(sans)
    not_before = _time(certificate, "not_valid_before")
    not_after = _time(certificate, "not_valid_after")
    lifetime_seconds = (
        _certificate_time(certificate, "not_valid_after")
        - _certificate_time(certificate, "not_valid_before")
    ).total_seconds()
    return {
        "id": str(uuid.uuid4()),
        "profile": _profile(certificate),
        "common_name": common_name,
        "sans_json": json.dumps(sans),
        "key_type": _key_type(certificate.public_key()),
        "validity_days": max(1, math.ceil(lifetime_seconds / 86400)),
        "serial": str(certificate.serial_number),
        "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
        "not_before": not_before,
        "not_after": not_after,
        "status": "active",
        "certificate_pem": certificate.public_bytes(serialization.Encoding.PEM),
        "created_at": not_before,
        "renewed_from": None,
        "revoked_at": None,
        "source": "acme",
        "provisioner": str(provisioner or "acme"),
    }


def import_log_line(line, inventory):
    """Import a successful ACME certificate response from one JSON log line."""
    try:
        entry = json.loads(line)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(entry, dict):
        return None
    try:
        status = int(entry.get("status", 0))
    except (TypeError, ValueError):
        return None
    if not (
        str(entry.get("path", "")).startswith("/acme/")
        and 200 <= status < 300
        and entry.get("certificate")
    ):
        return None
    try:
        certificate = x509.load_der_x509_certificate(
            base64.b64decode(entry["certificate"], validate=True)
        )
    except Exception:
        return None
    record = certificate_record(
        certificate, provisioner=entry.get("provisioner", "acme")
    )
    certificate_id, created = inventory.import_certificate(record)
    if created:
        inventory.audit(
            "certificate.acme-import",
            certificate_id,
            detail={
                "common_name": record["common_name"],
                "sans": json.loads(record["sans_json"]),
                "serial": record["serial"],
                "provisioner": record["provisioner"],
            },
        )
    return certificate_id


def ensure_json_logging(config_path):
    """Enable structured step-ca output without changing authority policy."""
    path = Path(config_path)
    config = json.loads(path.read_text())
    logger = dict(config.get("logger") or {})
    if logger.get("format") == "json":
        return False
    logger["format"] = "json"
    config["logger"] = logger
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, path.stat().st_mode & 0o777)
    os.replace(temporary, path)
    return True


def stream(data_root):
    inventory = Inventory(Path(data_root) / "inventory.db")
    for line in sys.stdin:
        # Preserve the complete Smallstep log in the Home Assistant app log.
        print(line, end="", flush=True)
        try:
            import_log_line(line, inventory)
        except Exception as exc:
            print(f"ACME inventory import failed: {exc}", file=sys.stderr, flush=True)


def main():
    data_root = Path(os.environ.get("IOT_CA_DATA_ROOT", "/config/iot-ca"))
    if len(sys.argv) == 2 and sys.argv[1] == "--prepare-config":
        ensure_json_logging(data_root / "step" / "config" / "ca.json")
        return
    if len(sys.argv) == 2 and sys.argv[1] == "--stream":
        stream(data_root)
        return
    raise SystemExit("usage: python -m iot_ca.acme_inventory --prepare-config|--stream")


if __name__ == "__main__":
    main()
