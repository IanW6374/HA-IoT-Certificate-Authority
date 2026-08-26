import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from iot_ca.external_acme import ExternalACME


class ExternalACMETests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_configuration_keeps_tokens_out_of_public_settings(self):
        client = ExternalACME(self.root)
        settings = client.configure(
            enabled=True, email="Admin@Example.com", zone="example.com",
            environment="staging", terms_accepted=True,
            dns_token="dns-secret", zone_token="zone-secret",
        )

        self.assertNotIn("dns-secret", str(settings))
        self.assertNotIn("zone-secret", str(settings))
        self.assertTrue(settings["dns_token_configured"])
        self.assertTrue(settings["zone_token_configured"])
        self.assertEqual(client.dns_token_path.stat().st_mode & 0o777, 0o600)

    def test_issue_passes_tokens_by_file_and_removes_temporary_keys(self):
        captured = {}

        def runner(command, **options):
            captured["command"] = command
            captured["env"] = options["env"]
            work = Path(command[command.index("--path") + 1])
            output = work / "certificates"
            output.mkdir(parents=True)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.now(timezone.utc)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "device.example.com")
            ])
            certificate = (
                x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=90))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("device.example.com")]),
                    critical=False,
                ).sign(key, hashes.SHA256())
            )
            (output / "device.example.com.crt").write_bytes(
                certificate.public_bytes(serialization.Encoding.PEM)
            )
            (output / "device.example.com.key").write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="staging", terms_accepted=True, dns_token="dns-secret",
        )
        result = client.issue(["device.example.com"])

        self.assertEqual(result.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "device.example.com")
        self.assertNotIn("dns-secret", " ".join(captured["command"]))
        self.assertEqual(
            captured["env"]["CF_DNS_API_TOKEN_FILE"], str(client.dns_token_path)
        )
        self.assertFalse(any(path.name.startswith("issuance-") for path in client.root.iterdir()))

    def test_names_are_restricted_to_configured_zone(self):
        client = ExternalACME(self.root)
        client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="staging", terms_accepted=True, dns_token="dns-secret",
        )
        with self.assertRaisesRegex(ValueError, "configured DNS suffix"):
            client.issue(["device.other.example"])


if __name__ == "__main__":
    unittest.main()
