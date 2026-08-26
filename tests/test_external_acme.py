import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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

    def test_automatic_enrollment_opens_a_short_lived_window(self):
        client = ExternalACME(self.root)
        settings = client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="staging", terms_accepted=True,
            dns_token="dns-secret", auto_enroll_enabled=True,
            provisioning_host="homeassistant.local",
        )
        self.assertTrue(settings["auto_enroll_enabled"])
        self.assertTrue(settings["auto_enroll_until"].endswith("Z"))
        self.assertEqual(settings["provisioning_host"], "homeassistant.local")
        disabled = client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="staging", terms_accepted=True,
            auto_enroll_enabled=False, provisioning_host="homeassistant.local",
        )
        self.assertFalse(disabled["auto_enroll_enabled"])
        self.assertEqual(disabled["auto_enroll_until"], "")

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
        self.assertIn("--dns.propagation.disable-rns", captured["command"])
        self.assertEqual(
            captured["command"][captured["command"].index("--dns.resolvers") + 1],
            "1.1.1.1:53,1.0.0.1:53",
        )
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

    def test_issue_reports_timeout_and_removes_temporary_state(self):
        def runner(command, **_options):
            raise subprocess.TimeoutExpired(command, 360)

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="staging", terms_accepted=True, dns_token="dns-secret",
        )

        with self.assertRaisesRegex(RuntimeError, "timed out after 360 seconds"):
            client.issue(["device.example.com"])
        self.assertFalse(
            any(path.name.startswith("issuance-") for path in client.root.iterdir())
        )

    def test_issue_csr_preserves_device_generated_public_key(self):
        captured = {}
        private_key = ec.generate_private_key(ec.SECP256R1())
        request = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "device.example.com")
            ]))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("device.example.com")
                ]), critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        def runner(command, **_options):
            captured["command"] = command
            work = Path(command[command.index("--path") + 1])
            submitted = x509.load_pem_x509_csr(
                Path(command[command.index("--csr") + 1]).read_bytes()
            )
            output = work / "certificates"
            output.mkdir(parents=True)
            issuer_key = ec.generate_private_key(ec.SECP256R1())
            now = datetime.now(timezone.utc)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(submitted.subject)
                .issuer_name(submitted.subject)
                .public_key(submitted.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=90))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("device.example.com")
                    ]), critical=False,
                )
                .sign(issuer_key, hashes.SHA256())
            )
            (output / "request.crt").write_bytes(
                certificate.public_bytes(serialization.Encoding.PEM)
            )
            return type("Completed", (), {
                "returncode": 0, "stdout": "", "stderr": "",
            })()

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="staging", terms_accepted=True, dns_token="dns-secret",
        )
        result = client.issue_csr(
            request.public_bytes(serialization.Encoding.PEM)
        )

        self.assertIn("--csr", captured["command"])
        self.assertNotIn("--domains", captured["command"])
        self.assertIsNone(result.private_key)
        self.assertEqual(
            result.certificate.public_key().public_numbers(),
            private_key.public_key().public_numbers(),
        )


if __name__ == "__main__":
    unittest.main()
