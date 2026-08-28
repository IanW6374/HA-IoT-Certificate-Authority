import json
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

    @staticmethod
    def _write_registered_account(
        client, account_id, email, server, key_type="RSA2048"
    ):
        server_name = server.split("://", 1)[-1].split("/", 1)[0].replace(":", "_")
        account_path = (
            client.storage_path / "accounts" / server_name / account_id
        )
        account_path.mkdir(parents=True, exist_ok=True)
        (account_path / "account.json").write_text(json.dumps({
            "id": account_id,
            "email": email,
            "keyType": key_type,
            "server": server,
            "registration": {
                "body": {"status": "valid"},
                "uri": "https://acme.example/acct/123",
            },
        }))
        (account_path / (account_id + ".key")).write_text("retained account key")

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
            dns_token="dns-secret", auto_enroll_minutes=7,
            provisioning_host="homeassistant.local",
        )
        settings = client.set_auto_enrollment(True)
        self.assertTrue(settings["auto_enroll_enabled"])
        self.assertTrue(settings["auto_enroll_until"].endswith("Z"))
        self.assertEqual(settings["auto_enroll_minutes"], 7)
        self.assertEqual(settings["provisioning_host"], "homeassistant.local")
        disabled = client.set_auto_enrollment(False)
        self.assertFalse(disabled["auto_enroll_enabled"])
        self.assertEqual(disabled["auto_enroll_until"], "")

    def test_issue_passes_tokens_by_file_and_removes_temporary_keys(self):
        captured = {}

        def runner(command, **options):
            captured["command"] = command
            captured["env"] = options["env"]
            work = Path(command[command.index("--path") + 1])
            certificate_id = command[command.index("--cert.name") + 1]
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
            (output / (certificate_id + ".crt")).write_bytes(
                certificate.public_bytes(serialization.Encoding.PEM)
            )
            (output / (certificate_id + ".key")).write_bytes(
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
        self.assertEqual(captured["command"][:2], ["lego", "run"])
        self.assertIn("--account-id", captured["command"])
        self.assertIn("--cert.name", captured["command"])
        self.assertNotIn("--cert-name", captured["command"])
        self.assertIn("--dns.propagation.disable-rns", captured["command"])
        self.assertEqual(
            captured["command"][captured["command"].index("--dns.resolvers") + 1],
            "1.1.1.1:53,1.0.0.1:53",
        )
        self.assertEqual(
            captured["env"]["CF_DNS_API_TOKEN_FILE"], str(client.dns_token_path)
        )
        self.assertFalse(any(path.name.startswith("issuance-") for path in client.root.iterdir()))
        self.assertFalse(any((client.storage_path / "certificates").glob("*.key")))
        self.assertTrue(any((client.storage_path / "certificates").glob("*.crt")))
        certificate_id = captured["command"][
            captured["command"].index("--cert.name") + 1
        ]
        retained = json.loads(
            (client.certificate_accounts_path / (certificate_id + ".json")).read_text()
        )
        self.assertEqual(retained["id"], "admin@example.com")

    def test_issue_recovers_once_when_retained_account_no_longer_exists(self):
        attempts = []
        server = "https://acme-v02.api.letsencrypt.org/directory"

        def runner(command, **_options):
            attempts.append(list(command))
            if len(attempts) == 1:
                return type("Completed", (), {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": (
                        "acme: error: 400 :: urn:ietf:params:acme:error:"
                        "accountDoesNotExist :: No account exists with the provided key"
                    ),
                })()
            self._write_registered_account(
                client, "admin@example.com", "admin@example.com", server,
            )
            certificate_id = command[command.index("--cert.name") + 1]
            output = client.storage_path / "certificates"
            output.mkdir(parents=True, exist_ok=True)
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
                    x509.SubjectAlternativeName([
                        x509.DNSName("device.example.com")
                    ]), critical=False,
                ).sign(key, hashes.SHA256())
            )
            (output / (certificate_id + ".crt")).write_bytes(
                certificate.public_bytes(serialization.Encoding.PEM)
            )
            (output / (certificate_id + ".key")).write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            return type("Completed", (), {
                "returncode": 0, "stdout": "", "stderr": "",
            })()

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="production", terms_accepted=True,
            dns_token="dns-secret",
        )
        self._write_registered_account(
            client, "admin@example.com", "admin@example.com", server,
        )

        result = client.issue(["device.example.com"])

        self.assertEqual(len(attempts), 2)
        self.assertEqual(
            result.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "device.example.com",
        )
        self.assertEqual(len(list((client.root / "invalid-accounts").iterdir())), 1)
        self.assertEqual(len(client._registered_accounts()), 1)
        retained = next(client.certificate_accounts_path.glob("*.json"))
        self.assertNotIn("_path", retained.read_text())

    def test_issue_does_not_replace_account_for_unrelated_acme_failure(self):
        attempts = []
        server = "https://acme-v02.api.letsencrypt.org/directory"

        def runner(command, **_options):
            attempts.append(list(command))
            return type("Completed", (), {
                "returncode": 1,
                "stdout": "",
                "stderr": "cloudflare: failed to find zone for domain",
            })()

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="production", terms_accepted=True,
            dns_token="dns-secret",
        )
        self._write_registered_account(
            client, "admin@example.com", "admin@example.com", server,
        )

        with self.assertRaisesRegex(RuntimeError, "failed to find zone"):
            client.issue(["device.example.com"])

        self.assertEqual(len(attempts), 1)
        self.assertFalse((client.root / "invalid-accounts").exists())
        self.assertEqual(len(client._registered_accounts()), 1)

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
            certificate_id = command[command.index("--cert.name") + 1]
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
            (output / (certificate_id + ".crt")).write_bytes(
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

    def test_revoke_uses_retained_account_and_public_certificate(self):
        captured = {}

        def runner(command, **_options):
            captured["command"] = command
            return type("Completed", (), {
                "returncode": 0, "stdout": "", "stderr": "",
            })()

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="admin@example.com", zone="example.com",
            environment="production", terms_accepted=True,
            dns_token="dns-secret",
        )
        self._write_registered_account(
            client, "admin@example.com", "admin@example.com",
            "https://acme-v02.api.letsencrypt.org/directory",
        )
        certificates = client.storage_path / "certificates"
        certificates.mkdir(parents=True, exist_ok=True)
        (certificates / "certificate-1.crt").write_text("public certificate")

        client.revoke("certificate-1")

        self.assertEqual(captured["command"][:3], ["lego", "certificates", "revoke"])
        self.assertIn("--keep", captured["command"])
        self.assertNotIn("--cert-name", captured["command"])
        self.assertEqual(
            captured["command"][captured["command"].index("--cert.name") + 1],
            "certificate-1",
        )
        self.assertEqual(
            captured["command"][captured["command"].index("--account-id") + 1],
            "admin@example.com",
        )

    def test_revoke_discovers_issuing_account_after_settings_email_changes(self):
        captured = {}

        def runner(command, **_options):
            captured["command"] = command
            return type("Completed", (), {
                "returncode": 0, "stdout": "", "stderr": "",
            })()

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="new-admin@example.com", zone="example.com",
            environment="production", terms_accepted=True,
            dns_token="dns-secret",
        )
        self._write_registered_account(
            client, "original-admin@example.com", "original-admin@example.com",
            "https://acme-v02.api.letsencrypt.org/directory", "EC256",
        )
        certificates = client.storage_path / "certificates"
        certificates.mkdir(parents=True, exist_ok=True)
        (certificates / "certificate-2.crt").write_text("public certificate")

        client.revoke("certificate-2")

        self.assertEqual(
            captured["command"][captured["command"].index("--account-id") + 1],
            "original-admin@example.com",
        )
        self.assertEqual(
            captured["command"][captured["command"].index("--key-type") + 1],
            "EC256",
        )
        retained = json.loads(
            (client.certificate_accounts_path / "certificate-2.json").read_text()
        )
        self.assertEqual(retained["id"], "original-admin@example.com")

    def test_revoke_tries_retained_accounts_until_issuer_accepts_one(self):
        attempted = []

        def runner(command, **_options):
            account_id = command[command.index("--account-id") + 1]
            attempted.append(account_id)
            return type("Completed", (), {
                "returncode": 0 if account_id == "issuer@example.com" else 1,
                "stdout": "",
                "stderr": "unauthorized account" if account_id != "issuer@example.com" else "",
            })()

        client = ExternalACME(self.root, runner=runner)
        client.configure(
            enabled=True, email="current@example.com", zone="example.com",
            environment="production", terms_accepted=True,
            dns_token="dns-secret",
        )
        server = "https://acme-v02.api.letsencrypt.org/directory"
        self._write_registered_account(
            client, "current@example.com", "current@example.com", server,
        )
        self._write_registered_account(
            client, "issuer@example.com", "issuer@example.com", server,
        )
        certificates = client.storage_path / "certificates"
        certificates.mkdir(parents=True, exist_ok=True)
        (certificates / "certificate-3.crt").write_text("public certificate")

        client.revoke("certificate-3")

        self.assertEqual(attempted, ["current@example.com", "issuer@example.com"])


if __name__ == "__main__":
    unittest.main()
