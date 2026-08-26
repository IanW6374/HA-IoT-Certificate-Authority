import tempfile
import unittest
import zipfile
import base64
from pathlib import Path
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from iot_ca.service import CertificateService
from tests.helpers import FakeEngine, FakeExternalACME


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.engine = FakeEngine()
        self.service = CertificateService(self.root, engine=self.engine)

    def tearDown(self):
        self.temporary.cleanup()

    def test_iot_md_export_and_private_key_disposal(self):
        certificate_id, token = self.service.issue(
            profile_slug="iot_md",
            common_name="iot-md-a1b2c3",
            sans="iot-md-a1b2c3.home.arpa,192.168.1.20",
            key_type="rsa-2048",
            validity_days=365,
            export_format="iot_md",
        )
        record = self.service.certificate(certificate_id)
        self.assertEqual(record["profile"], "iot_md")
        self.assertEqual(record["source"], "manual")
        self.assertEqual(record["provisioner"], "iot-ca-admin")
        self.assertNotIn(b"PRIVATE KEY", record["certificate_pem"])
        export = self.service.export_for_token(token)
        with zipfile.ZipFile(export["path"]) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {
                    "certificate-info.json", "web.crt.der", "web.key.der",
                    "mqtt-ca.der", "update-ca.der", "intermediate-ca.der",
                },
            )
            key = serialization.load_der_private_key(archive.read("web.key.der"), password=None)
            self.assertEqual(key.key_size, 2048)
        self.service.complete_export(export)
        self.assertFalse(Path(export["path"]).exists())
        self.assertIsNone(self.service.export_for_token(token))

    def test_pkcs12_requires_password(self):
        with self.assertRaisesRegex(ValueError, "password"):
            self.service.issue(
                profile_slug="tls-server",
                common_name="service",
                sans="service.home.arpa",
                key_type="ec-p256",
                validity_days=90,
                export_format="pkcs12",
                export_password="short",
            )

    def test_reissue_revokes_old_serial(self):
        old_id, _ = self.service.issue(
            profile_slug="tls-client",
            common_name="sensor-1",
            sans="",
            key_type="ec-p256",
            validity_days=90,
            export_format="pem",
        )
        new_id, token = self.service.renew(old_id, export_format="pem")
        self.assertNotEqual(old_id, new_id)
        self.assertEqual(self.service.certificate(old_id)["status"], "superseded")
        self.assertEqual(self.service.certificate(old_id)["sans"], ["sensor-1"])
        self.assertEqual(self.service.certificate(new_id)["renewed_from"], old_id)
        self.assertTrue(self.engine.revoked)
        self.assertIsNotNone(self.service.export_for_token(token))

    def test_public_ca_downloads_include_root_and_intermediate(self):
        root = x509.load_pem_x509_certificate(self.service.root_trust())
        intermediate = x509.load_pem_x509_certificate(self.service.intermediate_trust())
        chain = self.service.ca_chain()

        self.assertEqual(
            self.service.root_trust("der"),
            root.public_bytes(serialization.Encoding.DER),
        )
        self.assertEqual(
            self.service.intermediate_trust("der"),
            intermediate.public_bytes(serialization.Encoding.DER),
        )
        self.assertEqual(chain.count(b"-----BEGIN CERTIFICATE-----"), 2)
        self.assertEqual(chain, self.service.intermediate_trust() + self.service.root_trust())

    def test_existing_certificate_exports_use_requested_encoding(self):
        certificate_id, _ = self.service.issue(
            profile_slug="tls-server",
            common_name="existing.home.arpa",
            sans="existing.home.arpa",
            key_type="ec-p256",
            validity_days=90,
            export_format="pem",
        )

        pem = self.service.certificate_public_bytes(certificate_id, "PEM")
        der = self.service.certificate_public_bytes(certificate_id, "DER")

        self.assertTrue(pem.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertFalse(der.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertEqual(
            x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256()),
            x509.load_der_x509_certificate(der).fingerprint(hashes.SHA256()),
        )

    def test_public_certificate_exports_reject_unknown_encoding(self):
        with self.assertRaisesRegex(ValueError, "PEM or DER"):
            self.service.root_trust("pkcs12")

    def test_public_portal_profile_exports_split_public_and_private_identities(self):
        service = CertificateService(
            self.root, engine=self.engine, external_acme=FakeExternalACME()
        )
        certificate_id, token = service.issue_public_portal(
            common_name="device.example.com",
            sans="alias.example.com",
            api_hostname="device.local",
        )

        public = service.certificate(certificate_id)
        self.assertEqual(public["profile"], "public-portal")
        self.assertEqual(public["source"], "external-acme")
        api = next(
            item for item in service.certificates()
            if item["provisioner"] == "iot-md-public-profile"
        )
        self.assertEqual(api["common_name"], "device.local")
        export = service.export_for_token(token)
        with zipfile.ZipFile(export["path"]) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {
                    "certificate-info.json", "web.crt.pem", "web.key.der",
                    "api-server.crt.der",
                    "api-server.key.der", "api-server.crt.pem", "mqtt-ca.der",
                    "update-ca.der", "intermediate-ca.der",
                },
            )
            public_key = serialization.load_der_private_key(
                archive.read("web.key.der"), password=None
            )
            api_key = serialization.load_der_private_key(
                archive.read("api-server.key.der"), password=None
            )
            self.assertEqual(public_key.key_size, 2048)
            self.assertEqual(api_key.key_size, 2048)
            self.assertNotEqual(
                public_key.public_key().public_numbers(),
                api_key.public_key().public_numbers(),
            )

    def test_public_portal_rejects_invalid_private_name_before_acme_request(self):
        external_acme = FakeExternalACME()
        external_acme.issue = Mock(side_effect=AssertionError("ACME must not be called"))
        service = CertificateService(
            self.root, engine=self.engine, external_acme=external_acme
        )

        with self.assertRaisesRegex(ValueError, "single-label .local"):
            service.issue_public_portal(
                common_name="device.example.com",
                sans="",
                api_hostname="",
            )
        external_acme.issue.assert_not_called()

    @staticmethod
    def enrollment_csr(name, usage, include_san=True):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        ).add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        if include_san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False
            )
        csr = builder.sign(key, hashes.SHA256())
        return base64.b64encode(
            csr.public_bytes(serialization.Encoding.DER)
        ).decode()

    def test_device_enrollment_issues_only_authorized_device_csrs(self):
        service = CertificateService(
            self.root, engine=self.engine, external_acme=FakeExternalACME()
        )
        enrollment_id, export_token = service.create_device_enrollment("device")
        exported = service.export_for_token(export_token)
        package = __import__("json").loads(Path(exported["path"]).read_text())
        request = {
            "portal_csr": self.enrollment_csr(
                "device.example.com", ExtendedKeyUsageOID.SERVER_AUTH
            ),
            "api_csr": self.enrollment_csr(
                "device.local", ExtendedKeyUsageOID.SERVER_AUTH
            ),
            "renewal_csr": self.enrollment_csr(
                package["renewal_name"], ExtendedKeyUsageOID.CLIENT_AUTH, False
            ),
        }

        claimed = service.claim_device_enrollment(
            enrollment_id, package["token"], request
        )
        self.assertEqual(claimed["status"], "pending")
        service.fulfill_device_enrollment(enrollment_id)
        status = service.device_enrollment_status(
            enrollment_id, package["token"]
        )
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["result"]["portal_hostname"], "device.example.com")
        self.assertEqual(status["result"]["api_hostname"], "device.local")
        self.assertEqual(
            base64.b64decode(status["result"]["api_certificate_pem"]).count(
                b"-----BEGIN CERTIFICATE-----"
            ),
            2,
        )
        self.assertEqual(len(service.certificates()), 3)

    def test_device_enrollment_rejects_a_csr_for_another_host(self):
        service = CertificateService(
            self.root, engine=self.engine, external_acme=FakeExternalACME()
        )
        enrollment_id, export_token = service.create_device_enrollment("device")
        package = __import__("json").loads(Path(
            service.export_for_token(export_token)["path"]
        ).read_text())
        service.claim_device_enrollment(enrollment_id, package["token"], {
            "portal_csr": self.enrollment_csr(
                "other.example.com", ExtendedKeyUsageOID.SERVER_AUTH
            ),
            "api_csr": self.enrollment_csr(
                "device.local", ExtendedKeyUsageOID.SERVER_AUTH
            ),
            "renewal_csr": self.enrollment_csr(
                package["renewal_name"], ExtendedKeyUsageOID.CLIENT_AUTH, False
            ),
        })

        with self.assertRaisesRegex(ValueError, "identity does not match"):
            service.fulfill_device_enrollment(enrollment_id)
        self.assertEqual(
            service.device_enrollment_status(enrollment_id, package["token"])["status"],
            "error",
        )


if __name__ == "__main__":
    unittest.main()
