import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from iot_ca.service import CertificateService
from tests.helpers import FakeEngine


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.engine = FakeEngine()
        self.service = CertificateService(self.root, engine=self.engine)

    def tearDown(self):
        self.temporary.cleanup()

    def test_hamd_export_and_private_key_disposal(self):
        certificate_id, token = self.service.issue(
            profile_slug="hamd",
            common_name="hamd-a1b2c3",
            sans="hamd-a1b2c3.home.arpa,192.168.1.20",
            key_type="rsa-2048",
            validity_days=365,
            export_format="hamd",
        )
        record = self.service.certificate(certificate_id)
        self.assertEqual(record["profile"], "hamd")
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


if __name__ == "__main__":
    unittest.main()
