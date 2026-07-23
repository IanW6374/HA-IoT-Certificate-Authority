import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from iot_ca.acme_inventory import ensure_json_logging, import_log_line
from iot_ca.database import Inventory
from iot_ca.service import CertificateService
from tests.helpers import FakeEngine


class AcmeInventoryTests(unittest.TestCase):
    def certificate(self, root, common_name="whes01.home.arpa"):
        service = CertificateService(root / "source", engine=FakeEngine())
        certificate_id, _token = service.issue(
            profile_slug="tls-server",
            common_name=common_name,
            sans=common_name,
            key_type="ec-p256",
            validity_days=1,
            export_format="pem",
        )
        return x509.load_pem_x509_certificate(
            service.certificate(certificate_id)["certificate_pem"]
        )

    @staticmethod
    def log_line(certificate, **overrides):
        entry = {
            "path": "/acme/acme/certificate/order-1",
            "status": 200,
            "provisioner": "acme (provisioner-id)",
            "certificate": base64.b64encode(
                certificate.public_bytes(serialization.Encoding.DER)
            ).decode(),
        }
        entry.update(overrides)
        return json.dumps(entry)

    def test_successful_acme_certificate_is_imported_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = Inventory(root / "inventory.db")
            certificate = self.certificate(root)
            line = self.log_line(certificate)

            certificate_id = import_log_line(line, inventory)
            self.assertEqual(import_log_line(line, inventory), certificate_id)
            records = inventory.certificates()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["common_name"], "whes01.home.arpa")
            self.assertEqual(records[0]["sans"], ["whes01.home.arpa"])
            self.assertEqual(records[0]["source"], "acme")
            self.assertEqual(records[0]["profile"], "tls-server")
            self.assertEqual(records[0]["provisioner"], "acme (provisioner-id)")
            self.assertEqual(
                [entry["action"] for entry in inventory.audit_log()],
                ["certificate.acme-import"],
            )

    def test_acme_renewal_links_and_supersedes_previous_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = Inventory(root / "inventory.db")
            first = self.certificate(root / "first")
            second = self.certificate(root / "second")
            first_id = import_log_line(self.log_line(first), inventory)
            second_id = import_log_line(self.log_line(second), inventory)

            self.assertNotEqual(first_id, second_id)
            self.assertEqual(inventory.certificate(first_id)["status"], "superseded")
            self.assertEqual(
                inventory.certificate(second_id)["renewed_from"], first_id
            )

    def test_non_acme_or_failed_log_entries_are_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = Inventory(root / "inventory.db")
            certificate = self.certificate(root)
            self.assertIsNone(import_log_line(
                self.log_line(certificate, path="/1.0/sign"), inventory
            ))
            self.assertIsNone(import_log_line(
                self.log_line(certificate, status=500), inventory
            ))
            self.assertIsNone(import_log_line("[]", inventory))
            self.assertIsNone(import_log_line('{"status":"invalid"}', inventory))
            self.assertEqual(inventory.certificates(), [])

    def test_existing_ca_configuration_is_migrated_to_json_logging(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ca.json"
            path.write_text(json.dumps({
                "address": ":9000",
                "logger": {"format": "text", "traceHeader": "X-Trace"},
            }))
            self.assertTrue(ensure_json_logging(path))
            self.assertFalse(ensure_json_logging(path))
            config = json.loads(path.read_text())
            self.assertEqual(config["logger"]["format"], "json")
            self.assertEqual(config["logger"]["traceHeader"], "X-Trace")


if __name__ == "__main__":
    unittest.main()
