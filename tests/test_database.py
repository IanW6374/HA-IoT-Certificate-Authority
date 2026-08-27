import tempfile
import unittest
import sqlite3
from pathlib import Path

from iot_ca.database import Inventory


class DatabaseTests(unittest.TestCase):
    @staticmethod
    def certificate_record(certificate_id, serial, issued, *, status="active"):
        return {
            "id": certificate_id, "profile": "public-portal",
            "common_name": "device.example.com",
            "sans_json": '["device.example.com"]', "key_type": "rsa-2048",
            "validity_days": 90, "serial": serial,
            "fingerprint": "fingerprint-" + serial, "not_before": issued,
            "not_after": "2027-01-01T00:00:00Z", "status": status,
            "certificate_pem": b"certificate", "created_at": issued,
            "renewed_from": None, "revoked_at": None,
            "source": "external-acme", "provisioner": "test",
        }

    def test_startup_reconciles_existing_public_replacement_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.db"
            inventory = Inventory(path)
            inventory.add_certificate(self.certificate_record(
                "original", "100", "2026-01-01T00:00:00Z"
            ))
            replacement = self.certificate_record(
                "replacement", "200", "2026-02-01T00:00:00Z",
                status="revoked",
            )
            replacement["sans_json"] = '["device.example.com", "alias.example.com"]'
            inventory.add_certificate(replacement)

            repaired = Inventory(path)
            self.assertEqual(repaired.certificate("original")["status"], "superseded")
            self.assertEqual(
                repaired.certificate("replacement")["renewed_from"], "original"
            )
            self.assertEqual(repaired.dashboard_counts()["active"], 0)

    def test_add_certificate_supersedes_matching_identity_atomically(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Inventory(Path(temporary) / "inventory.db")
            inventory.add_certificate(self.certificate_record(
                "original", "100", "2026-01-01T00:00:00Z"
            ))
            inventory.add_certificate(
                self.certificate_record(
                    "replacement", "200", "2026-02-01T00:00:00Z"
                ),
                supersede_matching=True,
            )

            self.assertEqual(inventory.certificate("original")["status"], "superseded")
            self.assertEqual(
                inventory.certificate("replacement")["renewed_from"], "original"
            )

    def test_device_enrollment_token_is_one_time_and_request_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Inventory(Path(directory) / "inventory.db")
            inventory.add_device_enrollment(
                enrollment_id="enrollment-1", token="secret-token",
                portal_hostname="device.example.com",
                api_hostname="device.local", renewal_name="renewal-device",
                expires_at="2099-01-01T00:00:00Z",
            )

            self.assertIsNone(
                inventory.device_enrollment("enrollment-1", "wrong-token")
            )
            claimed = inventory.claim_device_enrollment(
                "enrollment-1", "secret-token", {"portal_csr": "first"}
            )
            self.assertEqual(claimed["status"], "pending")
            self.assertEqual(claimed["request"]["portal_csr"], "first")
            repeated = inventory.claim_device_enrollment(
                "enrollment-1", "secret-token", {"portal_csr": "first"}
            )
            self.assertEqual(repeated["status"], "pending")
            with self.assertRaisesRegex(ValueError, "another request"):
                inventory.claim_device_enrollment(
                    "enrollment-1", "secret-token", {"portal_csr": "second"}
                )
    def test_existing_inventory_gains_certificate_source_columns(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.db"
            with sqlite3.connect(path) as db:
                db.execute(
                    """
                    CREATE TABLE certificates (
                        id TEXT PRIMARY KEY, profile TEXT NOT NULL,
                        common_name TEXT NOT NULL, sans_json TEXT NOT NULL,
                        key_type TEXT NOT NULL, validity_days INTEGER NOT NULL,
                        serial TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL,
                        not_before TEXT NOT NULL, not_after TEXT NOT NULL,
                        status TEXT NOT NULL, certificate_pem BLOB NOT NULL,
                        created_at TEXT NOT NULL, renewed_from TEXT,
                        revoked_at TEXT
                    )
                    """
                )
                db.execute(
                    """
                    INSERT INTO certificates VALUES(
                        'old-id', 'tls-server', 'old.home.arpa', '[]',
                        'ec-p256', 90, '123', 'fingerprint',
                        '2026-01-01T00:00:00Z', '2026-04-01T00:00:00Z',
                        'active', X'00', '2026-01-01T00:00:00Z', NULL, NULL
                    )
                    """
                )

            inventory = Inventory(path)
            record = inventory.certificate("old-id")
            self.assertEqual(record["source"], "manual")
            self.assertIsNone(record["provisioner"])

    def test_export_tokens_are_hashed_and_replaceable(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Inventory(Path(temporary) / "inventory.db")
            token = inventory.add_export(
                export_id="export-1",
                kind="offline-root",
                path=str(Path(temporary) / "root.zip"),
                filename="root.zip",
                expires_at="2099-01-01T00:00:00Z",
            )
            record = inventory.export_for_token(token)
            self.assertEqual(record["id"], "export-1")
            replacement = inventory.replace_export_token("export-1")
            self.assertIsNone(inventory.export_for_token(token))
            self.assertEqual(inventory.export_for_token(replacement)["id"], "export-1")
            inventory.consume_export("export-1")
            self.assertIsNone(inventory.export_for_token(replacement))


if __name__ == "__main__":
    unittest.main()
