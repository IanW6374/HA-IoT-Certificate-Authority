import tempfile
import unittest
import sqlite3
from pathlib import Path

from iot_ca.database import Inventory


class DatabaseTests(unittest.TestCase):
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
