import tempfile
import unittest
from pathlib import Path

from iot_ca.database import Inventory


class DatabaseTests(unittest.TestCase):
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
