import re
import tempfile
import unittest
from pathlib import Path

from iot_ca.service import CertificateService
from iot_ca.web import create_app
from tests.helpers import FakeEngine


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.service = CertificateService(root, engine=FakeEngine())
        self.app = create_app(data_root=root, service=self.service)
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary.cleanup()

    def csrf(self):
        response = self.client.get("/")
        with self.client.session_transaction() as browser_session:
            return browser_session["csrf_token"]

    def test_dashboard_and_ingress_prefix(self):
        response = self.client.get("/", headers={"X-Ingress-Path": "/api/hassio_ingress/test"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Certificate operations at a glance", response.data)
        self.assertIn(b"/api/hassio_ingress/test/certificates", response.data)

    def test_post_requires_csrf(self):
        response = self.client.post("/certificates/new", data={})
        self.assertEqual(response.status_code, 403)

    def test_offline_root_warning_clears_after_confirmation(self):
        token = self.service._store_export(
            b"encrypted-root-export",
            kind="offline-root",
            filename="iot-ca-offline-root.zip",
        )
        csrf_token = self.csrf()
        with self.client.session_transaction() as browser_session:
            browser_session["pending_export_token"] = token
            browser_session["pending_export_kind"] = "offline-root"

        dashboard = self.client.get("/")
        self.assertIn(b"Offline root export is awaiting confirmation", dashboard.data)
        confirmed = self.client.post(
            "/exports/confirm",
            data={"csrf_token": csrf_token},
            follow_redirects=True,
        )
        self.assertEqual(confirmed.status_code, 200)
        self.assertNotIn(b"Offline root export is awaiting confirmation", confirmed.data)
        self.assertIsNone(self.service.export_for_token(token))

    def test_issue_route_prepares_one_time_export(self):
        response = self.client.post(
            "/certificates/new",
            data={
                "csrf_token": self.csrf(),
                "profile": "hamd",
                "common_name": "hamd-web-test",
                "sans": "hamd-web-test.home.arpa",
                "key_type": "rsa-2048",
                "validity_days": "365",
                "export_format": "hamd",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Certificate package is ready", response.data)
        self.assertIn(b"hamd-web-test-hamd.zip", response.data)
        with self.client.session_transaction() as browser_session:
            token = browser_session["pending_export_token"]
            csrf_token = browser_session["csrf_token"]

        download = self.client.get("/download")
        self.assertEqual(download.status_code, 200)
        self.assertIsNotNone(self.service.export_for_token(token))
        download.close()

        confirmed = self.client.post(
            "/exports/confirm",
            data={"csrf_token": csrf_token},
            follow_redirects=True,
        )
        self.assertEqual(confirmed.status_code, 200)
        self.assertIn(b"Export confirmed and removed from app storage", confirmed.data)
        self.assertIsNone(self.service.export_for_token(token))


if __name__ == "__main__":
    unittest.main()
