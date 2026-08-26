import re
import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from iot_ca.service import CertificateService
from iot_ca.web import create_app
from tests.helpers import FakeEngine, FakeExternalACME


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.service = CertificateService(
            root, engine=FakeEngine(), external_acme=FakeExternalACME()
        )
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

    def test_initial_setup_renders_submitable_identity_defaults(self):
        engine = FakeEngine()
        engine.initialized = False
        service = CertificateService(
            Path(self.temporary.name) / "uninitialized",
            engine=engine, external_acme=FakeExternalACME(),
        )
        app = create_app(
            data_root=Path(self.temporary.name) / "uninitialized", service=service
        )
        response = app.test_client().get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'name="ca_name" required minlength="3" maxlength="64" '
            b'value="Home IoT CA"', response.data
        )
        self.assertIn(
            b'name="ca_dns" required value="iot-ca.home.arpa"', response.data
        )
        self.assertIn(
            b'name="allowed_dns_suffix" required value="home.arpa"', response.data
        )

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
                "profile": "iot_md",
                "common_name": "iot-md-web-test",
                "sans": "iot-md-web-test.home.arpa",
                "key_type": "rsa-2048",
                "validity_days": "365",
                "export_format": "iot_md",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Certificate package is ready", response.data)
        self.assertIn(b"iot-md-web-test-iot-md.zip", response.data)
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

    def test_certificate_pages_show_inventory_source(self):
        certificate_id, _token = self.service.issue(
            profile_slug="tls-server",
            common_name="portal.home.arpa",
            sans="portal.home.arpa",
            key_type="ec-p256",
            validity_days=90,
            export_format="pem",
        )
        listing = self.client.get("/certificates")
        self.assertIn(b"Source", listing.data)
        self.assertIn(b"MANUAL", listing.data)
        detail = self.client.get("/certificates/" + certificate_id)
        self.assertIn(b"Provisioner", detail.data)
        self.assertIn(b"iot-ca-admin", detail.data)
        self.assertIn(b"Download PEM", detail.data)
        self.assertIn(b"Download DER", detail.data)

        pem = self.client.get(
            "/certificates/" + certificate_id + "/download?format=pem"
        )
        self.assertEqual(pem.status_code, 200)
        self.assertEqual(pem.mimetype, "application/x-pem-file")
        x509.load_pem_x509_certificate(pem.data)

        der = self.client.get(
            "/certificates/" + certificate_id + "/download?format=der"
        )
        self.assertEqual(der.status_code, 200)
        self.assertEqual(der.mimetype, "application/pkix-cert")
        self.assertNotIn(b"-----BEGIN CERTIFICATE-----", der.data)
        x509.load_der_x509_certificate(der.data)

    def test_iot_md_export_uses_human_readable_label(self):
        certificate_id, _token = self.service.issue(
            profile_slug="iot_md",
            common_name="iot-md-label-test",
            sans="iot-md-label-test.home.arpa",
            key_type="rsa-2048",
            validity_days=365,
            export_format="iot_md",
        )
        detail = self.client.get("/certificates/" + certificate_id)
        self.assertIn(b">IoT MD<", detail.data)
        self.assertNotIn(b"IOT" + b"_MD", detail.data)

        script = (
            Path(__file__).parents[1]
            / "iot_certificate_authority/rootfs/opt/iot-ca/iot_ca/static/app.js"
        ).read_text(encoding="utf-8")
        self.assertIn('value === "iot_md" ? "IoT MD"', script)

    def test_certificate_status_filter_defaults_to_active(self):
        active_id, _ = self.service.issue(
            profile_slug="tls-client",
            common_name="active-client",
            sans="",
            key_type="ec-p256",
            validity_days=90,
            export_format="pem",
        )
        revoked_id, _ = self.service.issue(
            profile_slug="tls-client",
            common_name="revoked-client",
            sans="",
            key_type="ec-p256",
            validity_days=90,
            export_format="pem",
        )
        self.service.revoke(revoked_id)

        default_listing = self.client.get("/certificates")
        self.assertIn(active_id.encode(), default_listing.data)
        self.assertNotIn(revoked_id.encode(), default_listing.data)
        self.assertIn(b'<option value="active" selected>', default_listing.data)
        self.assertNotIn(b"Apply filter", default_listing.data)

        revoked_listing = self.client.get("/certificates?status=revoked")
        self.assertNotIn(active_id.encode(), revoked_listing.data)
        self.assertIn(revoked_id.encode(), revoked_listing.data)

        all_listing = self.client.get("/certificates?status=all")
        self.assertIn(active_id.encode(), all_listing.data)
        self.assertIn(revoked_id.encode(), all_listing.data)

    def test_public_ca_certificate_downloads(self):
        settings = self.client.get("/settings")
        self.assertIn(b"Intermediate PEM", settings.data)
        self.assertIn(b"CA chain PEM", settings.data)

        intermediate = self.client.get("/trust/intermediate.pem")
        self.assertEqual(intermediate.status_code, 200)
        self.assertIn(b"iot-ca-intermediate.pem", intermediate.headers["Content-Disposition"].encode())
        self.assertEqual(intermediate.data.count(b"-----BEGIN CERTIFICATE-----"), 1)

        chain = self.client.get("/trust/chain.pem")
        self.assertEqual(chain.status_code, 200)
        self.assertIn(b"iot-ca-chain.pem", chain.headers["Content-Disposition"].encode())
        self.assertEqual(chain.data.count(b"-----BEGIN CERTIFICATE-----"), 2)

        root_der = self.client.get("/trust/root.der")
        self.assertEqual(root_der.status_code, 200)
        self.assertNotIn(b"-----BEGIN CERTIFICATE-----", root_der.data)
        x509.load_der_x509_certificate(root_der.data)

    def test_acme_url_has_copy_controls(self):
        for path in ("/", "/settings"):
            response = self.client.get(path)
            self.assertIn(b'data-copy-target="#acme-directory"', response.data)
            self.assertIn(b'aria-label="Copy ACME directory URL"', response.data)
            self.assertIn(b'class="copy-icon"', response.data)

    def test_public_acme_settings_never_render_tokens(self):
        response = self.client.get("/settings")
        self.assertIn(b"Public portal certificates", response.data)
        self.assertIn(b"Cloudflare DNS API token", response.data)
        self.assertIn(b"Allowed public portal DNS suffix", response.data)
        self.assertIn(b"Account ID, not a Client ID", response.data)
        self.assertIn(b"no separate Home Assistant integration", response.data)
        self.assertIn("••••••••••••".encode(), response.data)
        self.assertNotIn(b"Configured", response.data)
        self.assertNotIn(b"dns-secret", response.data)

        saved = self.client.post(
            "/settings/external-acme",
            data={
                "csrf_token": self.csrf(), "enabled": "on",
                "email": "admin@example.com", "zone": "example.com",
                "environment": "production", "terms_accepted": "on",
                "dns_token": "new-dns-secret",
            },
            follow_redirects=True,
        )
        self.assertEqual(saved.status_code, 200)
        self.assertIn(b"Public ACME settings saved", saved.data)
        self.assertNotIn(b"new-dns-secret", saved.data)

    def test_public_portal_route_prepares_complete_profile_export(self):
        response = self.client.post(
            "/public-certificates/new",
            data={
                "csrf_token": self.csrf(),
                "common_name": "device.example.com",
                "api_hostname": "device.local",
                "sans": "alias.example.com",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Certificate package is ready", response.data)
        self.assertIn(b"device.example.com-public-portal.zip", response.data)


if __name__ == "__main__":
    unittest.main()
