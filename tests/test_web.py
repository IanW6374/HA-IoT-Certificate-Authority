import re
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

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
        self.assertIn(b"Certificate actions", response.data)
        self.assertIn(b"Automatic IoT CA enrollment", response.data)
        self.assertIn(b"IoT CA enrollment authorization", response.data)
        self.assertIn(b"Create enrollment authorization", response.data)
        self.assertIn(b"Enable for 5 minutes", response.data)
        self.assertGreaterEqual(response.data.count(b'class="button primary"'), 3)
        self.assertIn(b'class="primary" type="submit">Enable for 5 minutes', response.data)
        self.assertLess(response.data.index(b'class="stats"'), response.data.index(b"Certificate actions"))

    def test_automatic_enrollment_is_an_overview_action_with_countdown(self):
        settings = self.client.get("/settings")
        self.assertIn(b"Automatic IoT CA enrollment window (minutes)", settings.data)
        self.assertIn(b'name="auto_enroll_minutes"', settings.data)
        self.assertNotIn(b"Enable automatic IoT MD enrollment", settings.data)

        opened = self.client.post(
            "/automatic-enrollment/open",
            data={"csrf_token": self.csrf()}, follow_redirects=True,
        )
        self.assertEqual(opened.status_code, 200)
        self.assertIn(b"Automatic IoT CA enrollment opened for 5 minutes", opened.data)
        self.assertIn(b"data-enrollment-countdown", opened.data)
        self.assertIn(b"Enrollment open", opened.data)

        closed = self.client.post(
            "/automatic-enrollment/close",
            data={"csrf_token": self.csrf()}, follow_redirects=True,
        )
        self.assertIn(b"Automatic IoT CA enrollment closed", closed.data)
        self.assertIn(b"Enable for 5 minutes", closed.data)

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
        self.assertIn(b"Download full-chain PEM", detail.data)
        self.assertIn(b"Download PKCS#7 PEM", detail.data)
        self.assertIn(b"Download PKCS#7 DER", detail.data)

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

        fullchain = self.client.get(
            "/certificates/" + certificate_id + "/fullchain?format=pem"
        )
        self.assertEqual(fullchain.status_code, 200)
        self.assertEqual(
            fullchain.data.count(b"-----BEGIN CERTIFICATE-----"), 3
        )
        fullchain_pem = self.client.get(
            "/certificates/" + certificate_id +
            "/fullchain?format=pkcs7-pem"
        )
        self.assertEqual(
            len(pkcs7.load_pem_pkcs7_certificates(fullchain_pem.data)), 3
        )
        fullchain_der = self.client.get(
            "/certificates/" + certificate_id +
            "/fullchain?format=pkcs7-der"
        )
        self.assertEqual(
            len(pkcs7.load_der_pkcs7_certificates(fullchain_der.data)), 3
        )

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
        reissue = self.client.get(
            "/certificates/" + certificate_id + "/reissue"
        )
        self.assertIn(b">IoT MD device portal<", reissue.data)
        self.assertNotIn(b"IOT" + b"_MD", reissue.data)

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
        dashboard = self.client.get("/")
        self.assertIn(b"CA trust downloads", dashboard.data)
        self.assertIn(b"Root certificate", dashboard.data)
        self.assertIn(b"Full CA chain", dashboard.data)
        self.assertIn(b"PKCS#7 DER", dashboard.data)
        self.assertEqual(dashboard.data.count(b"download-actions"), 2)

        settings = self.client.get("/settings")
        self.assertNotIn(b"Public CA certificates", settings.data)
        self.assertNotIn(b"Root PEM", settings.data)

        intermediate = self.client.get("/trust/intermediate.pem")
        self.assertEqual(intermediate.status_code, 200)
        self.assertIn(b"iot-ca-intermediate.pem", intermediate.headers["Content-Disposition"].encode())
        self.assertEqual(intermediate.data.count(b"-----BEGIN CERTIFICATE-----"), 1)

        chain = self.client.get("/trust/fullchain.pem")
        self.assertEqual(chain.status_code, 200)
        self.assertIn(b"iot-ca-fullchain.pem", chain.headers["Content-Disposition"].encode())
        self.assertEqual(chain.data.count(b"-----BEGIN CERTIFICATE-----"), 2)

        chain_der = self.client.get("/trust/fullchain.p7b")
        self.assertEqual(chain_der.status_code, 200)
        self.assertEqual(chain_der.mimetype, "application/pkcs7-mime")
        self.assertIn(
            b"iot-ca-fullchain.p7b",
            chain_der.headers["Content-Disposition"].encode(),
        )
        self.assertEqual(len(pkcs7.load_der_pkcs7_certificates(chain_der.data)), 2)

        root_der = self.client.get("/trust/root.der")
        self.assertEqual(root_der.status_code, 200)
        self.assertNotIn(b"-----BEGIN CERTIFICATE-----", root_der.data)
        x509.load_der_x509_certificate(root_der.data)

    def test_acme_url_has_copy_controls(self):
        dashboard = self.client.get("/")
        self.assertIn(b"Service endpoints", dashboard.data)
        for target, label in (
            (b"#issuing-service", b"Copy issuing service URL"),
            (b"#acme-directory", b"Copy ACME directory URL"),
        ):
            self.assertIn(b'data-copy-target="' + target + b'"', dashboard.data)
            self.assertIn(b'aria-label="' + label + b'"', dashboard.data)
        self.assertGreaterEqual(dashboard.data.count(b'class="copy-icon"'), 2)

        settings = self.client.get("/settings")
        self.assertNotIn(b'data-copy-target="#issuing-service"', settings.data)
        self.assertNotIn(b'data-copy-target="#acme-directory"', settings.data)

    def test_private_certificate_edit_and_reissue_form_is_prepopulated(self):
        certificate_id, _ = self.service.issue(
            profile_slug="tls-server",
            common_name="service.home.arpa",
            sans="service.home.arpa,old.home.arpa",
            key_type="ec-p256",
            validity_days=90,
            export_format="pem",
        )
        detail = self.client.get("/certificates/" + certificate_id)
        self.assertIn(b"Edit and reissue certificate", detail.data)

        form = self.client.get(
            "/certificates/" + certificate_id + "/reissue"
        )
        self.assertEqual(form.status_code, 200)
        self.assertIn(b"Edit and reissue certificate", form.data)
        self.assertIn(b'value="service.home.arpa"', form.data)
        self.assertIn(b"service.home.arpa\nold.home.arpa</textarea>", form.data)
        self.assertIn(b'data-initial-key="ec-p256"', form.data)
        self.assertIn(b'value="90"', form.data)

        issued = self.client.post(
            "/certificates/" + certificate_id + "/reissue",
            data={
                "csrf_token": self.csrf(),
                "profile": "tls-server",
                "common_name": "service.home.arpa",
                "sans": "service.home.arpa,new.home.arpa",
                "key_type": "rsa-2048",
                "validity_days": "180",
                "export_format": "pem",
            },
            follow_redirects=True,
        )
        self.assertEqual(issued.status_code, 200)
        self.assertIn(b"Certificate package is ready", issued.data)
        self.assertEqual(
            self.service.certificate(certificate_id)["status"], "superseded"
        )
        replacement = next(
            item for item in self.service.certificates()
            if item.get("renewed_from") == certificate_id
        )
        self.assertEqual(
            replacement["sans"], ["service.home.arpa", "new.home.arpa"]
        )

    def test_primary_navigation_targets_distinct_pages_and_marks_current_tab(self):
        expected = {
            "/": b"Overview",
            "/certificates": b"Certificates",
            "/audit": b"Audit",
            "/settings": b"Settings",
        }
        for path, label in expected.items():
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'aria-current="page">' + label + b"</a>", response.data)

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

    def test_both_lan_service_ports_are_configurable_with_existing_defaults(self):
        settings = self.client.get("/settings")
        self.assertIn(b'name="ca_port"', settings.data)
        self.assertIn(b'value="9000"', settings.data)
        self.assertIn(b'name="provisioning_port"', settings.data)
        self.assertIn(b'value="9010"', settings.data)

        saved = self.client.post(
            "/settings/service-ports",
            data={
                "csrf_token": self.csrf(), "ca_port": "9443",
                "provisioning_port": "9444",
            },
            follow_redirects=True,
        )
        self.assertIn(b"IoT CA service ports saved", saved.data)
        self.assertIn(b'value="9444"', saved.data)
        dashboard = self.client.get("/")
        self.assertIn(b"https://iot-ca.home.arpa:9443", dashboard.data)

    def test_public_portal_route_prepares_complete_profile_export(self):
        response = self.client.post(
            "/public-certificates/new",
            data={
                "csrf_token": self.csrf(),
                "portal_host": "device",
                "api_hostname": "device.local",
                "sans": "alias.example.com",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Certificate package is ready", response.data)
        self.assertIn(b"device.example.com-public-portal.zip", response.data)

    def test_public_portal_certificate_can_be_revoked(self):
        certificate_id, _token = self.service.issue_public_portal(
            common_name="device.example.com", api_hostname="device.local"
        )
        detail = self.client.get("/certificates/" + certificate_id)
        self.assertIn(b"Revoke public certificate", detail.data)

        revoked = self.client.post(
            "/certificates/" + certificate_id + "/revoke",
            data={"csrf_token": self.csrf()}, follow_redirects=True,
        )
        self.assertEqual(revoked.status_code, 200)
        self.assertIn(b"Public certificate revoked with its ACME issuer", revoked.data)
        self.assertEqual(
            self.service.external_acme.revoked_certificate_id, certificate_id
        )
        self.assertEqual(
            self.service.certificate(certificate_id)["status"], "revoked"
        )

    def test_public_replacement_form_is_populated_from_existing_identity(self):
        certificate_id, _token = self.service.issue_public_portal(
            common_name="device.example.com", api_hostname="private-device.local",
            sans="alias.example.com",
        )
        detail = self.client.get("/certificates/" + certificate_id)
        self.assertIn(
            ("/public-certificates/new?replace=" + certificate_id).encode(),
            detail.data,
        )

        replacement = self.client.get(
            "/public-certificates/new?replace=" + certificate_id
        )
        self.assertEqual(replacement.status_code, 200)
        self.assertIn(b"Edit and reissue a public portal certificate", replacement.data)
        self.assertIn(b'name="portal_host"', replacement.data)
        self.assertIn(b'value="device"', replacement.data)
        self.assertIn(b'value="private-device.local"', replacement.data)
        self.assertIn(b">alias.example.com</textarea>", replacement.data)
        self.assertIn(
            ('name="replaces" value="' + certificate_id + '"').encode(),
            replacement.data,
        )

        issued = self.client.post(
            "/public-certificates/new",
            data={
                "csrf_token": self.csrf(), "replaces": certificate_id,
                "portal_host": "device", "api_hostname": "private-device.local",
                "sans": "alias.example.com",
            },
            follow_redirects=True,
        )
        self.assertEqual(issued.status_code, 200)
        self.assertIn(b"Certificate package is ready", issued.data)
        original = self.service.certificate(certificate_id)
        self.assertEqual(original["status"], "superseded")
        new_certificate = next(
            item for item in self.service.certificates()
            if item["profile"] == "public-portal" and item["status"] == "active"
        )
        self.assertEqual(new_certificate["renewed_from"], certificate_id)

        original_detail = self.client.get("/certificates/" + certificate_id)
        self.assertIn(b"Replaced by", original_detail.data)
        self.assertIn(new_certificate["id"].encode(), original_detail.data)
        self.assertIn(b"Issued", original_detail.data)
        self.assertIn(b"serial", original_detail.data)

    def test_public_portal_form_has_ingress_safe_inline_validation(self):
        response = self.client.get("/public-certificates/new")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="public-certificate-form"', response.data)
        self.assertIn(b'action="/public-certificates/new"', response.data)
        self.assertIn(b'id="public-certificate-validation"', response.data)
        self.assertIn(b'id="public-portal-host"', response.data)
        self.assertIn(b'name="portal_host"', response.data)
        self.assertIn(b'.example.com</span>', response.data)
        self.assertIn(b'id="public-api-hostname"', response.data)

        script = self.client.get("/static/app.js")
        self.assertIn(b"The example text is not submitted as a value", script.data)
        self.assertIn(b"Preparing certificate", script.data)
        script.close()

    def test_public_portal_route_rejects_more_than_one_host_label(self):
        response = self.client.post(
            "/public-certificates/new",
            data={
                "csrf_token": self.csrf(),
                "portal_host": "device.other",
                "api_hostname": "device.local",
                "sans": "",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"must be one DNS label", response.data)

    def test_public_portal_route_derives_private_hostname_without_javascript(self):
        response = self.client.post(
            "/public-certificates/new",
            data={
                "csrf_token": self.csrf(),
                "portal_host": "device",
                "api_hostname": "",
                "sans": "",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        private_identity = next(
            item for item in self.service.certificates()
            if item["provisioner"] == "iot-md-public-profile"
        )
        self.assertEqual(private_identity["common_name"], "device.local")

    def test_iot_md_enrollment_route_exports_one_time_authorization(self):
        response = self.client.post(
            "/device-enrollments/new",
            data={"csrf_token": self.csrf(), "portal_host": "device"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"IoT CA enrollment authorization is ready", response.data)
        self.assertIn(b"device.iotenroll", response.data)
        download = self.client.get("/download")
        self.assertEqual(
            download.mimetype, "application/vnd.iotmd.enrollment+json"
        )
        package = __import__("json").loads(download.data)
        self.assertEqual(package["protocol"], "iotmd-enrollment-v1")
        self.assertEqual(package["portal_hostname"], "device.example.com")
        self.assertEqual(package["api_hostname"], "device.local")
        self.assertNotIn("private", str(package).lower())


if __name__ == "__main__":
    unittest.main()
