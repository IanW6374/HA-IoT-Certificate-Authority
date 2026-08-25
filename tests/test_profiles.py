import unittest

from iot_ca.profiles import IdentityError, normalize_sans, validate_request


class ProfileTests(unittest.TestCase):
    def test_iot_md_request(self):
        result = validate_request(
            profile_slug="iot_md",
            common_name="iot-md-a1b2c3",
            sans="iot-md-a1b2c3.home.arpa\n192.168.1.20",
            key_type="rsa-2048",
            validity_days=365,
            export_format="iot_md",
            allowed_suffix="home.arpa",
        )
        self.assertEqual(result["sans"], ["iot-md-a1b2c3.home.arpa", "192.168.1.20"])

    def test_public_dns_is_rejected(self):
        with self.assertRaisesRegex(IdentityError, "within home.arpa"):
            normalize_sans("device.example.com", allowed_suffix="home.arpa")

    def test_public_ip_is_rejected(self):
        with self.assertRaisesRegex(IdentityError, "Public IP"):
            normalize_sans("8.8.8.8", allowed_suffix="home.arpa")

    def test_iot_md_requires_rsa(self):
        with self.assertRaisesRegex(IdentityError, "not allowed"):
            validate_request(
                profile_slug="iot_md",
                common_name="iot-md-test",
                sans="iot-md-test.home.arpa",
                key_type="ec-p256",
                validity_days=365,
                export_format="iot_md",
                allowed_suffix="home.arpa",
            )

    def test_profile_validity_limit(self):
        with self.assertRaisesRegex(IdentityError, "between 1 and 825"):
            validate_request(
                profile_slug="tls-server",
                common_name="server",
                sans="server.home.arpa",
                key_type="ec-p256",
                validity_days=826,
                export_format="pem",
                allowed_suffix="home.arpa",
            )


if __name__ == "__main__":
    unittest.main()
