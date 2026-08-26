"""Test doubles for the Smallstep process boundary."""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _ca_certificate(subject, key, issuer_certificate=None, issuer_key=None, path_length=None):
    now = datetime.now(timezone.utc)
    issuer_certificate = issuer_certificate or subject
    issuer_key = issuer_key or key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_certificate.subject if hasattr(issuer_certificate, "subject") else issuer_certificate)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


class FakeEngine:
    def __init__(self):
        self.initialized = True
        root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test IoT Root")])
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _ca_certificate(root_subject, self.root_key, path_length=1)
        intermediate_subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Test IoT Intermediate")]
        )
        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = _ca_certificate(
            intermediate_subject,
            self.intermediate_key,
            issuer_certificate=self.root,
            issuer_key=self.root_key,
            path_length=0,
        )
        self.revoked = []

    def settings(self):
        return {
            "ca_name": "Test IoT CA",
            "ca_dns": "iot-ca.home.arpa",
            "allowed_dns_suffix": "home.arpa",
            "allow_public_sans": False,
            "public_ca_url": "https://iot-ca.home.arpa:9000",
            "acme_directory": "https://iot-ca.home.arpa:9000/acme/acme/directory",
            "initialized_at": "2026-01-01T00:00:00Z",
        }

    def health(self):
        return {"initialized": True, "online": True}

    def sign(self, *, csr_pem, common_name, sans, validity_days):
        csr = x509.load_pem_x509_csr(csr_pem)
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.intermediate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        for extension in csr.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        certificate = builder.sign(self.intermediate_key, hashes.SHA256())
        return certificate.public_bytes(serialization.Encoding.PEM)

    def revoke(self, serial, reason="keyCompromise"):
        self.revoked.append((str(serial), reason))

    def root_certificate(self):
        return self.root.public_bytes(serialization.Encoding.PEM)

    def intermediate_certificate(self):
        return self.intermediate.public_bytes(serialization.Encoding.PEM)


class FakeExternalACME:
    def __init__(self):
        self.config = {
            "enabled": True,
            "provider": "cloudflare",
            "email": "operator@example.com",
            "zone": "example.com",
            "environment": "staging",
            "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "terms_accepted": True,
            "dns_token_configured": True,
            "zone_token_configured": False,
            "auto_enroll_enabled": False,
            "auto_enroll_until": "",
            "provisioning_host": "homeassistant.local",
        }

    def settings(self):
        return dict(self.config)

    def configure(self, **values):
        self.config.update(values)
        self.config["provider"] = "cloudflare"
        self.config["directory_url"] = "https://acme-v02.api.letsencrypt.org/directory"
        self.config["dns_token_configured"] = True
        self.config["zone_token_configured"] = bool(values.get("zone_token"))
        self.config.pop("dns_token", None)
        self.config.pop("zone_token", None)
        return self.settings()

    def issue(self, names):
        from iot_ca.external_acme import PublicCertificate

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        return PublicCertificate(certificate, pem, pem, key)

    def issue_csr(self, csr_pem):
        from iot_ca.external_acme import PublicCertificate

        csr = x509.load_pem_x509_csr(csr_pem)
        names = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        issuer_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Public Issuer")
            ]))
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
                critical=False,
            )
            .sign(issuer_key, hashes.SHA256())
        )
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        return PublicCertificate(certificate, pem, pem, None)
