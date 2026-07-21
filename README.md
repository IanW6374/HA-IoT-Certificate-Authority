# Home Assistant IoT Certificate Authority

A graphical private certificate authority for Home Assistant OS and
Supervised installations. The app uses Smallstep `step-ca` for signing and
certificate lifecycle operations, with an administrator-only Home Assistant
Ingress interface designed for IoT fleets such as HAMD.

## First-release capabilities

- Guided private CA initialization with an offline-root export
- Online intermediate CA hosted by Home Assistant
- Device and certificate inventory
- HAMD, generic TLS server, generic TLS client, and MQTT client profiles
- DNS and IP Subject Alternative Name validation
- PEM, DER, PKCS#12, and HAMD provisioning exports
- Expiry dashboard, renewal/reissue, and passive revocation
- Root trust-bundle downloads
- One-time private-key downloads with automatic expiry
- Append-only operator audit history
- ACME endpoint provided by `step-ca`

The root private key is re-encrypted with an operator-supplied passphrase,
placed into a one-time export, and removed from the online CA. Home Assistant
retains only the encrypted online intermediate and the local secret required to
start it.

See [the app documentation](iot_certificate_authority/DOCS.md) for installation,
security boundaries, provisioning, and recovery procedures.

## Status

This project is experimental. Use it first in a test environment, download the
offline-root export and an encrypted Home Assistant backup, and verify recovery
before trusting production devices.
