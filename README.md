# Home Assistant IoT Certificate Authority

A graphical certificate service for Home Assistant OS and Supervised
installations. Smallstep `step-ca` provides the private CA. An optional,
strictly separated external ACME workflow uses Cloudflare DNS-01 to obtain
publicly trusted IoT MD portal certificates without exposing private services.

## First-release capabilities

- Guided private CA initialization with an offline-root export
- Online intermediate CA hosted by Home Assistant
- Device and certificate inventory
- IoT MD device portal, generic TLS server, generic TLS client, and MQTT client profiles
- DNS and IP Subject Alternative Name validation
- PEM, DER, PKCS#12, and IoT MD provisioning exports
- Expiry dashboard, renewal/reissue, and passive revocation
- Root, intermediate, and combined CA-chain downloads
- PEM and DER downloads for public certificates already in inventory
- One-time private-key downloads with automatic expiry
- Append-only operator audit history
- ACME endpoint provided by `step-ca`
- Optional Let’s Encrypt portal issuance through scoped Cloudflare DNS tokens
- Split IoT MD provisioning packages with a public portal identity and a
  separate private-CA Device API/fleet identity
- Host-bound IoT MD enrollment files that let devices generate keys locally
  and receive public portal plus private service certificates automatically

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
