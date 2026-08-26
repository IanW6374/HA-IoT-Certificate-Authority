# Changelog

## 0.3.2

- Add optional Let’s Encrypt issuance through Cloudflare DNS-01 with scoped,
  file-referenced API tokens.
- Add an IoT MD public-portal profile that exports separate public portal and
  private Device API/fleet identities for initial provisioning.
- Keep public ACME secrets out of commands, exports, inventory, and audit data.
- Pin and checksum lego 5.0.4 for amd64, aarch64, and armv7 images.

## 0.3.1

- Render the IoT MD provisioning export with the correct display name.
- Use `iot-md` rather than an internal identifier in downloaded package names.

## 0.3.0

- Establish the clean IoT Certificate Authority application identity.
- Provide the IoT MD device portal, generic TLS server, generic TLS client and MQTT client profiles.
- Provide PEM, DER, PKCS#12 and IoT MD provisioning exports.
- Manage certificate inventory, renewal, revocation and ACME-issued identities.
- Protect one-time private-key exports and offline root recovery material.
- Provide root and intermediate trust downloads through authenticated Home Assistant ingress.
- Use the shared IoT Home Assistant visual system and responsive dark-mode interface.
