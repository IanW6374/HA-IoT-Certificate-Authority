# Changelog

## 0.3.5

- Keep nginx and Gunicorn alive longer than the external ACME request ceiling
  so the portal receives the real result instead of a 504 response.
- Use public Cloudflare resolvers for DNS-01 discovery and require propagation
  at authoritative name servers without waiting on stale recursive caches.
- Write sanitized lego failures and request timeouts to the add-on log.
- Clarify in-progress messaging for DNS validation that may take several
  minutes.

## 0.3.4

- Show public-certificate form validation errors inline inside Home Assistant
  ingress instead of relying on browser validation popovers.
- Accept only the public portal host label, append the CA-configured DNS suffix
  server-side, and derive the private `.local` hostname until overridden.
- Show visible progress and prevent duplicate certificate requests while DNS
  validation and ACME issuance are running.
- Validate the private hostname before placing an external ACME order.

## 0.3.3

- Make every non-secret CA identity default a submitted value on initial setup.
- Display configured Cloudflare credentials as masked password placeholders.
- Clarify Cloudflare Account ID versus Client ID and document that lego does
  not need either identifier for API-token DNS operations.
- Separate the allowed public portal DNS suffix from the authoritative
  Cloudflare zone in labels and guidance.
- Explain that the built-in ACME client creates the Let’s Encrypt account from
  the configured email without a separate Home Assistant integration.

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
