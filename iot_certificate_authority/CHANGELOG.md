# Changelog

## 0.2.0

- Download any stored public certificate from its inventory record as PEM or
  binary DER without reissuing it.
- Add copy-to-clipboard controls for the ACME directory URL.
- Validate certificate encodings strictly and verify that Root CA DER downloads
  contain DER rather than PEM data.

## 0.1.4

- Import certificates downloaded through the Smallstep ACME endpoint into the
  graphical certificate inventory.
- Link ACME renewals to the previous certificate and mark the replaced record
  as superseded.
- Show certificate source and provisioner in inventory and lifecycle views.
- Migrate existing inventory databases without losing certificate records.
- Add individual intermediate downloads and a combined intermediate-plus-root
  PEM chain alongside the root trust anchor.

## 0.1.3

- Start `step-ca` directly on add-on restarts instead of invoking the offline
  provisioner-policy migration through an unavailable admin API.
- Keep certificate lifetime policy configuration in the initial CA creation
  path, before database-backed administration is enabled.

## 0.1.2

- Replace unreliable response-close export cleanup with explicit download confirmation.
- Clarify when the offline-root warning is cleared and when protected files are deleted.

## 0.1.1

- Prevent `step-ca` from starting before initialization and provisioner policy updates complete.
- Reapply certificate lifetime policy on startup so existing authorities accept profile durations.
- Remove ANSI terminal formatting from Smallstep errors shown in the web interface.

## 0.1.0

- Add guided CA initialization and one-time offline-root export.
- Add HAMD, generic TLS server, generic TLS client, and MQTT client profiles.
- Add certificate inventory, expiry tracking, reissue, and passive revocation.
- Add PEM, DER, PKCS#12, HAMD, and root trust-bundle exports.
- Add administrator-only Home Assistant Ingress interface and audit history.
- Provide a LAN-facing Smallstep ACME endpoint.
