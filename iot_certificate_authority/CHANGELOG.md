# Changelog

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
