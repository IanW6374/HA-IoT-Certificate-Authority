# IoT Certificate Authority

Run a private, graphical IoT certificate authority on Home Assistant using the
Smallstep `step-ca` signing engine.

The app is designed for local infrastructure and device fleets. IoT MD devices
have a dedicated export profile, while generic TLS and MQTT profiles cover
other services and clients.

The management interface is available only through administrator-restricted
Home Assistant Ingress. Port 9000 exposes the `step-ca` HTTPS and ACME service
to explicitly configured LAN clients. Port 9010 exposes the pinned HTTPS IoT MD
provisioning API for short-lived, host-bound enrollments.

Read the full [documentation](DOCS.md) and [security model](SECURITY.md) before
initializing a production authority.
