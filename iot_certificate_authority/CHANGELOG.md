# Changelog

## 0.4.8

- Explicitly register a replacement Let’s Encrypt account after quarantining a
  retained account that the ACME service no longer recognises, then retry the
  interrupted certificate request once.
- Preserve the sanitized lego account-registration failure in the portal and
  add-on log instead of replacing it with a generic recovery message.

## 0.4.7

- Recover automatically when Let’s Encrypt reports that a retained local ACME
  account no longer exists: quarantine only that stale account, register a new
  account using the configured identity and retry the pending CSR once.
- Keep DNS, Cloudflare and other ACME failures separate from account recovery,
  and replace the raw `accountDoesNotExist` response with an actionable error if
  the guarded retry also fails.

## 0.4.6

- Bind each public certificate to the retained ACME account identity that
  issued it instead of reconstructing that identity from mutable settings.
- Discover legacy registered accounts and try the matching production or
  staging accounts when revoking certificates issued before account binding.
- Ignore unregistered account files left by earlier failed revocation attempts
  so they cannot prevent a valid retained account from being selected.

## 0.4.5

- Standardise the setup method names shared with IoT MD as **Automatic IoT CA
  enrollment** and **IoT CA enrollment file (`.iotenroll`)**.
- Add authenticated renewal of the complete IoT MD public portal, private
  Device API and renewal identity set without exporting device private keys.
- Link public certificate replacements to the certificate they replace and
  atomically mark the previous public and private identities as superseded.
- Reconcile replacement history created by earlier releases so a revoked
  replacement cannot leave the previous same-name certificate shown as active.
- Distinguish repeated identities throughout inventory with issue dates and
  serial suffixes, and show both directions of the replacement relationship.

## 0.4.4

- Use the pinned lego 5 command and flag contract for public certificate
  issuance, CSR enrollment and revocation.
- Verify the required `run --cert.name` and `certificates revoke --cert.name`
  interfaces while building every add-on image.

## 0.4.3

- Use the same primary action treatment for all available certificate and
  enrollment operations on the Overview page.
- Pre-populate public certificate replacements with the existing portal host,
  private API hostname and additional DNS names.

## 0.4.2

- Group certificate issuance and enrollment controls in a dedicated
  **Certificate actions** panel on Overview.
- Move automatic IoT MD enrollment out of Settings, add a live countdown and
  close control, and make its duration configurable from 1 to 60 minutes with
  a 5-minute default.
- Retain the external ACME account identity and public certificate required to
  revoke newly issued public portal certificates while continuing to delete
  every portal private key after its one-time export.
- Allow the externally reachable CA/ACME and provisioning ports to be recorded
  independently, keeping 9000 and 9010 as their defaults.

## 0.4.1

- Add an opt-in, 15-minute automatic IoT MD enrollment window. Private-LAN
  devices can request a hostname-bound, one-time authorization directly from
  the provisioning API; requests are rate-limited and audited.
- Allow the provisioning TLS identity and enrollment packages to use a
  device-resolvable server name such as `homeassistant.local`.

## 0.4.0

- Add short-lived, host-bound `.iotenroll` authorizations for automated IoT MD
  first-boot provisioning without exporting device private keys.
- Accept separate portal, private Device API and renewal CSRs over a dedicated
  private-CA-pinned HTTPS provisioning endpoint on TCP 9010.
- Complete Cloudflare/Let’s Encrypt DNS-01 issuance from the portal CSR while
  signing API and renewal identities with the private IoT CA.
- Enforce one-time token, expiry, P-256 key, exact CN/SAN and server/client EKU
  constraints before issuance, with success and failure audit records.
- Return certificate and trust material only; Cloudflare credentials remain in
  the CA and every device private key remains on the device.

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
