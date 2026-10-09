# Changelog

## 0.6.0

- Issue one device HTTPS certificate/key for both IoT-MD portal and API. Remove
  the extra private API server identity from manual packages and forms.
- Enrollment/renewal protocol v2 accepts only HTTPS and renewal-client CSRs.
  The renewal credential remains private-CA issued and separate from the server
  identity; device private keys never leave the device during enrollment.
- Coordinate with IoT-MD Alpha 110 and Management 3.1.0. Existing protocol-v1
  devices must re-enroll; no compatibility or migration path is provided.
- API client trust and permission scopes remain independent of server issuance.

## 0.5.7

- Standardise checkbox-first controls, required markers, aligned form fields,
  helper typography and keyboard focus styling with the IoT portfolio.
- Give dynamic notifications accessible status/alert roles while preserving
  existing certificate security requirements and scalar selection controls.

## 0.5.6

- Use compact required-only icons, including mandatory acknowledgements.
- Apply public ACME field and agreement requirements only while enabled.

## 0.5.5

- Mark portal form fields consistently as required or optional, updating labels
  when conditional requirements change (for example a PKCS#12 password).

## 0.5.4

- Align form labels and use the shared 42 px single-line control height. Keep
  checkboxes compact and unboxed; preserve text areas and multi-select lists.

## 0.5.3

- Match Home Assistant's compact 14 px Roboto type scale, 32 px maximum page
  heading, 1,200 px content width, tighter controls and lower-radius panels.

## 0.5.2

- Align the portal type scale, heading sizes, panel density and page spacing
  more closely with the Home Assistant add-on experience.

## 0.5.1

- Preserve expanded disclosure panels when an asynchronous action refreshes
  its surrounding portal section.

## 0.5.0

- Adopt the shared IoT portal shell, content width, typography, spacing and card hierarchy.
- Turn overview counts into linked navigation cards for faster inventory and settings access.
- Standardise the IoT CA brand mark and responsive overview presentation with IoT-MD Management.

## 0.4.14

- Align routine portal actions with IoT-MD's in-place interaction model: save
  settings, toggle automatic enrollment and revoke certificates without a full
  page redirect while retaining server-rendered fallbacks.
- Add consistent inline busy, success and error feedback, sticky Save/Discard
  controls and unsaved-change protection for editable settings.
- Keep page transitions for issuance and one-time private-key exports where the
  security workflow genuinely moves to a new stage.

## 0.4.13

- Align the CA trust download controls into consistent format columns.
- Add per-device full-chain downloads containing the leaf, issuing intermediate
  and root certificates in concatenated PEM, PKCS#7 PEM and PKCS#7 DER formats.

## 0.4.12

- Consolidate root/full-chain trust downloads and copyable service endpoints
  within Certificate actions, with PEM, DER and PKCS#7 DER choices as
  appropriate, and remove duplicate controls from Settings.
- Add editable private and public certificate reissue workflows pre-populated
  with the existing identity and Subject Alternative Names.

## 0.4.11

- Place certificate totals above the action panel and label the temporary
  automatic enrollment control **Enable for 5 minutes**.
- Keep the issuing-service and ACME-directory URLs on Settings, with accessible
  copy controls for both, and mark the active Overview, Certificates, Audit or
  Settings tab explicitly.
- Standardise the one-time method name as **IoT CA enrollment authorization
  (`.iotenroll`)** across IoT CA and IoT-MD.

## 0.4.10

- Group the issuing-service and ACME-directory URLs together in the Overview
  Automation panel and provide the same accessible copy-to-clipboard control
  for both endpoints.

## 0.4.9

- Quarantine incomplete lego account directories and orphaned account keys
  left by an earlier failed recovery before registering the replacement ACME
  account.
- Recover correctly when 0.4.7 or 0.4.8 has already retired the original
  account record, without requiring an add-on reinstall or configuration reset.

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
