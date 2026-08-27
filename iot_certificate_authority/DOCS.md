# IoT Certificate Authority

## Purpose

This Home Assistant app runs a private X.509 certificate authority for local
IoT devices and services. Smallstep `step-ca` performs CA signing, ACME,
renewal authorization, and passive revocation. The app adds a graphical
administrator workflow, certificate inventory, local issuance profiles,
one-time secret exports, expiry visibility, and an audit log.

The built-in authority is private, so clients must explicitly install its root
certificate. Version 0.4 adds an optional external ACME path for browser-trusted
IoT MD portal certificates. That path uses Let’s Encrypt and Cloudflare DNS-01;
it does not turn the private CA into a public authority.

## CA certificate downloads

The **Settings** page provides the root and intermediate CA certificates in
PEM and DER formats. The root is the trust anchor that clients normally
install. TLS servers should present the online intermediate with their leaf
certificate.

For software that expects the issuing CA and trust anchor in a single file,
download **CA chain PEM**. It contains the intermediate first and the root
second. These public certificate downloads never contain private key material.
PEM downloads are Base64 text with certificate boundary markers; DER downloads
are the binary X.509 representation.

## Installation

Version 0.3.0 establishes the clean IoT Certificate Authority application
identity and IoT MD profile identifiers. Remove an earlier installation and
install 0.3.0 fresh instead of carrying its application data forward. A fresh
authority creates a new trust root, so replace certificates and trust anchors
on connected services and devices after initialization.

1. Add `https://github.com/IanW6374/HA-IoT-Certificate-Authority` as a custom
   repository in the Home Assistant App Store.
2. Install **IoT Certificate Authority**.
3. Keep TCP port 9000 restricted to trusted local networks. Do not forward it
   to the internet.
4. Keep TCP port 9010 restricted to trusted local networks. IoT MD devices use
   it only for host-bound certificate provisioning.
5. Start the app and open its web UI.

Ports 9000 and 9010 are the defaults. If Home Assistant maps either internal
listener to a different host port, set that mapping in the add-on **Network**
configuration and record the same externally reachable values under
**Settings → LAN service endpoints**. IoT CA then publishes the matching ACME
URL and provisioning endpoint to devices. The two external ports must differ.

The graphical interface is accepted only from Home Assistant Supervisor
Ingress and is restricted to Home Assistant administrators. The Smallstep CA
service is exposed separately on TCP port 9000 for ACME and explicitly
configured enrollment clients.

## Initialize the authority

Choose the CA identity carefully; changing it requires a migration rather than
renaming a setting.

- **CA name** is the human-readable authority name.
- **CA DNS name** must resolve from every ACME client, for example
  `iot-ca.home.arpa`.
- **Allowed DNS suffix** limits manually issued DNS SANs, for example
  `home.arpa`.
- **Offline-root passphrase** encrypts the exported root key and is never
  stored by this app.
- Leave public SANs disabled unless the private CA intentionally manages public
  names or addresses.

Initialization creates a root and online intermediate with `step-ca`. Before
the online service starts, the root key is re-encrypted with the supplied
offline passphrase, staged as a protected ZIP download, and removed from the CA
working directory. The export is deleted after you explicitly confirm that it
was downloaded and stored safely.

Download the root export immediately. Store its archive and passphrase in
separate offline locations. The archive contains:

```text
root_ca.crt
root_ca_key.encrypted.pem
SHA256SUMS
README.txt
```

The download link expires after seven days. If the browser loses its link
before confirmation, use **Review root export** on the dashboard to invalidate
the old token and produce another link to the same encrypted archive.

## Certificate profiles

### IoT MD device portal

Produces an RSA-2048 portal identity compatible with the IoT MD
traditional-RSA DER requirement. The IoT MD export contains:

```text
web.crt.der
web.key.der
mqtt-ca.der
update-ca.der
intermediate-ca.der
certificate-info.json
```

`web.crt.der` and `web.key.der` are the unique device portal identity. The CA
files establish trust in services using this authority. If MQTT and the update
server use different authorities, replace their CA files with those services'
actual trust roots before provisioning the device.

Install the files through the IoT MD first-boot certificate page. The DNS SAN
should match the name operators use to open the IoT MD portal. Prefer a stable
local DNS name over a DHCP address.

### IoT MD public portal

Enable **Settings → Public portal certificates** only after creating a
Cloudflare API token scoped to the authoritative zone. A single token may have
`Zone / Zone / Read` and `Zone / DNS / Edit`, or those permissions may be split
between separate Zone and DNS tokens. The app stores tokens in mode-0600 files,
passes them to the ACME client by file reference, and never includes them in
commands, exports, inventory, or audit details.

The allowed public portal DNS suffix may be a delegated namespace beneath that
zone. For example, use `iot.example.com` for portal names while scoping the API
token to the authoritative `example.com` Cloudflare zone. Scoped API tokens do
not require a Cloudflare Client ID or account email. A `cfat_` credential is an
account-owned API token. Its verification URL contains a Cloudflare Account ID,
not a Client ID; lego does not need that identifier for its DNS operations. The
built-in ACME client registers and manages the Let’s Encrypt account using the
email entered in Settings; no separate Home Assistant Let’s Encrypt integration
is involved.

Test with the Let’s Encrypt staging environment first. Staging certificates are
not browser trusted. After successful staging issuance, change the environment
to production and issue the final package. Public certificate names are normally
recorded in Certificate Transparency logs; do not use sensitive hostnames.

The IoT MD public-portal profile asks for the public portal name inside the
configured Cloudflare zone and the private single-label `.local` name used by
Device API/fleet clients. Its one-time ZIP contains:

```text
web.crt.pem
web.key.der
api-server.crt.der
api-server.key.der
api-server.crt.pem
mqtt-ca.der
update-ca.der
intermediate-ca.der
certificate-info.json
```

`web.crt.pem` contains the public leaf and intermediate chain required by
browsers. The `web.*` pair is publicly issued. The `api-server.*` pair and trust anchors
are issued by the private IoT CA. Unzip the package on an administrator
workstation and select the named DER files in the IoT MD initial setup wizard.
The Cloudflare token never goes to the IoT MD device.

The manual ZIP remains available, but version 0.4 also provides automated,
device-key-preserving provisioning. Choose **Authorize IoT MD** on the
dashboard, enter the public portal host label and download the one-time
`.iotenroll` file. The file contains the exact public portal and private
`<host>.local` identities, the private CA root, endpoint and a random bearer
authorization. It contains no private key or Cloudflare credential and expires
after 30 minutes.

For a one-step first boot, open **Automatic IoT MD enrollment** in the
**Certificate actions** panel on Overview. The button displays a live countdown
and can close the window immediately. Its duration is configured under
**Settings** from 1 to 60 minutes and defaults to 5 minutes.
The IoT MD wizard requests the same hostname-bound authorization directly over
the private-LAN provisioning listener. This bootstrap route is disabled by
default, accepts only private-LAN clients, is rate-limited and audited, and
closes automatically. The `.iotenroll` export remains the higher-assurance
alternative when the setup LAN is not trusted.

In the IoT MD first-boot wizard, the administrator may explicitly choose this
public workflow, local private-CA ACME, a manual certificate package, or the
device-generated self-signed fallback. For the public workflow, the device
generates independent P-256 portal, Device API and renewal keys locally and
sends only signed CSRs over pinned HTTPS to TCP 9010. The CA requires exact
authorized names and key usages. It performs Cloudflare DNS-01 for the portal
CSR, signs the other CSRs privately, and returns certificates and public trust
only. The private Device API server response includes its leaf and online
intermediate so root-trusting clients can build the complete chain. The
authorization cannot be reused with different requests.

Neither automated nor manual provisioning calls Cloudflare from the device or
places DNS credentials on it. This prevents an unprovisioned field device from
obtaining general DNS-edit authority.

### Generic TLS server

Creates an EC P-256 or RSA server identity. At least one DNS or IP SAN is
required. Use this for local HTTPS, MQTT broker, or other TLS servers.

### Generic TLS client and MQTT client

Creates a client identity for mutual TLS. If no SAN is entered, the common
name is also issued as the SAN required by the Smallstep authorization token.

## Export formats

- **PEM**: unencrypted PKCS#8 private key, leaf certificate, intermediate, and
  root in a ZIP archive.
- **DER**: binary certificate and private key plus intermediate and root.
- **PKCS#12**: password-encrypted identity and chain. A 12-character minimum
  password is required and not stored.
- **IoT MD**: fixed DER filenames expected by the IoT MD setup workflow.

PEM, DER, and IoT MD exports contain an unencrypted private key inside the ZIP.
Download them only through trusted Home Assistant access and move them to the
target device immediately.

Certificate export links expire after 15 minutes. The protected export is
deleted after the operator confirms it has been downloaded and stored safely.
The CA stores the public certificate and metadata, but never the leaf private
key. A lost private key cannot be recovered; reissue the certificate with a new
key.

After the original protected export has been cleared, open any certificate in
the inventory to download its stored public certificate in PEM or DER format.
These later downloads do not include a private key. Reissue the certificate if
the private key is unavailable and a new identity package is required.

## Renewal and revocation

The certificate inventory shows active records by default. Use the **Status**
filter to view revoked, superseded, or all certificates.

Select an active certificate and choose **Reissue with a new key**. The app:

1. creates a new key and certificate with the same profile and identity;
2. creates a fresh one-time export;
3. passively revokes the previous serial; and
4. links both inventory records.

Direct revocation blocks future Smallstep renewal. It does not make an already
issued certificate fail validation immediately. Existing copies remain valid
until expiry unless each relying service applies an external revocation
mechanism. Prefer shorter validity for clients capable of automated renewal.

Public portal certificates issued by current releases can also be revoked from
their certificate detail page. IoT CA retains the Let’s Encrypt ACME account
identity and public certificate needed for that request, but still deletes the
portal private key after creating its one-time export. Public certificates
issued by 0.4.1 or earlier predate that retained account state and cannot be
reliably revoked by the app; issue a replacement first.

## ACME

The Settings page displays the ACME directory URL:

```text
https://iot-ca.home.arpa:9000/acme/acme/directory
```

Use the copy icon beside the URL on the Overview or Settings page to copy the
complete directory URL without selecting it manually.

Before using it, the ACME client must:

1. resolve the configured CA DNS name;
2. trust the downloaded root certificate; and
3. reach TCP port 9000 on the Home Assistant host.

ACME issuance is performed by `step-ca`. Successful certificate downloads are
captured from its structured audit log and added to the graphical inventory.
Renewed certificates are linked to the previous serial and the previous record
is marked superseded. Only the public certificate and metadata are stored; the
ACME client's private key never leaves the client.

Certificates issued before version 0.1.4 are added when the ACME client next
renews them. They cannot be reconstructed from historical app logs that are no
longer present in the add-on container.

The private Smallstep ACME directory above is independent from external public
ACME. Private ACME remains suitable for local identities. External public ACME
uses DNS-01 only and is limited to the Cloudflare zone configured in Settings.

## Backups and recovery

The app uses `addon_config` storage and requests a cold backup so the CA
database and encrypted intermediate are captured consistently. Home Assistant
also stores the local password needed to unlock that intermediate. Therefore:

- encrypt every backup containing this app;
- keep at least one tested backup offline;
- restrict access to backup storage; and
- test restoration before enrolling production devices.

The offline root alone does not restore the graphical inventory. Restore a Home
Assistant backup for normal disaster recovery. Creating a replacement
intermediate from the offline root is currently a manual Smallstep operation;
an assisted intermediate-rotation workflow is planned for a later release.

## Uninstallation

Do not uninstall or delete app data until all devices have migrated to a new
authority. Removing the app does not remove its root from clients, and issued
certificates remain cryptographically valid until expiry.
