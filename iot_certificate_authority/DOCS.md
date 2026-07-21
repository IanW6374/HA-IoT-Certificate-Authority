# IoT Certificate Authority

## Purpose

This Home Assistant app runs a private X.509 certificate authority for local
IoT devices and services. Smallstep `step-ca` performs CA signing, ACME,
renewal authorization, and passive revocation. The app adds a graphical
administrator workflow, certificate inventory, local issuance profiles,
one-time secret exports, expiry visibility, and an audit log.

It is not a public certificate authority and does not make certificates
trusted by browsers automatically. Clients must explicitly install the root
certificate.

## Installation

1. Add `https://github.com/IanW6374/HA-IoT-Certificate-Authority` as a custom
   repository in the Home Assistant App Store.
2. Install **IoT Certificate Authority**.
3. Keep TCP port 9000 restricted to trusted local networks. Do not forward it
   to the internet.
4. Start the app and open its web UI.

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
offline passphrase, staged as a one-time ZIP download, and removed from the CA
working directory.

Download the root export immediately. Store its archive and passphrase in
separate offline locations. The archive contains:

```text
root_ca.crt
root_ca_key.encrypted.pem
SHA256SUMS
README.txt
```

The download link expires after seven days. If the browser loses its link
before download, use **Open root download** on the dashboard to invalidate the
old token and produce another link to the same encrypted archive.

## Certificate profiles

### HAMD device portal

Produces an RSA-2048 portal identity compatible with HAMD's current
traditional-RSA DER requirement. The HAMD export contains:

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

Install the files through the HAMD first-boot certificate page. The DNS SAN
should match the name operators use to open the HAMD portal. Prefer a stable
local DNS name over a DHCP address.

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
- **HAMD**: fixed DER filenames expected by the HAMD setup workflow.

PEM, DER, and HAMD exports contain an unencrypted private key inside the ZIP.
Download them only through trusted Home Assistant access and move them to the
target device immediately.

Certificate export links expire after 15 minutes and are deleted after the
download response closes. The CA stores the public certificate and metadata,
but never the leaf private key. A lost private key cannot be recovered; reissue
the certificate with a new key.

## Renewal and revocation

Select an active certificate and choose **Reissue with a new key**. The app:

1. creates a new key and certificate with the same profile and identity;
2. creates a fresh one-time export;
3. passively revokes the previous serial; and
4. links both inventory records.

Direct revocation blocks future Smallstep renewal. It does not make an already
issued certificate fail validation immediately. Existing copies remain valid
until expiry unless each relying service applies an external revocation
mechanism. Prefer shorter validity for clients capable of automated renewal.

## ACME

The Settings page displays the ACME directory URL:

```text
https://iot-ca.home.arpa:9000/acme/acme/directory
```

Before using it, the ACME client must:

1. resolve the configured CA DNS name;
2. trust the downloaded root certificate; and
3. reach TCP port 9000 on the Home Assistant host.

ACME issuance is performed by `step-ca` and is not added to the graphical
inventory in this first release. Inventory and audit cover certificates issued
through the graphical app.

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
