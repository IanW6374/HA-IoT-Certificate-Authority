# Security policy

## Security boundary

This project hosts an online intermediate certificate authority. Compromise of
Home Assistant, this app, its app configuration directory, or a backup may
allow an attacker to issue identities trusted by enrolled devices.

The design reduces—but cannot eliminate—that risk:

- the root key is removed from the online CA after a one-time encrypted export;
- the administrator UI accepts traffic only from Home Assistant Ingress;
- the app requests no Supervisor API role, host networking, privileged mode,
  Docker access, or Home Assistant configuration access;
- manually requested identities pass profile, SAN, key, and lifetime policy;
- leaf private keys are stored only in short-lived one-time export files;
- export bearer tokens are stored as SHA-256 hashes;
- IoT MD enrollment bearer tokens are short-lived, host-bound, request-bound,
  stored only as hashes, and accepted over private-CA-authenticated HTTPS;
- IoT MD private keys are generated on the device and never enter the CA;
- state-changing browser requests require a session CSRF token;
- operational events are appended to a local audit table; and
- the app runs with Home Assistant's default protection enabled.

The online intermediate password is stored locally because unattended app
startup requires it. Encryption of that key therefore protects copied key
material but does not protect against compromise of the running app or its full
data directory. Hardware-backed signing is outside the first-release scope.

## Deployment requirements

- Do not expose ports 9000 or 9010 to the public internet.
- Use an administrator-only Home Assistant account for CA operations.
- Encrypt Home Assistant backups and keep offline copies.
- Store the offline root archive and its passphrase separately.
- Use local DNS and stable device names rather than bypassing hostname checks.
- Prefer the shortest certificate lifetime that the device renewal workflow
  can safely support.
- Treat PEM, DER, and IoT MD exports as secrets because they contain private keys.

## Revocation limitation

Open-source `step-ca` uses passive revocation by default. Revocation stops
renewal but an existing certificate remains valid until it expires unless a
relying party implements an additional active revocation check.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security advisory reporting for this repository and include affected versions,
impact, and reproduction details without real private keys or certificates.
