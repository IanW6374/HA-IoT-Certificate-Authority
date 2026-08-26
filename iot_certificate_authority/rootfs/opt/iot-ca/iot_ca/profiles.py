"""Certificate profiles and identity validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
COMMON_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,63}$")


@dataclass(frozen=True)
class CertificateProfile:
    slug: str
    name: str
    description: str
    default_days: int
    maximum_days: int
    key_types: tuple[str, ...]
    default_key_type: str
    require_san: bool
    server_auth: bool
    client_auth: bool
    export_formats: tuple[str, ...]


PROFILES = {
    "public-portal": CertificateProfile(
        slug="public-portal",
        name="IoT MD public portal",
        description="Publicly trusted portal identity issued by external ACME with Cloudflare DNS-01.",
        default_days=90,
        maximum_days=90,
        key_types=("ec-p256", "rsa-2048"),
        default_key_type="ec-p256",
        require_san=True,
        server_auth=True,
        client_auth=False,
        export_formats=("iot_md",),
    ),
    "iot_md": CertificateProfile(
        slug="iot_md",
        name="IoT MD device portal",
        description="RSA certificate and DER provisioning files for an IoT MD HTTPS portal.",
        default_days=365,
        maximum_days=825,
        key_types=("rsa-2048",),
        default_key_type="rsa-2048",
        require_san=True,
        server_auth=True,
        client_auth=False,
        export_formats=("iot_md", "pem", "der", "pkcs12"),
    ),
    "tls-server": CertificateProfile(
        slug="tls-server",
        name="Generic TLS server",
        description="Server certificate for a local HTTPS or TLS service.",
        default_days=90,
        maximum_days=825,
        key_types=("ec-p256", "rsa-2048", "rsa-3072"),
        default_key_type="ec-p256",
        require_san=True,
        server_auth=True,
        client_auth=False,
        export_formats=("pem", "der", "pkcs12"),
    ),
    "tls-client": CertificateProfile(
        slug="tls-client",
        name="Generic TLS client",
        description="Client identity certificate for mutual TLS.",
        default_days=90,
        maximum_days=825,
        key_types=("ec-p256", "rsa-2048", "rsa-3072"),
        default_key_type="ec-p256",
        require_san=False,
        server_auth=False,
        client_auth=True,
        export_formats=("pem", "der", "pkcs12"),
    ),
    "mqtt-client": CertificateProfile(
        slug="mqtt-client",
        name="MQTT client",
        description="Client identity certificate for an mTLS-enabled MQTT broker.",
        default_days=180,
        maximum_days=825,
        key_types=("ec-p256", "rsa-2048"),
        default_key_type="ec-p256",
        require_san=False,
        server_auth=False,
        client_auth=True,
        export_formats=("pem", "der", "pkcs12"),
    ),
}


class IdentityError(ValueError):
    """Raised when a requested certificate identity violates local policy."""


def get_profile(slug: str) -> CertificateProfile:
    try:
        return PROFILES[slug]
    except KeyError as exc:
        raise IdentityError("Unknown certificate profile") from exc


def validate_common_name(value: str) -> str:
    value = str(value or "").strip()
    if not COMMON_NAME.fullmatch(value):
        raise IdentityError(
            "Common name must be 1-64 characters using letters, numbers, dot, dash, underscore, colon or @"
        )
    return value


def _validate_dns(value: str, allowed_suffix: str, allow_public: bool) -> str:
    value = value.lower().rstrip(".")
    if len(value) > 253 or "." not in value:
        raise IdentityError(f"Invalid DNS SAN: {value}")
    if any(not DNS_LABEL.fullmatch(label) for label in value.split(".")):
        raise IdentityError(f"Invalid DNS SAN: {value}")
    suffix = str(allowed_suffix or "").lower().strip().strip(".")
    if not allow_public and suffix and value != suffix and not value.endswith("." + suffix):
        raise IdentityError(f"DNS SAN must be within {suffix}: {value}")
    return value


def _validate_ip(value: str, allow_public: bool) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise IdentityError(f"Invalid IP SAN: {value}") from exc
    if not allow_public and not (
        address.is_private or address.is_loopback or address.is_link_local
    ):
        raise IdentityError(f"Public IP SANs are disabled: {value}")
    return str(address)


def normalize_sans(
    values: str | list[str] | tuple[str, ...],
    *,
    allowed_suffix: str,
    allow_public: bool = False,
) -> list[str]:
    if isinstance(values, str):
        raw_values = re.split(r"[,\n\r]+", values)
    else:
        raw_values = list(values)
    result: list[str] = []
    for raw in raw_values:
        value = str(raw).strip()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            normalized = _validate_dns(value, allowed_suffix, allow_public)
        else:
            normalized = _validate_ip(value, allow_public)
        if normalized not in result:
            result.append(normalized)
    if len(result) > 16:
        raise IdentityError("At most 16 Subject Alternative Names are allowed")
    return result


def validate_request(
    *,
    profile_slug: str,
    common_name: str,
    sans: str | list[str],
    key_type: str,
    validity_days: int,
    export_format: str,
    allowed_suffix: str,
    allow_public: bool = False,
) -> dict:
    profile = get_profile(profile_slug)
    common_name = validate_common_name(common_name)
    normalized_sans = normalize_sans(
        sans, allowed_suffix=allowed_suffix, allow_public=allow_public
    )
    if profile.require_san and not normalized_sans:
        raise IdentityError(f"{profile.name} certificates require at least one DNS or IP SAN")
    if key_type not in profile.key_types:
        raise IdentityError(f"Key type {key_type} is not allowed for {profile.name}")
    try:
        validity_days = int(validity_days)
    except (TypeError, ValueError) as exc:
        raise IdentityError("Validity must be a whole number of days") from exc
    if validity_days < 1 or validity_days > profile.maximum_days:
        raise IdentityError(
            f"Validity must be between 1 and {profile.maximum_days} days for {profile.name}"
        )
    if export_format not in profile.export_formats:
        raise IdentityError(f"Export format {export_format} is not allowed for {profile.name}")
    return {
        "profile": profile,
        "common_name": common_name,
        "sans": normalized_sans,
        "key_type": key_type,
        "validity_days": validity_days,
        "export_format": export_format,
    }
