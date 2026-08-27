FROM smallstep/step-ca:0.30.2 AS smallstep

FROM alpine:3.22 AS lego

ARG BUILD_ARCH="unknown"
ARG LEGO_VERSION="5.0.4"

RUN apk add --no-cache curl tar \
    && case "${BUILD_ARCH}" in \
        amd64) LEGO_ARCH="amd64"; LEGO_SHA256="b9ee4e690dd4d516c52c4dc71988caba474fc804a28daaf0760fbda3030ff95d" ;; \
        aarch64) LEGO_ARCH="arm64"; LEGO_SHA256="fe831bb1147cdaa2e0527dba0fb7c9bb3e9bcdb187619bee165e4cb6f260ca5f" ;; \
        armv7) LEGO_ARCH="armv7"; LEGO_SHA256="b95234031941ed9968cacbf5beea18c170a10229fb6cdf584afebfe1b24e2907" ;; \
        *) echo "Unsupported BUILD_ARCH: ${BUILD_ARCH}" >&2; exit 1 ;; \
    esac \
    && LEGO_ARCHIVE="lego_v${LEGO_VERSION}_linux_${LEGO_ARCH}.tar.gz" \
    && curl --fail --location --retry 3 \
        "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/${LEGO_ARCHIVE}" \
        --output "/tmp/${LEGO_ARCHIVE}" \
    && echo "${LEGO_SHA256}  /tmp/${LEGO_ARCHIVE}" | sha256sum -c - \
    && tar -xzf "/tmp/${LEGO_ARCHIVE}" -C /usr/local/bin lego \
    && chmod 0755 /usr/local/bin/lego

FROM ghcr.io/home-assistant/base:latest

ARG BUILD_ARCH="unknown"
ARG BUILD_VERSION="dev"

LABEL \
    io.hass.type="app" \
    io.hass.name="IoT Certificate Authority" \
    io.hass.description="Graphical private CA and certificate lifecycle manager for IoT devices" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.version="${BUILD_VERSION}" \
    org.opencontainers.image.source="https://github.com/IanW6374/HA-IoT-Certificate-Authority" \
    org.opencontainers.image.licenses="MIT"

COPY --from=smallstep /usr/local/bin/step /usr/local/bin/step
COPY --from=smallstep /usr/local/bin/step-ca /usr/local/bin/step-ca
COPY --from=lego /usr/local/bin/lego /usr/local/bin/lego

RUN lego run --help | grep -q -- "--cert.name" \
    && lego certificates revoke --help | grep -q -- "--cert.name"

RUN apk add --no-cache \
        nginx \
        py3-cryptography \
        py3-flask \
        py3-gunicorn

COPY rootfs /

RUN chmod 0755 /run.sh \
    && mkdir -p /run/nginx

CMD ["/run.sh"]
