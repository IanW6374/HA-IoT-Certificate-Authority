FROM smallstep/step-ca:0.30.2 AS smallstep

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

RUN apk add --no-cache \
        nginx \
        py3-cryptography \
        py3-flask \
        py3-gunicorn

COPY rootfs /

RUN chmod 0755 /run.sh \
    && mkdir -p /run/nginx

CMD ["/run.sh"]
