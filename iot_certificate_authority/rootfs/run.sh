#!/usr/bin/with-contenv bashio

set -euo pipefail

readonly DATA_ROOT="/config/iot-ca"
readonly CA_CONFIG="${DATA_ROOT}/step/config/ca.json"
readonly PASSWORD_FILE="${DATA_ROOT}/secrets/intermediate-password"
readonly SETTINGS_FILE="${DATA_ROOT}/settings.json"

export IOT_CA_DATA_ROOT="${DATA_ROOT}"
export PYTHONPATH="/opt/iot-ca"
export NO_COLOR="1"

start_step_ca() {
    while [[ ! -s "${CA_CONFIG}" || ! -s "${PASSWORD_FILE}" || ! -s "${SETTINGS_FILE}" ]]; do
        sleep 2
    done
    export STEPPATH="${DATA_ROOT}/step"
    python3 -c 'from iot_ca.engine import StepCAEngine; StepCAEngine("/config/iot-ca").apply_provisioner_policy()'
    exec step-ca "${CA_CONFIG}" --password-file "${PASSWORD_FILE}"
}

shutdown() {
    trap - TERM INT EXIT
    kill "${STEP_CA_PID}" "${UI_PID}" "${NGINX_PID}" 2>/dev/null || true
    wait "${STEP_CA_PID}" "${UI_PID}" "${NGINX_PID}" 2>/dev/null || true
}

mkdir -p "${DATA_ROOT}" /run/nginx

start_step_ca &
STEP_CA_PID=$!

gunicorn \
    --bind 127.0.0.1:8080 \
    --workers 1 \
    --threads 4 \
    --timeout 90 \
    --access-logfile - \
    --error-logfile - \
    'iot_ca.web:create_app()' &
UI_PID=$!

nginx -g "daemon off; error_log /dev/stdout notice;" &
NGINX_PID=$!

trap shutdown TERM INT EXIT

set +e
wait -n "${STEP_CA_PID}" "${UI_PID}" "${NGINX_PID}"
EXIT_STATUS=$?
set -e
if [[ "${EXIT_STATUS}" -eq 0 ]]; then
    EXIT_STATUS=1
fi
bashio::log.error "A required IoT CA process exited with status ${EXIT_STATUS}"
exit "${EXIT_STATUS}"
