"""Host-bound IoT MD certificate enrollment API."""

from __future__ import annotations

import os
import threading
import time
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import Flask, jsonify, request

from .service import CertificateService


def _bearer():
    scheme, separator, value = request.headers.get("Authorization", "").partition(" ")
    return value.strip() if separator and scheme.lower() == "bearer" else ""


def create_app(*, data_root=None, service=None):
    root = Path(data_root or os.environ.get("IOT_CA_DATA_ROOT", "/config/iot-ca"))
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    certificate_service = service or CertificateService(root)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="iotmd-enrollment")
    active = set()
    active_lock = threading.Lock()
    automatic_attempts = {}

    def schedule(enrollment_id):
        with active_lock:
            if enrollment_id in active:
                return
            active.add(enrollment_id)

        def run():
            try:
                certificate_service.fulfill_device_enrollment(enrollment_id)
            finally:
                with active_lock:
                    active.discard(enrollment_id)

        executor.submit(run)

    @app.after_request
    def secure(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/healthz")
    def health():
        return jsonify({"application": "ok"})

    @app.post("/v1/auto-enrollments")
    def auto_enrollment():
        try:
            source = ip_address(request.remote_addr or "")
        except ValueError:
            return jsonify({"error": "Automatic enrollment requires a private LAN client"}), 403
        if not (source.is_private or source.is_loopback):
            return jsonify({"error": "Automatic enrollment requires a private LAN client"}), 403
        now = time.monotonic()
        attempts = [value for value in automatic_attempts.get(str(source), [])
                    if now - value < 600]
        if len(attempts) >= 5:
            return jsonify({"error": "Automatic enrollment rate limit exceeded"}), 429
        attempts.append(now)
        automatic_attempts[str(source)] = attempts
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"api_hostname"}:
            return jsonify({"error": "A Device API hostname is required"}), 400
        try:
            package = certificate_service.create_automatic_device_enrollment(
                payload["api_hostname"]
            )
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(package), 201

    @app.post("/v1/enrollments/<enrollment_id>")
    def submit(enrollment_id):
        token = _bearer()
        if not token:
            return jsonify({"error": "Bearer enrollment token is required"}), 401
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {
            "portal_csr", "api_csr", "renewal_csr"
        }:
            return jsonify({"error": "Three certificate requests are required"}), 400
        try:
            enrollment = certificate_service.claim_device_enrollment(
                enrollment_id, token, payload
            )
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 401
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        if enrollment["status"] == "pending":
            schedule(enrollment_id)
        return jsonify({
            "status": enrollment["status"],
            "poll": "/v1/enrollments/" + enrollment_id,
        }), 202

    @app.get("/v1/enrollments/<enrollment_id>")
    def status(enrollment_id):
        try:
            value = certificate_service.device_enrollment_status(
                enrollment_id, _bearer()
            )
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 401
        code = 422 if value["status"] in {"error", "expired"} else 200
        return jsonify(value), code

    return app
