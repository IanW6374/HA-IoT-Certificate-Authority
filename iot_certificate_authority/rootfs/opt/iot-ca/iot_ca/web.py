"""Administrator-only Flask interface served behind Home Assistant Ingress."""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from .profiles import PROFILES
from .service import CertificateService


class IngressScriptName:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        ingress_path = environ.get("HTTP_X_INGRESS_PATH", "").rstrip("/")
        if ingress_path:
            environ["SCRIPT_NAME"] = ingress_path
        return self.app(environ, start_response)


def _secret_key(data_root: Path):
    path = data_root / "secrets" / "flask-secret"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(secrets.token_urlsafe(48))
        path.chmod(0o600)
    return path.read_text().strip()


def create_app(*, data_root=None, service=None):
    data_root = Path(data_root or os.environ.get("IOT_CA_DATA_ROOT", "/config/iot-ca"))
    app = Flask(__name__)
    app.secret_key = _secret_key(data_root)
    app.config.update(
        MAX_CONTENT_LENGTH=1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    app.wsgi_app = IngressScriptName(app.wsgi_app)
    certificate_service = service or CertificateService(data_root)
    app.extensions["certificate_service"] = certificate_service

    @app.before_request
    def csrf_protection():
        certificate_service.cleanup_exports()
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(24)
        if request.method == "POST":
            supplied = request.form.get("csrf_token", "")
            if not secrets.compare_digest(supplied, session["csrf_token"]):
                abort(403, "Invalid CSRF token")

    @app.after_request
    def secure_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'self'"
        )
        return response

    @app.context_processor
    def template_values():
        return {
            "csrf_token": session.get("csrf_token", ""),
            "profiles": PROFILES,
            "initialized": certificate_service.initialized,
        }

    @app.get("/healthz")
    def health():
        return jsonify({"application": "ok", "ca": certificate_service.engine.health()})

    @app.route("/", methods=["GET"])
    def dashboard():
        if not certificate_service.initialized:
            return render_template("setup.html")
        return render_template(
            "dashboard.html",
            dashboard=certificate_service.dashboard(),
            settings=certificate_service.settings(),
        )

    @app.post("/setup")
    def setup():
        if certificate_service.initialized:
            abort(409, "Certificate authority is already initialized")
        if request.form.get("root_export_passphrase") != request.form.get("confirm_passphrase"):
            flash("Offline-root export passphrases do not match", "error")
            return redirect(url_for("dashboard"))
        try:
            token = certificate_service.initialize(
                ca_name=request.form.get("ca_name", ""),
                ca_dns=request.form.get("ca_dns", ""),
                allowed_dns_suffix=request.form.get("allowed_dns_suffix", ""),
                root_export_passphrase=request.form.get("root_export_passphrase", ""),
                allow_public_sans=request.form.get("allow_public_sans") == "on",
            )
            session["pending_export_token"] = token
            session["pending_export_kind"] = "offline-root"
            return redirect(url_for("export_ready"))
        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

    @app.get("/certificates")
    def certificates():
        _require_initialized(certificate_service)
        selected_status = request.args.get("status", "active").strip().lower()
        status_filters = ("active", "revoked", "superseded", "all")
        if selected_status not in status_filters:
            abort(400, "Unknown certificate status filter")
        inventory = certificate_service.certificates()
        if selected_status != "all":
            inventory = [
                certificate
                for certificate in inventory
                if certificate["status"] == selected_status
            ]
        return render_template(
            "certificates.html",
            certificates=inventory,
            selected_status=selected_status,
            status_filters=status_filters,
        )

    @app.route("/certificates/new", methods=["GET", "POST"])
    def new_certificate():
        _require_initialized(certificate_service)
        if request.method == "GET":
            selected = request.args.get("profile", "iot_md")
            return render_template("new_certificate.html", selected_profile=selected)
        try:
            certificate_id, token = certificate_service.issue(
                profile_slug=request.form.get("profile", ""),
                common_name=request.form.get("common_name", ""),
                sans=request.form.get("sans", ""),
                key_type=request.form.get("key_type", ""),
                validity_days=request.form.get("validity_days", ""),
                export_format=request.form.get("export_format", ""),
                export_password=request.form.get("export_password", ""),
            )
            session["pending_export_token"] = token
            session["pending_export_kind"] = "certificate"
            session["new_certificate_id"] = certificate_id
            return redirect(url_for("export_ready"))
        except Exception as exc:
            flash(str(exc), "error")
            return render_template(
                "new_certificate.html",
                selected_profile=request.form.get("profile", "iot_md"),
                form=request.form,
            ), 400

    @app.route("/public-certificates/new", methods=["GET", "POST"])
    def new_public_certificate():
        _require_initialized(certificate_service)
        external = certificate_service.settings()["external_acme"]
        if not external["enabled"]:
            flash("Configure and enable public ACME issuance first", "error")
            return redirect(url_for("settings"))
        if request.method == "GET":
            return render_template("new_public_certificate.html", external=external)
        try:
            portal_host = request.form.get("portal_host", "").strip().lower()
            if not re.fullmatch(
                r"(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])",
                portal_host,
            ):
                raise ValueError(
                    "The public portal host must be one DNS label containing only "
                    "letters, numbers, or internal hyphens"
                )
            common_name = f"{portal_host}.{external['zone']}" if portal_host else ""
            api_hostname = request.form.get("api_hostname", "").strip()
            certificate_id, token = certificate_service.issue_public_portal(
                common_name=common_name,
                api_hostname=api_hostname or f"{portal_host}.local",
                sans=request.form.get("sans", ""),
            )
            session["pending_export_token"] = token
            session["pending_export_kind"] = "certificate"
            session["new_certificate_id"] = certificate_id
            return redirect(url_for("export_ready"))
        except Exception as exc:
            flash(str(exc), "error")
            return render_template(
                "new_public_certificate.html", external=external,
                form=request.form,
            ), 400

    @app.route("/device-enrollments/new", methods=["GET", "POST"])
    def new_device_enrollment():
        _require_initialized(certificate_service)
        external = certificate_service.settings()["external_acme"]
        if not external["enabled"]:
            flash("Configure and enable public ACME issuance first", "error")
            return redirect(url_for("settings"))
        if request.method == "GET":
            return render_template(
                "new_device_enrollment.html", external=external
            )
        try:
            enrollment_id, token = certificate_service.create_device_enrollment(
                request.form.get("portal_host", "")
            )
            session["pending_export_token"] = token
            session["pending_export_kind"] = "device-enrollment"
            session["new_enrollment_id"] = enrollment_id
            return redirect(url_for("export_ready"))
        except Exception as exc:
            flash(str(exc), "error")
            return render_template(
                "new_device_enrollment.html", external=external,
                form=request.form,
            ), 400

    @app.get("/certificates/<certificate_id>")
    def certificate_detail(certificate_id):
        _require_initialized(certificate_service)
        certificate = certificate_service.certificate(certificate_id)
        if not certificate:
            abort(404)
        return render_template("certificate_detail.html", certificate=certificate)

    @app.get("/certificates/<certificate_id>/download")
    def download_certificate(certificate_id):
        _require_initialized(certificate_service)
        certificate = certificate_service.certificate(certificate_id)
        if not certificate:
            abort(404)
        encoding = request.args.get("format", "pem").strip().lower()
        if encoding not in {"pem", "der"}:
            abort(400, "Certificate format must be PEM or DER")
        filename = secure_filename(certificate["common_name"]) or "certificate"
        mimetype = (
            "application/pkix-cert"
            if encoding == "der"
            else "application/x-pem-file"
        )
        return _memory_download(
            certificate_service.certificate_public_bytes(certificate_id, encoding),
            f"{filename}.{encoding}",
            mimetype,
        )

    @app.post("/certificates/<certificate_id>/renew")
    def renew_certificate(certificate_id):
        _require_initialized(certificate_service)
        try:
            new_id, token = certificate_service.renew(
                certificate_id,
                export_format=request.form.get("export_format", "pem"),
                export_password=request.form.get("export_password", ""),
            )
            session["pending_export_token"] = token
            session["pending_export_kind"] = "certificate"
            session["new_certificate_id"] = new_id
            return redirect(url_for("export_ready"))
        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("certificate_detail", certificate_id=certificate_id))

    @app.post("/certificates/<certificate_id>/revoke")
    def revoke_certificate(certificate_id):
        _require_initialized(certificate_service)
        try:
            certificate_service.revoke(certificate_id)
            flash("Certificate revoked. Existing copies remain valid until expiry, but cannot renew.", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("certificate_detail", certificate_id=certificate_id))

    @app.get("/export-ready")
    def export_ready():
        token = session.get("pending_export_token")
        record = certificate_service.export_for_token(token) if token else None
        if not record:
            flash("The one-time export is unavailable or has expired", "error")
            return redirect(url_for("dashboard"))
        return render_template(
            "export_ready.html",
            record=record,
            export_kind=session.get("pending_export_kind"),
            certificate_id=session.get("new_certificate_id"),
            enrollment_id=session.get("new_enrollment_id"),
        )

    @app.get("/download")
    def download_export():
        token = session.get("pending_export_token")
        record = certificate_service.export_for_token(token) if token else None
        if not record:
            abort(404, "One-time export not found or expired")
        mimetype = (
            "application/vnd.iotmd.enrollment+json"
            if record["kind"] == "device-enrollment" else "application/zip"
        )
        return send_file(
            record["path"],
            as_attachment=True,
            download_name=record["filename"],
            mimetype=mimetype,
            conditional=False,
        )

    @app.post("/exports/confirm")
    def confirm_export():
        token = session.get("pending_export_token")
        record = certificate_service.export_for_token(token) if token else None
        if not record:
            flash("The export is unavailable or has expired", "error")
            return redirect(url_for("dashboard"))
        try:
            certificate_service.complete_export(record)
        except Exception as exc:
            flash(f"Could not clear the export: {exc}", "error")
            return redirect(url_for("export_ready"))
        certificate_id = session.pop("new_certificate_id", None)
        session.pop("pending_export_token", None)
        session.pop("pending_export_kind", None)
        session.pop("new_enrollment_id", None)
        flash("Export confirmed and removed from app storage", "success")
        if certificate_id and certificate_service.certificate(certificate_id):
            return redirect(url_for("certificate_detail", certificate_id=certificate_id))
        return redirect(url_for("dashboard"))

    @app.post("/offline-root/recover-link")
    def recover_root_link():
        _require_initialized(certificate_service)
        try:
            token = certificate_service.recover_root_export()
            session["pending_export_token"] = token
            session["pending_export_kind"] = "offline-root"
            return redirect(url_for("export_ready"))
        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))

    @app.get("/trust/root.pem")
    def root_pem():
        _require_initialized(certificate_service)
        return _memory_download(certificate_service.root_trust("pem"), "iot-ca-root.pem", "application/x-pem-file")

    @app.get("/trust/root.der")
    def root_der():
        _require_initialized(certificate_service)
        return _memory_download(certificate_service.root_trust("der"), "iot-ca-root.der", "application/pkix-cert")

    @app.get("/trust/intermediate.pem")
    def intermediate_pem():
        _require_initialized(certificate_service)
        return _memory_download(
            certificate_service.intermediate_trust("pem"),
            "iot-ca-intermediate.pem",
            "application/x-pem-file",
        )

    @app.get("/trust/intermediate.der")
    def intermediate_der():
        _require_initialized(certificate_service)
        return _memory_download(
            certificate_service.intermediate_trust("der"),
            "iot-ca-intermediate.der",
            "application/pkix-cert",
        )

    @app.get("/trust/chain.pem")
    def ca_chain_pem():
        _require_initialized(certificate_service)
        return _memory_download(
            certificate_service.ca_chain(),
            "iot-ca-chain.pem",
            "application/x-pem-file",
        )

    @app.get("/audit")
    def audit():
        _require_initialized(certificate_service)
        return render_template("audit.html", entries=certificate_service.audit_log())

    @app.get("/settings")
    def settings():
        _require_initialized(certificate_service)
        return render_template(
            "settings.html",
            settings=certificate_service.settings(),
            ca_health=certificate_service.engine.health(),
        )

    @app.post("/settings/external-acme")
    def external_acme_settings():
        _require_initialized(certificate_service)
        try:
            certificate_service.configure_external_acme(
                enabled=request.form.get("enabled") == "on",
                email=request.form.get("email", ""),
                zone=request.form.get("zone", ""),
                environment=request.form.get("environment", "staging"),
                terms_accepted=request.form.get("terms_accepted") == "on",
                dns_token=request.form.get("dns_token", ""),
                zone_token=request.form.get("zone_token", ""),
            )
            flash("Public ACME settings saved", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("settings"))

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    def error_page(error):
        return render_template("error.html", error=error), getattr(error, "code", 500)

    return app


def _require_initialized(service):
    if not service.initialized:
        abort(409, "Initialize the certificate authority first")


def _memory_download(data, filename, mimetype):
    import io
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename, mimetype=mimetype)
