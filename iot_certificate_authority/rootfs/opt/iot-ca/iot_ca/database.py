"""SQLite inventory, one-time exports, and audit log."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Inventory:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self):
        with self.connection() as db:
            db.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS certificates (
                    id TEXT PRIMARY KEY,
                    profile TEXT NOT NULL,
                    common_name TEXT NOT NULL,
                    sans_json TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    validity_days INTEGER NOT NULL,
                    serial TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    status TEXT NOT NULL,
                    certificate_pem BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    renewed_from TEXT,
                    revoked_at TEXT,
                    FOREIGN KEY(renewed_from) REFERENCES certificates(id)
                );
                CREATE INDEX IF NOT EXISTS certificates_expiry ON certificates(not_after);
                CREATE INDEX IF NOT EXISTS certificates_status ON certificates(status);

                CREATE TABLE IF NOT EXISTS exports (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    path TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS exports_expiry ON exports(expires_at);

                CREATE TABLE IF NOT EXISTS device_enrollments (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    portal_hostname TEXT NOT NULL,
                    api_hostname TEXT NOT NULL,
                    renewal_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_json TEXT,
                    result_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS device_enrollments_expiry
                    ON device_enrollments(expires_at);

                CREATE TABLE IF NOT EXISTS device_renewals (
                    id TEXT PRIMARY KEY,
                    enrollment_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(enrollment_id) REFERENCES device_enrollments(id)
                );
                CREATE INDEX IF NOT EXISTS device_renewals_enrollment
                    ON device_renewals(enrollment_id, created_at);

                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_id TEXT,
                    success INTEGER NOT NULL,
                    detail_json TEXT NOT NULL
                );
                """
            )
            columns = {
                row["name"] for row in db.execute(
                    "PRAGMA table_info(certificates)"
                ).fetchall()
            }
            if "source" not in columns:
                db.execute(
                    "ALTER TABLE certificates ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'"
                )
            if "provisioner" not in columns:
                db.execute(
                    "ALTER TABLE certificates ADD COLUMN provisioner TEXT"
                )
            self._reconcile_public_certificate_history(db)

    @staticmethod
    def _reconcile_public_certificate_history(db):
        """Repair public replacement lineage created before it was persisted."""
        rows = db.execute(
            """
            SELECT id, common_name, sans_json, status, renewed_from
            FROM certificates
            WHERE profile = 'public-portal' AND source = 'external-acme'
            ORDER BY common_name, not_before, created_at, id
            """
        ).fetchall()
        previous_by_identity = {}
        for row in rows:
            identity = row["common_name"]
            previous = previous_by_identity.get(identity)
            if previous:
                if not row["renewed_from"]:
                    db.execute(
                        "UPDATE certificates SET renewed_from = ? WHERE id = ?",
                        (previous["id"], row["id"]),
                    )
                if previous["status"] == "active":
                    db.execute(
                        "UPDATE certificates SET status = 'superseded' WHERE id = ?",
                        (previous["id"],),
                    )
            previous_by_identity[identity] = row

    def audit(self, action: str, object_id: str | None = None, *, success=True, detail=None):
        with self.connection() as db:
            db.execute(
                "INSERT INTO audit(occurred_at, action, object_id, success, detail_json) VALUES(?,?,?,?,?)",
                (utc_now(), action, object_id, int(bool(success)), json.dumps(detail or {}, sort_keys=True)),
            )

    def audit_log(self, limit: int = 250):
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 1000)),)
            ).fetchall()
        return [self._row(row) for row in rows]

    def add_certificate(
        self, record: dict, *, supersedes: str | None = None,
        supersede_matching: bool = False,
    ):
        columns = (
            "id", "profile", "common_name", "sans_json", "key_type", "validity_days",
            "serial", "fingerprint", "not_before", "not_after", "status",
            "certificate_pem", "created_at", "renewed_from", "revoked_at",
            "source", "provisioner",
        )
        with self.connection() as db:
            previous = None
            if supersedes:
                previous = db.execute(
                    "SELECT id, status FROM certificates WHERE id = ?",
                    (supersedes,),
                ).fetchone()
                if not previous:
                    raise ValueError("Replacement certificate not found")
                if previous["status"] != "active":
                    raise ValueError("Only an active certificate can be replaced")
            elif supersede_matching:
                previous = db.execute(
                    """
                    SELECT id, status FROM certificates
                    WHERE status = 'active' AND profile = ?
                      AND common_name = ?
                    ORDER BY not_before DESC, created_at DESC LIMIT 1
                    """,
                    (
                        record["profile"], record["common_name"],
                    ),
                ).fetchone()
            if previous:
                record = dict(record)
                record["renewed_from"] = previous["id"]
            values = [
                record.get(column, "manual" if column == "source" else None)
                for column in columns
            ]
            db.execute(
                f"INSERT INTO certificates({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                values,
            )
            if previous:
                db.execute(
                    "UPDATE certificates SET status = 'superseded' WHERE id = ?",
                    (previous["id"],),
                )

    def import_certificate(self, record: dict):
        """Insert an externally issued certificate once and link ACME renewals."""
        with self.connection() as db:
            existing = db.execute(
                "SELECT id FROM certificates WHERE serial = ?",
                (record["serial"],),
            ).fetchone()
            if existing:
                return existing["id"], False

            previous = db.execute(
                """
                SELECT id FROM certificates
                WHERE source = 'acme' AND status = 'active'
                  AND common_name = ? AND sans_json = ?
                ORDER BY not_before DESC LIMIT 1
                """,
                (record["common_name"], record["sans_json"]),
            ).fetchone()
            if previous:
                record["renewed_from"] = previous["id"]
                db.execute(
                    "UPDATE certificates SET status = 'superseded' WHERE id = ?",
                    (previous["id"],),
                )

            columns = (
                "id", "profile", "common_name", "sans_json", "key_type",
                "validity_days", "serial", "fingerprint", "not_before",
                "not_after", "status", "certificate_pem", "created_at",
                "renewed_from", "revoked_at", "source", "provisioner",
            )
            db.execute(
                f"INSERT INTO certificates({','.join(columns)}) "
                f"VALUES({','.join('?' for _ in columns)})",
                [record.get(column) for column in columns],
            )
        return record["id"], True

    def certificate(self, certificate_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM certificates WHERE id = ?", (certificate_id,)).fetchone()
        return self._row(row) if row else None

    def certificates(self):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM certificates ORDER BY created_at DESC").fetchall()
        return [self._row(row) for row in rows]

    def set_certificate_status(self, certificate_id: str, status: str, *, revoked_at=None):
        with self.connection() as db:
            db.execute(
                "UPDATE certificates SET status = ?, revoked_at = COALESCE(?, revoked_at) WHERE id = ?",
                (status, revoked_at, certificate_id),
            )

    def active_certificate(self, *, profile: str, common_name: str):
        with self.connection() as db:
            row = db.execute(
                """
                SELECT * FROM certificates
                WHERE status = 'active' AND profile = ? AND common_name = ?
                ORDER BY not_before DESC, created_at DESC LIMIT 1
                """,
                (profile, common_name),
            ).fetchone()
        return self._row(row) if row else None

    def dashboard_counts(self):
        with self.connection() as db:
            rows = db.execute(
                "SELECT status, COUNT(*) AS count FROM certificates GROUP BY status"
            ).fetchall()
        counts = {"total": 0, "active": 0, "revoked": 0, "superseded": 0}
        for row in rows:
            counts[row["status"]] = row["count"]
            counts["total"] += row["count"]
        return counts

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def add_export(self, *, export_id: str, kind: str, path: str, filename: str, expires_at: str):
        token = secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute(
                "INSERT INTO exports(id, token_hash, kind, path, filename, created_at, expires_at) VALUES(?,?,?,?,?,?,?)",
                (export_id, self.token_hash(token), kind, path, filename, utc_now(), expires_at),
            )
        return token

    def export_for_token(self, token: str):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM exports WHERE token_hash = ? AND consumed_at IS NULL",
                (self.token_hash(token),),
            ).fetchone()
        return self._row(row) if row else None

    def pending_export(self, kind: str):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM exports WHERE kind = ? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1",
                (kind,),
            ).fetchone()
        return self._row(row) if row else None

    def replace_export_token(self, export_id: str):
        token = secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute(
                "UPDATE exports SET token_hash = ? WHERE id = ? AND consumed_at IS NULL",
                (self.token_hash(token), export_id),
            )
        return token

    def consume_export(self, export_id: str):
        with self.connection() as db:
            db.execute(
                "UPDATE exports SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
                (utc_now(), export_id),
            )

    def add_device_enrollment(
        self, *, enrollment_id, token, portal_hostname, api_hostname,
        renewal_name, expires_at,
    ):
        now = utc_now()
        with self.connection() as db:
            db.execute(
                """
                INSERT INTO device_enrollments(
                    id, token_hash, portal_hostname, api_hostname, renewal_name,
                    status, created_at, expires_at, updated_at
                ) VALUES(?,?,?,?,?,'authorized',?,?,?)
                """,
                (
                    enrollment_id, self.token_hash(token), portal_hostname,
                    api_hostname, renewal_name, now, expires_at, now,
                ),
            )

    def device_enrollment(self, enrollment_id, token):
        with self.connection() as db:
            row = db.execute(
                """
                SELECT * FROM device_enrollments
                WHERE id = ? AND token_hash = ?
                """,
                (enrollment_id, self.token_hash(token)),
            ).fetchone()
        return self._row(row) if row else None

    def device_enrollment_by_id(self, enrollment_id):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM device_enrollments WHERE id = ?", (enrollment_id,)
            ).fetchone()
        return self._row(row) if row else None

    def device_renewal(self, renewal_id, token):
        with self.connection() as db:
            row = db.execute(
                """
                SELECT * FROM device_renewals
                WHERE id = ? AND token_hash = ?
                """,
                (renewal_id, self.token_hash(token)),
            ).fetchone()
        return self._row(row) if row else None

    def device_renewal_by_id(self, renewal_id):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM device_renewals WHERE id = ?", (renewal_id,)
            ).fetchone()
        return self._row(row) if row else None

    def add_device_renewal(self, renewal_id, enrollment_id, token, request_value):
        encoded = json.dumps(request_value, sort_keys=True, separators=(",", ":"))
        now = utc_now()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM device_renewals WHERE id = ?", (renewal_id,)
            ).fetchone()
            if existing:
                current = self._row(existing)
                if (
                    current["enrollment_id"] != enrollment_id or
                    current["token_hash"] != self.token_hash(token) or
                    existing["request_json"] != encoded
                ):
                    raise ValueError("Renewal request identifier has already been used")
                return current
            pending = db.execute(
                """
                SELECT id FROM device_renewals
                WHERE enrollment_id = ? AND status = 'pending' LIMIT 1
                """,
                (enrollment_id,),
            ).fetchone()
            if pending:
                raise ValueError("A certificate renewal is already in progress")
            db.execute(
                """
                INSERT INTO device_renewals(
                    id, enrollment_id, token_hash, status, request_json,
                    created_at, updated_at
                ) VALUES(?,?,?,'pending',?,?,?)
                """,
                (
                    renewal_id, enrollment_id, self.token_hash(token), encoded,
                    now, now,
                ),
            )
        return self.device_renewal(renewal_id, token)

    def complete_device_renewal(self, renewal_id, result):
        with self.connection() as db:
            db.execute(
                """
                UPDATE device_renewals
                SET status='complete', result_json=?, error=NULL, updated_at=?
                WHERE id=?
                """,
                (json.dumps(result, sort_keys=True), utc_now(), renewal_id),
            )

    def fail_device_renewal(self, renewal_id, error):
        with self.connection() as db:
            db.execute(
                """
                UPDATE device_renewals
                SET status='error', error=?, updated_at=? WHERE id=?
                """,
                (str(error), utc_now(), renewal_id),
            )

    def claim_device_enrollment(self, enrollment_id, token, request_value):
        encoded = json.dumps(request_value, sort_keys=True, separators=(",", ":"))
        now = utc_now()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM device_enrollments WHERE id = ? AND token_hash = ?",
                (enrollment_id, self.token_hash(token)),
            ).fetchone()
            if not row:
                return None
            current = dict(row)
            if current["expires_at"] < now:
                db.execute(
                    "UPDATE device_enrollments SET status='expired', updated_at=? WHERE id=?",
                    (now, enrollment_id),
                )
                current["status"] = "expired"
                return self._row(current)
            if current["status"] == "authorized":
                db.execute(
                    """
                    UPDATE device_enrollments
                    SET status='pending', request_json=?, error=NULL, updated_at=?
                    WHERE id=?
                    """,
                    (encoded, now, enrollment_id),
                )
                current["status"] = "pending"
                current["request_json"] = encoded
            elif current.get("request_json") != encoded:
                raise ValueError("Enrollment has already been claimed with another request")
        return self._row(current)

    def complete_device_enrollment(self, enrollment_id, result):
        with self.connection() as db:
            db.execute(
                """
                UPDATE device_enrollments
                SET status='complete', result_json=?, error=NULL, updated_at=?
                WHERE id=? AND status='pending'
                """,
                (json.dumps(result, sort_keys=True), utc_now(), enrollment_id),
            )

    def fail_device_enrollment(self, enrollment_id, error):
        with self.connection() as db:
            db.execute(
                """
                UPDATE device_enrollments
                SET status='error', error=?, updated_at=?
                WHERE id=? AND status='pending'
                """,
                (str(error)[:800], utc_now(), enrollment_id),
            )

    def expired_exports(self, now: str | None = None):
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM exports WHERE consumed_at IS NULL AND expires_at < ?",
                (now or utc_now(),),
            ).fetchall()
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row):
        result = dict(row)
        if "sans_json" in result:
            result["sans"] = json.loads(result.pop("sans_json"))
        if "detail_json" in result:
            result["detail"] = json.loads(result.pop("detail_json"))
        if "request_json" in result:
            raw = result.pop("request_json")
            result["request"] = json.loads(raw) if raw else None
        if "result_json" in result:
            raw = result.pop("result_json")
            result["result"] = json.loads(raw) if raw else None
        return result
