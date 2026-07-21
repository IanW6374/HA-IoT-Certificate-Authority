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

    def add_certificate(self, record: dict):
        columns = (
            "id", "profile", "common_name", "sans_json", "key_type", "validity_days",
            "serial", "fingerprint", "not_before", "not_after", "status",
            "certificate_pem", "created_at", "renewed_from", "revoked_at",
        )
        values = [record.get(column) for column in columns]
        with self.connection() as db:
            db.execute(
                f"INSERT INTO certificates({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                values,
            )

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
        return result
