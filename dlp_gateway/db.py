"""Small SQLite audit/policy store. Raw file contents never enter the database."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                  actor TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'normal'
                );
                CREATE TABLE IF NOT EXISTS policies (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, keyword TEXT NOT NULL,
                  action TEXT NOT NULL, scope TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS audits (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                  actor TEXT NOT NULL, destination TEXT NOT NULL, filename TEXT NOT NULL,
                  sha256 TEXT NOT NULL, size INTEGER NOT NULL, action TEXT NOT NULL,
                  reasons TEXT NOT NULL, signals TEXT NOT NULL, model_status TEXT NOT NULL,
                  forwarded INTEGER NOT NULL DEFAULT 0, upstream_status INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_audits_time ON audits(created_at);
                CREATE TABLE IF NOT EXISTS exceptions (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id INTEGER NOT NULL UNIQUE,
                  actor TEXT NOT NULL, destination TEXT NOT NULL, sha256 TEXT NOT NULL,
                  justification TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                  created_at TEXT NOT NULL, expires_at TEXT,
                  FOREIGN KEY(audit_id) REFERENCES audits(id)
                );
                CREATE TABLE IF NOT EXISTS feedback (
                  audit_id INTEGER PRIMARY KEY, verdict TEXT NOT NULL,
                  note TEXT NOT NULL, created_at TEXT NOT NULL,
                  FOREIGN KEY(audit_id) REFERENCES audits(id)
                );
                CREATE TABLE IF NOT EXISTS admin_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                  event TEXT NOT NULL, target TEXT NOT NULL
                );
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def rows(self, query: str, params: tuple = ()) -> list[dict]:
        with self.connection() as db:
            return [dict(row) for row in db.execute(query, params).fetchall()]

    def one(self, query: str, params: tuple = ()) -> dict | None:
        rows = self.rows(query, params)
        return rows[0] if rows else None

    def execute(self, query: str, params: tuple = ()) -> int:
        with self.connection() as db:
            return db.execute(query, params).lastrowid

    def event(self, event: str, target: str) -> None:
        self.execute("INSERT INTO admin_events(created_at,event,target) VALUES(?,?,?)", (now(), event, target))

    def audit(self, *, actor: str, destination: str, filename: str, sha256: str,
              size: int, action: str, reasons: list[str], signals: list[str], model_status: str) -> int:
        return self.execute("""INSERT INTO audits
            (created_at,actor,destination,filename,sha256,size,action,reasons,signals,model_status)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", (now(), actor, destination, filename,
            sha256, size, action, json.dumps(reasons), json.dumps(signals), model_status))

    def policies(self) -> list[dict]:
        return self.rows("SELECT * FROM policies ORDER BY id")

    def user_status(self, actor: str) -> str:
        user = self.one("SELECT status FROM users WHERE actor=?", (actor,))
        return user["status"] if user else "normal"

    def approved(self, actor: str, destination: str, sha256: str) -> bool:
        return bool(self.one("""SELECT id FROM exceptions WHERE actor=? AND destination=? AND sha256=?
            AND status='approved' AND expires_at>? LIMIT 1""", (actor, destination, sha256, now())))
