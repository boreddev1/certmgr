"""SQLite-Registry fuer die ausgegebenen Client-Zertifikate.

Eine Datei, eine Tabelle. Der Dienst laeuft in podman, die Datei liegt auf
einem Volume - deshalb WAL-Modus und ein kurzes busy_timeout, damit ein
paralleler Admin-Zugriff nicht auf ein "database is locked" laeuft.

Schema-Hinweis: Der private Schluessel wird NIE im Klartext gespeichert.
Gespeichert wird ein AES-GCM-Blob (siehe ca.py). Nach dem einmaligen
Download wird das Blob geloescht - ab dann existiert der Schluessel nur
noch beim Client.
"""
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS certs (
    id              TEXT PRIMARY KEY,      -- CF-Client-Certificate-ID (UUID)
    device          TEXT NOT NULL,         -- Geraetename, z.B. "laptop-sven"
    note            TEXT DEFAULT '',       -- Freitext
    common_name     TEXT NOT NULL,
    certificate     TEXT NOT NULL,         -- signiertes PEM (oeffentlich)
    serial_number   TEXT DEFAULT '',
    fingerprint     TEXT DEFAULT '',
    issued_on       TEXT DEFAULT '',
    expires_on      TEXT DEFAULT '',
    status          TEXT DEFAULT 'active', -- active|pending_revocation|revoked
    cf_status       TEXT DEFAULT '',       -- letzter Status von Cloudflare
    key_blob        BLOB,                  -- AES-GCM-verschluesselter privater Schluessel
    key_deleted     INTEGER DEFAULT 0,
    token_hash      TEXT,                  -- SHA-256 des Onboarding-Tokens
    token_expires   REAL DEFAULT 0,
    password_hash   TEXT,                  -- scrypt-Hash des Onboarding-Passworts
    downloaded_at   REAL DEFAULT 0,
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_device ON certs(device);
CREATE INDEX IF NOT EXISTS idx_certs_token  ON certs(token_hash);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    action    TEXT NOT NULL,
    device    TEXT DEFAULT '',
    detail    TEXT DEFAULT '',
    remote    TEXT DEFAULT ''
);
"""

# Spalten, die der Admin-UI gezeigt werden. key_blob/token_hash/
# password_hash bleiben draussen - die gehoeren nicht in Listenansichten.
PUBLIC_COLUMNS = (
    "id, device, note, common_name, serial_number, fingerprint, issued_on, "
    "expires_on, status, cf_status, key_deleted, downloaded_at, created_at, "
    "updated_at"
)


class Store:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._init_schema()

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ---------------------------------------------------------------- CRUD

    def insert_cert(self, **fields):
        now = time.time()
        fields.setdefault("created_at", now)
        fields["updated_at"] = now
        cols = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO certs ({cols}) VALUES ({marks})", list(fields.values())
            )
        return fields["id"]

    def update_cert(self, cert_id, **fields):
        if not fields:
            return
        fields["updated_at"] = time.time()
        sets = ", ".join(f"{k}=?" for k in fields)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE certs SET {sets} WHERE id=?", list(fields.values()) + [cert_id]
            )

    def get_cert(self, cert_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certs WHERE id=?", (cert_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_by_token_hash(self, token_hash):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certs WHERE token_hash=?", (token_hash,)
            ).fetchone()
        return dict(row) if row else None

    def list_certs(self, limit=500):
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {PUBLIC_COLUMNS} FROM certs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_key_blob(self, cert_id):
        """Schluessel endgueltig vernichten (nach dem Download)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE certs SET key_blob=NULL, key_deleted=1, updated_at=? WHERE id=?",
                (time.time(), cert_id),
            )

    # -------------------------------------------------------------- Audit

    def audit(self, action, device="", detail="", remote=""):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit (ts, action, device, detail, remote) VALUES (?,?,?,?,?)",
                (time.time(), action, device, detail, remote),
            )

    def recent_audit(self, limit=100):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
