"""
SQLite-backed PII vault.

Every original→surrogate mapping is stored here, keyed by engagement ID.
The same original value within an engagement always maps to the same surrogate.
Different engagements are fully isolated — same IP at two clients gets different surrogates.
"""
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

_TZ_BRT = timezone(timedelta(hours=-3))

from .config import config


def _conn(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or config.DATABASE_PATH
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: Path | None = None) -> None:
    conn = _conn(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pii_vault (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement   TEXT    NOT NULL,
            entity_type  TEXT    NOT NULL,
            original     TEXT    NOT NULL,
            surrogate    TEXT    NOT NULL,
            created_at   TEXT    NOT NULL,
            UNIQUE(engagement, original, entity_type)
        );
        CREATE INDEX IF NOT EXISTS idx_surrogate
            ON pii_vault(engagement, surrogate);

        -- Audit trail: every time a value is seen (new or cached) during a request
        CREATE TABLE IF NOT EXISTS transform_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT    NOT NULL,
            engagement   TEXT    NOT NULL,
            entity_type  TEXT    NOT NULL,
            original     TEXT    NOT NULL,
            surrogate    TEXT    NOT NULL,
            is_new       INTEGER NOT NULL DEFAULT 0  -- 1 = new mapping, 0 = retrieved from cache
        );
        CREATE INDEX IF NOT EXISTS idx_log_ts
            ON transform_log(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_log_eng
            ON transform_log(engagement, ts DESC);
    """)
    conn.commit()
    conn.close()


def get_or_create(
    original: str,
    entity_type: str,
    surrogate_fn,
    engagement: str | None = None,
    db_path: Path | None = None,
) -> tuple[str, bool]:
    """Return (surrogate, is_new).

    is_new=True  → first time this value is seen; a new mapping was created.
    is_new=False → value was already in the vault; existing surrogate returned.

    Also appends a row to transform_log so the /audit page can show history.
    """
    eng = engagement or config.ENGAGEMENT_ID
    ts  = datetime.now(_TZ_BRT).isoformat(timespec="seconds")
    conn = _conn(db_path)
    try:
        row = conn.execute(
            "SELECT surrogate FROM pii_vault "
            "WHERE engagement=? AND original=? AND entity_type=?",
            (eng, original, entity_type),
        ).fetchone()

        if row:
            surrogate = row[0]
            is_new = False
        else:
            surrogate = surrogate_fn(original, entity_type)
            conn.execute(
                "INSERT INTO pii_vault "
                "(engagement, entity_type, original, surrogate, created_at) "
                "VALUES (?,?,?,?,?)",
                (eng, entity_type, original, surrogate, ts),
            )
            is_new = True

        # Always log to audit trail (new AND cached hits, so operators see traffic)
        conn.execute(
            "INSERT INTO transform_log "
            "(ts, engagement, entity_type, original, surrogate, is_new) "
            "VALUES (?,?,?,?,?,?)",
            (ts, eng, entity_type, original, surrogate, int(is_new)),
        )
        conn.commit()
        return surrogate, is_new
    finally:
        conn.close()


def get_transform_log(
    engagement: str | None = None,
    db_path: Path | None = None,
    limit: int = 500,
) -> list[dict]:
    """Return recent transform_log entries newest-first."""
    eng = engagement or config.ENGAGEMENT_ID
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT ts, engagement, entity_type, original, surrogate, is_new "
            "FROM transform_log "
            "WHERE engagement=? "
            "ORDER BY id DESC LIMIT ?",
            (eng, limit),
        ).fetchall()
        return [
            {
                "ts": r[0], "engagement": r[1], "entity_type": r[2],
                "original": r[3], "surrogate": r[4], "is_new": bool(r[5]),
            }
            for r in rows
        ]
    finally:
        conn.close()


def get_all_engagements(db_path: Path | None = None) -> list[str]:
    """Return all distinct engagement IDs in the vault."""
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT DISTINCT engagement FROM pii_vault ORDER BY engagement"
        ).fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


def get_all_mappings(
    engagement: str | None = None,
    db_path: Path | None = None,
) -> list[tuple[str, str]]:
    """Returns (surrogate, original) for the engagement, longest surrogate first."""
    eng = engagement or config.ENGAGEMENT_ID
    conn = _conn(db_path)
    try:
        return conn.execute(
            "SELECT surrogate, original FROM pii_vault "
            "WHERE engagement=? ORDER BY LENGTH(surrogate) DESC",
            (eng,),
        ).fetchall()
    finally:
        conn.close()


def get_stats(db_path: Path | None = None) -> dict[str, int]:
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT entity_type, COUNT(*) FROM pii_vault "
            "WHERE engagement=? GROUP BY entity_type",
            (config.ENGAGEMENT_ID,),
        ).fetchall()
        return {r[0]: r[1] for r in rows}
    finally:
        conn.close()
