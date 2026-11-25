import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.importer import file_sha256


def init_db(db_path: str) -> sqlite3.Connection:
    """Create the SQLite database and required tables."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    # Allow Streamlit worker threads to use the same temporary SQLite connection.
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY,
            value TEXT,
            type TEXT,
            source TEXT,
            UNIQUE(value, type)
        );
        CREATE TABLE IF NOT EXISTS rejected_iocs (
            id INTEGER PRIMARY KEY,
            row_id INTEGER,
            original_value TEXT,
            reason TEXT
        );
        CREATE TABLE IF NOT EXISTS evidence_files (
            id INTEGER PRIMARY KEY,
            filename TEXT,
            sha256 TEXT UNIQUE,
            imported_at TEXT,
            row_count INTEGER
        );
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY,
            ioc_id INTEGER,
            file_id INTEGER,
            row_id INTEGER,
            event_time TEXT,
            matched_field TEXT,
            matched_value TEXT,
            FOREIGN KEY(ioc_id) REFERENCES iocs(id),
            FOREIGN KEY(file_id) REFERENCES evidence_files(id),
            UNIQUE(ioc_id, file_id, row_id, matched_field)
        );
    """)
    conn.commit()
    return conn


def save_iocs(conn: sqlite3.Connection, valid_df: pd.DataFrame, rejected_df: pd.DataFrame) -> None:
    """Save valid and rejected IOCs without creating IOC duplicates."""
    for row in valid_df.to_dict("records"):
        conn.execute(
            "INSERT OR IGNORE INTO iocs (value, type, source) VALUES (?, ?, ?)",
            (row["norm_value"], row["norm_type"], row.get("source", "")),
        )

    for row in rejected_df.to_dict("records"):
        conn.execute(
            "INSERT INTO rejected_iocs (row_id, original_value, reason) VALUES (?, ?, ?)",
            (int(row["row_id"]), str(row.get("value", "")), str(row.get("reason", ""))),
        )
    conn.commit()


def register_evidence_file(conn: sqlite3.Connection, path: str, row_count: int) -> int:
    """Register an evidence file once, identified by its SHA-256 hash."""
    sha256 = file_sha256(path)
    existing = conn.execute(
        "SELECT id FROM evidence_files WHERE sha256 = ?", (sha256,)
    ).fetchone()
    if existing:
        return int(existing[0])

    filename = Path(path).name
    timestamp = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO evidence_files (filename, sha256, imported_at, row_count) VALUES (?, ?, ?, ?)",
        (filename, sha256, timestamp, row_count),
    )
    conn.commit()
    return int(cursor.lastrowid)


def save_matches(conn: sqlite3.Connection, matches_df: pd.DataFrame) -> None:
    """Save matched rows while silently skipping duplicates."""
    for row in matches_df.to_dict("records"):
        ioc = conn.execute(
            "SELECT id FROM iocs WHERE value = ? AND type = ?",
            (row["ioc_value"], row["ioc_type"]),
        ).fetchone()
        file_row = conn.execute(
            "SELECT id FROM evidence_files WHERE filename = ?",
            (row["source_file"],),
        ).fetchall()
        if not ioc:
            continue
        for file_record in file_row:
            conn.execute(
                """INSERT OR IGNORE INTO matches
                   (ioc_id, file_id, row_id, event_time, matched_field, matched_value)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    ioc[0], file_record[0], int(row["row_id"]),
                    str(row.get("event_time", "")), row["matched_field"], row["matched_value"],
                ),
            )
    conn.commit()


def get_matches(conn: sqlite3.Connection) -> pd.DataFrame:
    """Return all stored matches with IOC and evidence file details."""
    query = """
        SELECT i.value AS ioc_value, i.type AS ioc_type, i.source AS source,
               f.filename AS filename, m.row_id AS row_id,
               m.event_time AS event_time, m.matched_field AS matched_field,
               m.matched_value AS matched_value
        FROM matches AS m
        JOIN iocs AS i ON i.id = m.ioc_id
        JOIN evidence_files AS f ON f.id = m.file_id
        ORDER BY m.event_time
    """
    return pd.read_sql_query(query, conn)
