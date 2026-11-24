"""Tests for SQLite database setup and persistence."""

import pandas as pd

from src.database import (
    get_matches,
    init_db,
    register_evidence_file,
    save_iocs,
    save_matches,
)


def test_init_db_creates_tables(tmp_path) -> None:
    conn = init_db(str(tmp_path / "test.db"))
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"iocs", "rejected_iocs", "evidence_files", "matches"}.issubset(tables)
    conn.close()


def test_save_iocs_does_not_create_valid_duplicates(tmp_path) -> None:
    conn = init_db(str(tmp_path / "test.db"))
    valid = pd.DataFrame([{
        "norm_value": "evil-domain.com",
        "norm_type": "domain",
        "source": "ThreatFeedA",
    }])
    rejected = pd.DataFrame([{
        "row_id": 13,
        "value": "999.999.1.1",
        "reason": "invalid",
    }])

    save_iocs(conn, valid, rejected)
    save_iocs(conn, valid, rejected)

    assert conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0] == 1
    conn.close()


def test_register_evidence_file_returns_existing_id(tmp_path) -> None:
    evidence = tmp_path / "log.csv"
    evidence.write_text("timestamp,src_ip\n10:00,185.220.101.45\n", encoding="utf-8")
    conn = init_db(str(tmp_path / "test.db"))

    first_id = register_evidence_file(conn, str(evidence), 1)
    second_id = register_evidence_file(conn, str(evidence), 1)

    assert first_id == second_id
    assert conn.execute("SELECT COUNT(*) FROM evidence_files").fetchone()[0] == 1
    conn.close()


def test_save_matches_skips_duplicates_and_get_matches_sorts(tmp_path) -> None:
    conn = init_db(str(tmp_path / "test.db"))
    valid = pd.DataFrame([{
        "norm_value": "185.220.101.45",
        "norm_type": "ipv4",
        "source": "feed",
    }])
    save_iocs(conn, valid, pd.DataFrame(columns=["row_id", "value", "reason"]))

    evidence = tmp_path / "auth.csv"
    evidence.write_text("timestamp,src_ip\n", encoding="utf-8")
    file_id = register_evidence_file(conn, str(evidence), 0)

    matches = pd.DataFrame([{
        "ioc_value": "185.220.101.45",
        "ioc_type": "ipv4",
        "source_file": "auth.csv",
        "row_id": 2,
        "event_time": "2026-10-10 08:00:00",
        "matched_field": "src_ip",
        "matched_value": "185.220.101.45",
    }])
    save_matches(conn, matches)
    save_matches(conn, matches)

    result = get_matches(conn)
    assert len(result) == 1
    assert result.iloc[0]["filename"] == "auth.csv"
    assert file_id > 0
    conn.close()
