"""Tests for IOC matching and end-to-end correlation."""
import pandas as pd
import pytest

from src.database import init_db
from src.importer import load_evidence_file
from src.matcher import find_matches, run_correlation
from src.normalizer import normalize_ioc_dataframe


def make_valid_iocs(rows: list[dict]) -> pd.DataFrame:
    """Return normalized valid IOCs from test rows."""
    df = pd.DataFrame(rows)
    valid, _ = normalize_ioc_dataframe(df)
    return valid


def test_known_ioc_in_log_matches_with_details() -> None:
    valid = make_valid_iocs([{"value": "185.220.101.45", "type": "ip", "source": "feed"}])
    evidence = pd.DataFrame([{"row_id": 2, "timestamp": "2026-10-10 07:55:01", "src_ip": "185.220.101.45"}])
    matches = find_matches(valid, evidence, "auth_log.csv")
    assert len(matches) == 1
    assert matches.iloc[0].to_dict() == {
        "ioc_value": "185.220.101.45",
        "ioc_type": "ipv4",
        "source_file": "auth_log.csv",
        "row_id": 2,
        "event_time": "2026-10-10 07:55:01",
        "matched_field": "src_ip",
        "matched_value": "185.220.101.45",
    }


def test_dns_domain_normalization_matches_both_forms() -> None:
    valid = make_valid_iocs([{"value": "evil-domain.com", "type": "domain", "source": "feed"}])
    evidence = pd.DataFrame([
        {"row_id": 2, "timestamp": "10:00", "query": "EVIL-DOMAIN.COM"},
        {"row_id": 3, "timestamp": "10:01", "query": "evil-domain.com."},
    ])
    matches = find_matches(valid, evidence, "dns_log.csv")
    assert len(matches) == 2


def test_domain_does_not_match_url_or_url_text() -> None:
    domain_valid = make_valid_iocs([{"value": "malware-site.net", "type": "domain", "source": "feed"}])
    url_valid = make_valid_iocs([{"value": "http://malware-site.net/payload.exe", "type": "url", "source": "feed"}])
    evidence = pd.DataFrame([{
        "row_id": 2,
        "timestamp": "10:00",
        "query": "malware-site.net",
        "url": "http://malware-site.net/payload.exe",
    }])
    assert len(find_matches(domain_valid, evidence, "proxy.csv")) == 1
    assert len(find_matches(url_valid, evidence, "proxy.csv")) == 1


def test_near_misses_do_not_match() -> None:
    valid = make_valid_iocs([
        {"value": "185.220.101.45", "type": "ip", "source": "feed"},
        {"value": "bad-domain.com", "type": "domain", "source": "feed"},
    ])
    evidence = pd.DataFrame([
        {"row_id": 2, "timestamp": "10:00", "src_ip": "185.220.101.46", "query": "notbad-domain.com"},
    ])
    assert find_matches(valid, evidence, "log.csv").empty


def test_empty_evidence_missing_timestamp_and_empty_cells() -> None:
    valid = make_valid_iocs([{"value": "evil-domain.com", "type": "domain", "source": "feed"}])
    evidence = pd.DataFrame([{"row_id": 2, "query": ""}, {"row_id": 3, "query": pd.NA}])
    matches = find_matches(valid, evidence, "dns.csv")
    assert matches.empty


def test_unsupported_file_extension(tmp_path) -> None:
    path = tmp_path / "evidence.txt"
    path.write_text("test", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported"):
        load_evidence_file(str(path))


def test_importing_same_evidence_twice_has_no_duplicates(tmp_path) -> None:
    evidence_path = tmp_path / "log.csv"
    evidence_path.write_text("timestamp,src_ip\n2026-10-10 07:55:01,185.220.101.45\n", encoding="utf-8")
    ioc_path = tmp_path / "iocs.csv"
    ioc_path.write_text("value,type,source\n185.220.101.45,ip,feed\n", encoding="utf-8")
    db_path = tmp_path / "test.db"
    conn = init_db(str(db_path))

    run_correlation(conn, str(ioc_path), [str(evidence_path)])
    run_correlation(conn, str(ioc_path), [str(evidence_path)])

    assert len(conn.execute("SELECT * FROM evidence_files").fetchall()) == 1
    assert len(conn.execute("SELECT * FROM matches").fetchall()) == 1
    conn.close()


def test_real_sample_end_to_end() -> None:
    conn = init_db(":memory:")
    evidence_paths = [
        "data/dns_log.csv",
        "data/auth_log.csv",
        "data/proxy_log.csv",
        "data/endpoint_log.csv",
    ]
    matches = run_correlation(conn, "data/iocs.csv", evidence_paths)

    assert len(matches) == 14
    row = matches[
        (matches["filename"] == "auth_log.csv")
        & (matches["row_id"] == 2)
        & (matches["matched_field"] == "src_ip")
        & (matches["matched_value"] == "185.220.101.45")
    ]
    assert len(row) == 1
    conn.close()
