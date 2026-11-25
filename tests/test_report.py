"""Tests for pure incident report functions."""
import json

import pandas as pd

from src.report import (
    build_case_report,
    build_summary,
    build_timeline,
    matches_to_csv,
    matches_to_json,
)


def make_matches() -> pd.DataFrame:
    """Create a small matches table for tests."""
    return pd.DataFrame([
        {
            "ioc_value": "evil,domain.com",
            "ioc_type": "domain",
            "source": "feed",
            "filename": "dns.csv",
            "row_id": 3,
            "event_time": "2026-10-10 08:00:00",
            "matched_field": "query",
            "matched_value": 'evil,"quoted".com',
        },
        {
            "ioc_value": "1.1.1.1",
            "ioc_type": "ipv4",
            "source": "feed",
            "filename": "auth.csv",
            "row_id": 2,
            "event_time": "2026-10-10 07:00:00",
            "matched_field": "src_ip",
            "matched_value": "1.1.1.1",
        },
    ])


def test_matches_to_csv_special_characters() -> None:
    csv_text = matches_to_csv(make_matches())
    assert 'evil,""quoted"".com' in csv_text
    assert "evil,domain.com" in csv_text


def test_matches_to_json_list_records() -> None:
    records = json.loads(matches_to_json(make_matches()))
    assert isinstance(records, list)
    assert records[0]["matched_field"] == "query"


def test_empty_csv_and_json_exports() -> None:
    empty = pd.DataFrame(columns=["ioc_value", "ioc_type"])
    assert matches_to_csv(empty).strip() == "ioc_value,ioc_type"
    assert json.loads(matches_to_json(empty)) == []


def test_build_timeline_sorted() -> None:
    timeline = build_timeline(make_matches())
    assert list(timeline.columns) == [
        "event_time", "ioc_value", "ioc_type", "filename",
        "row_id", "matched_field",
    ]
    assert timeline.iloc[0]["ioc_value"] == "1.1.1.1"


def test_build_timeline_empty() -> None:
    timeline = build_timeline(pd.DataFrame())
    assert timeline.empty
    assert "event_time" in timeline.columns


def test_build_summary() -> None:
    matches = make_matches()
    rejected = pd.DataFrame([{"value": "bad", "row_id": 10, "reason": "invalid"}])
    files = pd.DataFrame([
        {"filename": "dns.csv", "sha256": "a", "row_count": 8, "imported_at": "now"},
    ])
    summary = build_summary(matches, rejected, files)

    assert summary["total_matches"] == 2
    assert summary["unique_iocs_matched"] == 2
    assert summary["files_with_matches"] == 2
    assert summary["rejected_iocs"] == 1
    assert summary["matches_per_file"] == {"dns.csv": 1, "auth.csv": 1}
    assert summary["matches_per_type"] == {"domain": 1, "ipv4": 1}


def test_build_summary_empty() -> None:
    summary = build_summary(pd.DataFrame(), pd.DataFrame(), pd.DataFrame())
    assert summary["total_matches"] == 0
    assert summary["unique_iocs_matched"] == 0
    assert summary["matches_per_file"] == {}


def test_build_case_report() -> None:
    matches = make_matches()
    rejected = pd.DataFrame([{
        "value": "bad",
        "row_id": 10,
        "reason": "invalid",
    }])
    files = pd.DataFrame([{
        "filename": "dns.csv",
        "sha256": "abc123",
        "row_count": 8,
        "imported_at": "2026-10-10",
    }])

    report = build_case_report(matches, rejected, files, "NEXORA Test")
    assert report.startswith("# NEXORA Test")
    assert "Generated at:" in report
    assert "## Evidence Files" in report
    assert "## Findings" in report
    assert "## Rejected Indicators" in report
    assert "Matching is exact and offline only" in report


def test_build_case_report_empty() -> None:
    report = build_case_report(
        pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), "Empty Case"
    )
    assert "No findings." in report
    assert "No rejected indicators." in report
    assert "No evidence files registered." in report
