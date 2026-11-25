import sqlite3
from pathlib import Path
from typing import Iterable

import pandas as pd

from src.database import get_matches, register_evidence_file, save_iocs, save_matches
from src.importer import load_evidence_file, load_ioc_file
from src.normalizer import normalize_indicator, normalize_ioc_dataframe


FIELD_MAP = {
    "ipv4": ["src_ip", "dst_ip", "client_ip", "response_ip"],
    "ipv6": ["src_ip", "dst_ip", "client_ip", "response_ip"],
    "domain": ["query", "host"],
    "url": ["url"],
    "md5": ["file_md5"],
    "sha1": ["file_sha1"],
    "sha256": ["file_sha256"],
    "email": ["sender_email"],
}


def find_matches(valid_iocs_df: pd.DataFrame, evidence_df: pd.DataFrame,
                 source_name: str) -> pd.DataFrame:
    """Find exact IOC matches in evidence fields allowed for each IOC type."""
    ioc_lookup = {
        (row["norm_value"], row["norm_type"])
        for row in valid_iocs_df.to_dict("records")
    }

    # Only scan the columns that at least one loaded IOC type can match against.
    fields_to_scan = sorted({
        field for _, ioc_type in ioc_lookup for field in FIELD_MAP.get(ioc_type, [])
    })

    matches = []
    for evidence_row in evidence_df.to_dict("records"):
        row_id = int(evidence_row["row_id"])
        timestamp = evidence_row.get("timestamp", "")
        event_time = "" if pd.isna(timestamp) else str(timestamp)

        for field in fields_to_scan:
            raw_value = evidence_row.get(field)
            if raw_value is None or pd.isna(raw_value) or str(raw_value).strip() == "":
                continue

            indicator = normalize_indicator(raw_value)
            if (indicator.valid
                    and field in FIELD_MAP.get(indicator.ioc_type, [])
                    and (indicator.value, indicator.ioc_type) in ioc_lookup):
                matches.append({
                    "ioc_value": indicator.value,
                    "ioc_type": indicator.ioc_type,
                    "source_file": source_name,
                    "row_id": row_id,
                    "event_time": event_time,
                    "matched_field": field,
                    "matched_value": str(raw_value),
                })

    return pd.DataFrame(matches, columns=[
        "ioc_value", "ioc_type", "source_file", "row_id",
        "event_time", "matched_field", "matched_value",
    ])


def run_correlation(conn: sqlite3.Connection, ioc_path: str,
                    evidence_paths: Iterable[str]) -> pd.DataFrame:
    """Load IOCs and evidence, correlate matches, and return stored results."""
    ioc_df = load_ioc_file(ioc_path)
    valid_iocs, rejected_iocs = normalize_ioc_dataframe(ioc_df)
    save_iocs(conn, valid_iocs, rejected_iocs)

    file_ids = []
    for evidence_path in evidence_paths:
        evidence_df = load_evidence_file(evidence_path)
        file_id = register_evidence_file(conn, evidence_path, len(evidence_df))
        file_ids.append(file_id)
        source_name = Path(evidence_path).name
        matches_df = find_matches(valid_iocs, evidence_df, source_name)
        save_matches(conn, matches_df, file_id)

    return _matches_for_current_run(conn, valid_iocs, file_ids)


def _matches_for_current_run(conn: sqlite3.Connection, valid_iocs: pd.DataFrame,
                             file_ids: list[int]) -> pd.DataFrame:
    """Return only matches for the IOC list and evidence files used in this run."""
    stored = get_matches(conn, file_ids=file_ids)
    if stored.empty or valid_iocs.empty:
        return stored.iloc[0:0].reset_index(drop=True)
    current = set(zip(valid_iocs["norm_value"], valid_iocs["norm_type"]))
    keep = [pair in current for pair in zip(stored["ioc_value"], stored["ioc_type"])]
    return stored[keep].reset_index(drop=True)
