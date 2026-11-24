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

    matches = []
    for evidence_row in evidence_df.to_dict("records"):
        row_id = int(evidence_row["row_id"])
        timestamp = evidence_row.get("timestamp", "")
        event_time = "" if pd.isna(timestamp) else str(timestamp)

        for ioc_value, ioc_type in ioc_lookup:
            for field in FIELD_MAP.get(ioc_type, []):
                if field not in evidence_row:
                    continue
                raw_value = evidence_row[field]
                if pd.isna(raw_value) or str(raw_value).strip() == "":
                    continue

                indicator = normalize_indicator(raw_value)
                if (indicator.valid
                        and indicator.value == ioc_value
                        and indicator.ioc_type == ioc_type):
                    matches.append({
                        "ioc_value": ioc_value,
                        "ioc_type": ioc_type,
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

    for evidence_path in evidence_paths:
        evidence_df = load_evidence_file(evidence_path)
        register_evidence_file(conn, evidence_path, len(evidence_df))
        source_name = Path(evidence_path).name
        matches_df = find_matches(valid_iocs, evidence_df, source_name)
        save_matches(conn, matches_df)

    return get_matches(conn)
