import json
from datetime import datetime, timezone

import pandas as pd


def matches_to_csv(matches_df: pd.DataFrame) -> str:
    """Convert matches into CSV text."""
    return matches_df.to_csv(index=False)


def matches_to_json(matches_df: pd.DataFrame) -> str:
    """Convert matches into an indented JSON record list."""
    return json.dumps(matches_df.to_dict("records"), indent=2)


def build_timeline(matches_df: pd.DataFrame) -> pd.DataFrame:
    """Build a timeline sorted by event time."""
    columns = [
        "event_time", "ioc_value", "ioc_type", "filename",
        "row_id", "matched_field",
    ]
    if matches_df.empty:
        return pd.DataFrame(columns=columns)

    timeline = matches_df[[
        "event_time", "ioc_value", "ioc_type", "filename",
        "row_id", "matched_field",
    ]].copy()
    return timeline.sort_values("event_time", kind="stable").reset_index(drop=True)


def build_summary(matches_df: pd.DataFrame, rejected_df: pd.DataFrame,
                  files_df: pd.DataFrame) -> dict:
    """Build summary counts and breakdowns for a correlation run."""
    matches_per_file = {}
    matches_per_type = {}
    if not matches_df.empty:
        matches_per_file = matches_df["filename"].value_counts().to_dict()
        matches_per_type = matches_df["ioc_type"].value_counts().to_dict()

    files_with_matches = len(matches_per_file)
    if not matches_df.empty:
        unique_iocs = matches_df["ioc_value"].nunique()
    else:
        unique_iocs = 0

    return {
        "total_matches": int(len(matches_df)),
        "unique_iocs_matched": int(unique_iocs),
        "files_with_matches": int(files_with_matches),
        "rejected_iocs": int(len(rejected_df)),
        "matches_per_file": matches_per_file,
        "matches_per_type": matches_per_type,
    }


def build_case_report(matches_df: pd.DataFrame, rejected_df: pd.DataFrame,
                      files_df: pd.DataFrame, case_title: str) -> str:
    """Build a Markdown incident evidence report."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    summary = build_summary(matches_df, rejected_df, files_df)

    lines = [
        f"# {case_title}", "",
        f"Generated at: {generated_at}", "",
        "## Summary", "",
        f"- Total matches: {summary['total_matches']}",
        f"- Unique IOCs matched: {summary['unique_iocs_matched']}",
        f"- Files with matches: {summary['files_with_matches']}",
        f"- Rejected IOCs: {summary['rejected_iocs']}",
        "",
        "### Matches per file", "",
    ]

    if summary["matches_per_file"]:
        for filename, count in summary["matches_per_file"].items():
            lines.append(f"- {filename}: {count}")
    else:
        lines.append("- None")

    lines.extend(["", "### Matches per type", ""])
    if summary["matches_per_type"]:
        for ioc_type, count in summary["matches_per_type"].items():
            lines.append(f"- {ioc_type}: {count}")
    else:
        lines.append("- None")

    lines.extend(["", "## Evidence Files", ""])
    if files_df.empty:
        lines.append("No evidence files registered.")
    else:
        for row in files_df.to_dict("records"):
            lines.extend([
                f"### {row.get('filename', '')}",
                f"- SHA-256: {row.get('sha256', '')}",
                f"- Row count: {row.get('row_count', 0)}",
                f"- Imported at: {row.get('imported_at', '')}",
                "",
            ])

    lines.extend(["## Findings", ""])
    if matches_df.empty:
        lines.append("No findings.")
    else:
        for ioc_value in sorted(matches_df["ioc_value"].dropna().unique(), key=str):
            ioc_rows = matches_df[matches_df["ioc_value"] == ioc_value]
            ioc_type = str(ioc_rows.iloc[0]["ioc_type"])
            lines.append(f"### {ioc_value} ({ioc_type})")
            for row in ioc_rows.to_dict("records"):
                lines.append(
                    f"- File: {row.get('filename', '')}; row ID: {row.get('row_id', '')}; "
                    f"time: {row.get('event_time', '')}; field: {row.get('matched_field', '')}"
                )
            lines.append("")

    lines.extend(["## Rejected Indicators", ""])
    if rejected_df.empty:
        lines.append("No rejected indicators.")
    else:
        for row in rejected_df.to_dict("records"):
            lines.append(
                f"- Value: {row.get('value', '')}; row: {row.get('row_id', '')}; "
                f"reason: {row.get('reason', '')}"
            )

    lines.extend([
        "", "## Limitations", "",
        "Matching is exact and offline only. It does not provide fuzzy or network-based attribution.",
    ])
    return "\n".join(lines)
