"""Streamlit interface for the IOC Correlation and Incident Evidence Tracker."""
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from src.database import init_db
from src.importer import load_evidence_file, load_ioc_file
from src.matcher import run_correlation
from src.normalizer import normalize_ioc_dataframe
from src.report import (
    build_case_report,
    build_timeline,
    matches_to_csv,
    matches_to_json,
)


BUNDLED_IOC = "data/iocs.csv"
BUNDLED_EVIDENCE = [
    "data/dns_log.csv",
    "data/auth_log.csv",
    "data/proxy_log.csv",
    "data/endpoint_log.csv",
]


def initialize_session() -> None:
    """Initialize temporary storage and application state."""
    if "temp_directory" not in st.session_state:
        st.session_state.temp_directory = tempfile.TemporaryDirectory()
    if "upload_directory" not in st.session_state:
        st.session_state.upload_directory = Path(st.session_state.temp_directory.name)
    if "db_conn" not in st.session_state:
        db_path = Path(st.session_state.temp_directory.name) / "session.db"
        st.session_state.db_conn = init_db(str(db_path))
    if "correlation_done" not in st.session_state:
        st.session_state.correlation_done = False
    if "valid_iocs" not in st.session_state:
        st.session_state.valid_iocs = pd.DataFrame()
    if "rejected_iocs" not in st.session_state:
        st.session_state.rejected_iocs = pd.DataFrame()
    if "matches" not in st.session_state:
        st.session_state.matches = pd.DataFrame()


def reset_session() -> None:
    """Close the database and clear temporary session state."""
    conn = st.session_state.get("db_conn")
    if conn is not None:
        conn.close()
    temp_directory = st.session_state.get("temp_directory")
    if temp_directory is not None:
        temp_directory.cleanup()
    st.session_state.clear()
    st.rerun()


def save_uploaded_file(uploaded_file: object, directory: Path) -> Path:
    """Save one uploaded file into temporary storage."""
    destination = directory / uploaded_file.name
    destination.write_bytes(uploaded_file.getvalue())
    return destination


def validate_empty_and_columns(df: pd.DataFrame, file_name: str,
                               required_columns: list[str]) -> None:
    """Raise a friendly ValueError for common data mistakes."""
    if df.empty:
        raise ValueError(f"The file '{file_name}' is empty.")
    missing = [column for column in required_columns if column not in df.columns]
    if missing:
        raise ValueError(
            f"The file '{file_name}' is missing required column(s): {', '.join(missing)}"
        )


def load_bundled_files() -> tuple[Path, list[Path]]:
    """Copy bundled data paths into temporary storage."""
    directory = st.session_state.upload_directory
    ioc_path = directory / "iocs.csv"
    shutil.copy2(BUNDLED_IOC, ioc_path)

    evidence_paths = []
    for source_path in BUNDLED_EVIDENCE:
        destination = directory / Path(source_path).name
        shutil.copy2(source_path, destination)
        evidence_paths.append(destination)
    return ioc_path, evidence_paths


def get_files_dataframe(conn: sqlite3.Connection) -> pd.DataFrame:
    """Read registered evidence file records from SQLite."""
    return pd.read_sql_query(
        """SELECT filename, sha256, imported_at, row_count
           FROM evidence_files ORDER BY filename""",
        conn,
    )


def run_correlate(ioc_path: Path, evidence_paths: list[Path]) -> bool:
    """Run validation and correlation, storing results in session state."""
    try:
        ioc_df = load_ioc_file(str(ioc_path))
        validate_empty_and_columns(ioc_df, ioc_path.name, ["value"])
        valid, rejected = normalize_ioc_dataframe(ioc_df)

        for evidence_path in evidence_paths:
            evidence_df = load_evidence_file(str(evidence_path))
            validate_empty_and_columns(evidence_df, evidence_path.name, ["row_id"])

        conn = st.session_state.db_conn
        matches = run_correlation(conn, str(ioc_path), [str(path) for path in evidence_paths])
        st.session_state.valid_iocs = valid
        st.session_state.rejected_iocs = rejected
        st.session_state.matches = matches
        st.session_state.correlation_done = True
        st.session_state.files_df = get_files_dataframe(conn)
        return True
    except (ValueError, pd.errors.EmptyDataError, pd.errors.ParserError) as error:
        st.error(str(error))
        return False
    except sqlite3.Error:
        st.error("The temporary database could not complete the operation.")
        return False


def render_import_tab() -> None:
    """Render IOC validation results."""
    valid = st.session_state.valid_iocs
    rejected = st.session_state.rejected_iocs
    st.metric("Valid IOCs", len(valid))
    st.metric("Rejected IOCs", len(rejected))

    if valid.empty:
        st.info("No valid IOCs available yet.")
    else:
        st.dataframe(valid[["norm_value", "norm_type", "source"]], use_container_width=True)

    if rejected.empty:
        st.info("No rejected IOCs available yet.")
    else:
        st.dataframe(rejected[["row_id", "value", "reason"]], use_container_width=True)


def render_results_tab() -> None:
    """Render filters and the filtered match table."""
    if not st.session_state.correlation_done:
        st.info("Upload files and click Run correlation")
        return

    matches = st.session_state.matches
    col1, col2, col3 = st.columns(3)
    col1.metric("Total matches", len(matches))
    col2.metric("Unique IOCs matched", matches["ioc_value"].nunique() if not matches.empty else 0)
    col3.metric("Files with matches", matches["filename"].nunique() if not matches.empty else 0)

    if matches.empty:
        st.warning("No exact matches were found.")
        return

    ioc_types = st.multiselect("IOC type", sorted(matches["ioc_type"].dropna().unique()))
    filenames = st.multiselect("Source file", sorted(matches["filename"].dropna().unique()))
    search_text = st.text_input("Search IOC value")

    filtered = matches.copy()
    if ioc_types:
        filtered = filtered[filtered["ioc_type"].isin(ioc_types)]
    if filenames:
        filtered = filtered[filtered["filename"].isin(filenames)]
    if search_text:
        filtered = filtered[
            filtered["ioc_value"].astype(str).str.contains(search_text, case=False, regex=False)
        ]

    columns = [
        "ioc_value", "ioc_type", "source", "filename", "row_id",
        "event_time", "matched_field", "matched_value",
    ]
    st.dataframe(filtered[columns], use_container_width=True)


def render_timeline_tab() -> None:
    """Render timeline and file match chart."""
    if not st.session_state.correlation_done:
        st.info("Upload files and click Run correlation")
        return

    matches = st.session_state.matches
    timeline = build_timeline(matches)
    st.dataframe(timeline, use_container_width=True)

    if timeline.empty:
        st.warning("No timeline entries available.")
        return

    counts = timeline["filename"].value_counts().sort_index()
    st.bar_chart(counts)


def render_integrity_tab() -> None:
    """Render evidence integrity records."""
    if not st.session_state.correlation_done:
        st.info("Upload files and click Run correlation")
        return

    files_df = st.session_state.files_df
    st.dataframe(files_df, use_container_width=True)
    st.caption("The SHA-256 hash proves that registered file bytes were not modified after import.")


def render_export_tab(case_title: str) -> None:
    """Render download buttons for all export formats."""
    if not st.session_state.correlation_done:
        st.info("Upload files and click Run correlation")
        return

    matches = st.session_state.matches
    rejected = st.session_state.rejected_iocs
    files_df = st.session_state.files_df

    st.download_button(
        "Download CSV",
        data=matches_to_csv(matches),
        file_name="ioc_matches.csv",
        mime="text/csv",
    )
    st.download_button(
        "Download JSON",
        data=matches_to_json(matches),
        file_name="ioc_matches.json",
        mime="application/json",
    )
    report = build_case_report(matches, rejected, files_df, case_title)
    st.download_button(
        "Download Markdown Report",
        data=report,
        file_name="incident_report.md",
        mime="text/markdown",
    )


def main() -> None:
    """Render the Streamlit application."""
    st.set_page_config(
        page_title="IOC Correlation and Incident Evidence Tracker - NEXORA",
        layout="wide",
    )
    st.title("IOC Correlation and Incident Evidence Tracker - NEXORA")
    initialize_session()

    st.sidebar.header("Case Inputs")
    ioc_upload = st.sidebar.file_uploader("IOC file", type=["csv", "json"])
    evidence_uploads = st.sidebar.file_uploader(
        "Evidence files", type=["csv", "json"], accept_multiple_files=True
    )
    use_bundled = st.sidebar.button("Use bundled sample data")
    case_title = st.sidebar.text_input("Case title", value="NEXORA IOC Incident Report")

    if st.sidebar.button("Reset session"):
        reset_session()

    if use_bundled:
        ioc_path, evidence_paths = load_bundled_files()
        st.session_state.pending_ioc_path = ioc_path
        st.session_state.pending_evidence_paths = evidence_paths
        st.sidebar.success("Bundled sample data loaded.")

    ioc_path = st.session_state.get("pending_ioc_path")
    evidence_paths = st.session_state.get("pending_evidence_paths", [])

    if ioc_upload is not None:
        ioc_path = save_uploaded_file(ioc_upload, st.session_state.upload_directory)
        st.session_state.pending_ioc_path = ioc_path
    if evidence_uploads:
        evidence_paths = [
            save_uploaded_file(upload, st.session_state.upload_directory)
            for upload in evidence_uploads
        ]
        st.session_state.pending_evidence_paths = evidence_paths

    if st.sidebar.button("Run correlation"):
        if ioc_path is None:
            st.error("Upload or bundle an IOC file before running correlation.")
        elif not evidence_paths:
            st.error("Upload or bundle at least one evidence file before running correlation.")
        else:
            with st.spinner("Running correlation..."):
                run_correlate(ioc_path, evidence_paths)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "1. Import and Validation",
        "2. Correlation Results",
        "3. Incident Timeline",
        "4. Evidence Integrity",
        "5. Export",
    ])
    with tab1:
        render_import_tab()
    with tab2:
        render_results_tab()
    with tab3:
        render_timeline_tab()
    with tab4:
        render_integrity_tab()
    with tab5:
        render_export_tab(case_title)


if __name__ == "__main__":
    main()
