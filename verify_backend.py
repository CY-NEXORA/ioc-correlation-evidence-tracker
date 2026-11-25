"""Independent verification for the IOC tracker backend."""
import shutil
import tempfile
from pathlib import Path

from src.database import init_db, register_evidence_file
from src.importer import file_sha256
from src.matcher import run_correlation


IOC_PATH = "data/iocs.csv"
EVIDENCE_PATHS = [
    "data/dns_log.csv",
    "data/auth_log.csv",
    "data/proxy_log.csv",
    "data/endpoint_log.csv",
]

EXPECTED_MATCHES = {
    ("auth_log.csv", 2, "src_ip", "185.220.101.45", "2026-10-10 07:55:01"),
    ("auth_log.csv", 3, "src_ip", "185.220.101.45", "2026-10-10 07:55:04"),
    ("auth_log.csv", 4, "src_ip", "185.220.101.45", "2026-10-10 07:55:09"),
    ("auth_log.csv", 6, "src_ip", "10.66.6.6", "2026-10-10 08:31:50"),
    ("auth_log.csv", 8, "src_ip", "2001:db8::bad", "2026-10-10 08:41:00"),
    ("dns_log.csv", 3, "query", "EVIL-DOMAIN.COM", "2026-10-10 08:03:45"),
    ("dns_log.csv", 4, "query", "c2.badhost.org", "2026-10-10 08:05:02"),
    ("dns_log.csv", 4, "response_ip", "185.220.101.45", "2026-10-10 08:05:02"),
    ("dns_log.csv", 6, "query", "evil-domain.com.", "2026-10-10 08:09:33"),
    ("proxy_log.csv", 2, "url", "http://malware-site.net/payload.exe", "2026-10-10 08:14:50"),
    ("proxy_log.csv", 4, "host", "evil-domain.com", "2026-10-10 08:18:30"),
    ("endpoint_log.csv", 2, "file_md5", "44D88612FEA8A8F36DE82E1278ABB02F", "2026-10-10 08:15:30"),
    ("endpoint_log.csv", 4, "file_sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "2026-10-10 08:30:12"),
    ("endpoint_log.csv", 4, "sender_email", "phish@bad-mail.org", "2026-10-10 08:30:12"),
}


def run_checks() -> int:
    """Run the independent backend verification and return failures."""
    failures = 0
    passed_matches = 0

    conn = init_db(":memory:")
    try:
        matches = run_correlation(conn, IOC_PATH, EVIDENCE_PATHS)
        first_count = len(matches)

        actual = {
            (
                str(row["filename"]),
                int(row["row_id"]),
                str(row["matched_field"]),
                str(row["matched_value"]),
                str(row["event_time"]),
            )
            for _, row in matches.iterrows()
        }

        missing = EXPECTED_MATCHES - actual
        extra = actual - EXPECTED_MATCHES
        for expected in sorted(EXPECTED_MATCHES):
            if expected in actual:
                passed_matches += 1
            else:
                failures += 1
                print(f"FAIL: Missing expected match: {expected}")

        for unexpected in sorted(extra):
            failures += 1
            print(f"FAIL: Extra match: {unexpected}")

        if missing:
            failures += 1
            print(f"FAIL: {len(missing)} expected match(es) missing")
        if extra:
            failures += 1
            print(f"FAIL: {len(extra)} extra match(es) found")
        if first_count != 14:
            failures += 1
            print(f"FAIL: Expected 14 matches, found {first_count}")

        near_miss_values = {"185.220.101.46", "notbad-domain.com"}
        matched_values = set(actual_value[3] for actual_value in actual)
        for near_miss in near_miss_values:
            if near_miss in matched_values:
                failures += 1
                print(f"FAIL: Near-miss value matched: {near_miss}")

        run_correlation(conn, IOC_PATH, EVIDENCE_PATHS)
        rerun_count = len(run_correlation(conn, IOC_PATH, EVIDENCE_PATHS))
        if rerun_count != first_count:
            failures += 1
            print(f"FAIL: Duplicate matches after rerun: {rerun_count} matches")

        evidence_file_count = conn.execute("SELECT COUNT(*) FROM evidence_files").fetchone()[0]
        if evidence_file_count != len(EVIDENCE_PATHS):
            failures += 1
            print(f"FAIL: Expected {len(EVIDENCE_PATHS)} evidence records, found {evidence_file_count}")

        for evidence_path in EVIDENCE_PATHS:
            stored_hash = conn.execute(
                "SELECT sha256 FROM evidence_files WHERE filename = ?",
                (Path(evidence_path).name,),
            ).fetchone()
            calculated_hash = file_sha256(evidence_path)
            if stored_hash is None:
                failures += 1
                print(f"FAIL: No database hash for {evidence_path}")
            elif stored_hash[0] != calculated_hash:
                failures += 1
                print(f"FAIL: Hash mismatch for {evidence_path}")

        with tempfile.TemporaryDirectory() as temp_directory:
            temp_path = Path(temp_directory) / "dns_log.csv"
            shutil.copy2("data/dns_log.csv", temp_path)
            original_id = register_evidence_file(conn, str(temp_path), 8)
            with temp_path.open("a", encoding="utf-8") as file:
                file.write("2026-10-10 09:00:00,10.0.0.1,changed.example,A,10.0.0.2\n")
            changed_id = register_evidence_file(conn, str(temp_path), 9)
            if original_id == changed_id:
                failures += 1
                print("FAIL: Modified file received the same evidence file ID")

            temp_hashes = conn.execute(
                "SELECT sha256 FROM evidence_files WHERE filename = ?",
                ("dns_log.csv",),
            ).fetchall()
            if len(temp_hashes) < 2:
                failures += 1
                print("FAIL: Modified file was not registered as a new evidence record")

    finally:
        conn.close()

    print(f"Matched expected records: {passed_matches}/14")
    if failures == 0:
        print("14 of 14 checks passed")
    else:
        print(f"FAIL: {failures} verification issue(s) found")
    return failures


def main() -> None:
    """Run the standalone backend verifier."""
    raise SystemExit(1 if run_checks() else 0)


if __name__ == "__main__":
    main()
