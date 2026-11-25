"""
Independent backend check.

Compares what the backend produces against a hand-verified list of the 14 expected
matches for the bundled sample data. It does not use the project's own tests.

Run from the project root:  python verify_backend.py
"""
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile

from src.database import init_db
from src.matcher import run_correlation
from src.normalizer import normalize_indicator

IOC_FILE = "data/iocs.csv"
LOGS = ["data/dns_log.csv", "data/auth_log.csv", "data/proxy_log.csv", "data/endpoint_log.csv"]

# (file name, row id, matched field, matched value, event time) - checked by hand
EXPECTED = {
    ("dns_log.csv", 3, "query", "evil-domain.com", "2026-10-10 08:03:45"),
    ("dns_log.csv", 4, "query", "c2.badhost.org", "2026-10-10 08:05:02"),
    ("dns_log.csv", 4, "response_ip", "185.220.101.45", "2026-10-10 08:05:02"),
    ("dns_log.csv", 6, "query", "evil-domain.com", "2026-10-10 08:09:33"),
    ("auth_log.csv", 2, "src_ip", "185.220.101.45", "2026-10-10 07:55:01"),
    ("auth_log.csv", 3, "src_ip", "185.220.101.45", "2026-10-10 07:55:04"),
    ("auth_log.csv", 4, "src_ip", "185.220.101.45", "2026-10-10 07:55:09"),
    ("auth_log.csv", 6, "src_ip", "10.66.6.6", "2026-10-10 08:31:50"),
    ("auth_log.csv", 8, "src_ip", "2001:db8::bad", "2026-10-10 08:41:00"),
    ("proxy_log.csv", 2, "url", "http://malware-site.net/payload.exe", "2026-10-10 08:14:50"),
    ("proxy_log.csv", 4, "host", "evil-domain.com", "2026-10-10 08:18:30"),
    ("endpoint_log.csv", 2, "file_md5", "44d88612fea8a8f36de82e1278abb02f", "2026-10-10 08:15:30"),
    ("endpoint_log.csv", 4, "file_sha256",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "2026-10-10 08:30:12"),
    ("endpoint_log.csv", 4, "sender_email", "phish@bad-mail.org", "2026-10-10 08:30:12"),
}

# Values that look similar to IOCs but must NOT be matched
MUST_NOT_MATCH = ["185.220.101.46", "notbad-domain.com", "malware-site.net"]

results = []


def check(name: str, passed: bool, detail: str = "") -> None:
    results.append(passed)
    print(f"[{'PASS' if passed else 'FAIL'}] {name}" + (f"  ->  {detail}" if detail and not passed else ""))


def to_tuples(df) -> set:
    return {
        (os.path.basename(str(r.filename)), int(r.row_id), r.matched_field,
         normalize_indicator(r.matched_value).value, str(r.event_time))
        for r in df.itertuples()
    }


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def count(conn, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def main() -> int:
    workdir = tempfile.mkdtemp()
    db_path = os.path.join(workdir, "verify.db")
    conn = init_db(db_path)

    # 1. Full run
    df = run_correlation(conn, IOC_FILE, LOGS)
    got = to_tuples(df)
    check("Total number of matches is 14", len(df) == 14, f"got {len(df)}")
    check("No expected match is missing", not (EXPECTED - got), f"missing: {sorted(EXPECTED - got)}")
    check("No unexpected extra match", not (got - EXPECTED), f"extra: {sorted(got - EXPECTED)}")

    # 2. Near-misses must not appear
    matched_values = set(df["matched_value"].astype(str))
    for value in MUST_NOT_MATCH:
        check(f"'{value}' is not matched", value not in matched_values)

    # 3. IOC table and rejected rows (the backend keeps the raw log value as evidence)
    check("9 unique valid IOCs stored", count(conn, "iocs") == 9, f"got {count(conn, 'iocs')}")
    check("5 rejected IOC rows stored", count(conn, "rejected_iocs") == 5, f"got {count(conn, 'rejected_iocs')}")

    # 4. Evidence hashes recomputed independently
    stored = {os.path.basename(f): h for f, h in conn.execute("SELECT filename, sha256 FROM evidence_files")}
    hashes_ok = all(stored.get(os.path.basename(p)) == sha256_of(p) for p in LOGS)
    check("Stored SHA-256 equals an independent hash of every log file", hashes_ok)
    check("4 evidence files registered", count(conn, "evidence_files") == 4, f"got {count(conn, 'evidence_files')}")

    # 5. Running again must not create duplicates
    df2 = run_correlation(conn, IOC_FILE, LOGS)
    check("Second run keeps 14 matches (no duplicates)", len(df2) == 14, f"got {len(df2)}")
    check("Second run keeps 4 evidence files", count(conn, "evidence_files") == 4)
    check("Second run keeps 9 IOCs", count(conn, "iocs") == 9)
    check("Second run keeps 5 rejected IOC rows (no duplicates)", count(conn, "rejected_iocs") == 5,
          f"got {count(conn, 'rejected_iocs')}")

    # 6. A modified file must be registered as a different file (integrity)
    tampered = os.path.join(workdir, "dns_log.csv")
    shutil.copy("data/dns_log.csv", tampered)
    with open(tampered, "a", encoding="utf-8") as f:
        f.write("2026-10-10 09:00:00,192.168.1.99,extra.example.org,A,198.51.100.9\n")
    run_correlation(conn, IOC_FILE, [tampered])
    check("A modified copy of a log gets its own record (hash differs)", count(conn, "evidence_files") == 5,
          f"got {count(conn, 'evidence_files')}")

    conn.close()
    shutil.rmtree(workdir, ignore_errors=True)

    print(f"\n{sum(results)} of {len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
