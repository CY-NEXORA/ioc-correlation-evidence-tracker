"""Run a sample IOC correlation and print the matches."""
from src.database import init_db
from src.matcher import run_correlation


DB_PATH = "data/demo.db"
IOC_PATH = "data/iocs.csv"
EVIDENCE_PATHS = [
    "data/dns_log.csv",
    "data/auth_log.csv",
    "data/proxy_log.csv",
    "data/endpoint_log.csv",
]


def main() -> None:
    """Run the demonstration against the demo database."""
    conn = init_db(DB_PATH)
    try:
        matches = run_correlation(conn, IOC_PATH, EVIDENCE_PATHS)
        print(matches.to_string(index=False))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
