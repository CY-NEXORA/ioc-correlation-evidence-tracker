import time

import pandas as pd

from src.database import init_db
from src.matcher import run_correlation
from src.normalizer import normalize_ioc_dataframe

IOC_HEADER = "value,type,source,added_date\n"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_same_filename_different_content_keeps_evidence_separate(tmp_path) -> None:
    ioc = write(tmp_path / "iocs.csv", IOC_HEADER + "203.0.113.10,ip,F,2026-01-01\n203.0.113.11,ip,F,2026-01-01\n")
    file_a = write(tmp_path / "hostA" / "log.csv", "timestamp,src_ip\n2026-01-01 10:00:00,203.0.113.10\n")
    file_b = write(tmp_path / "hostB" / "log.csv", "timestamp,src_ip\n2026-01-01 11:00:00,203.0.113.11\n")
    conn = init_db(str(tmp_path / "t.db"))

    matches = run_correlation(conn, ioc, [file_a, file_b])

    assert len(matches) == 2
    links = conn.execute(
        "SELECT f.sha256, i.value FROM matches m JOIN iocs i ON i.id = m.ioc_id "
        "JOIN evidence_files f ON f.id = m.file_id ORDER BY i.value").fetchall()
    assert len(links) == 2
    assert links[0][0] != links[1][0]


def test_new_ioc_list_does_not_show_matches_of_the_old_list(tmp_path) -> None:
    first = write(tmp_path / "i1.csv", IOC_HEADER + "203.0.113.10,ip,F,2026-01-01\n")
    second = write(tmp_path / "i2.csv", IOC_HEADER + "203.0.113.11,ip,F,2026-01-01\n")
    log = write(tmp_path / "l.csv", "timestamp,src_ip\n2026-01-01 10:00:00,203.0.113.10\n2026-01-01 11:00:00,203.0.113.11\n")
    conn = init_db(str(tmp_path / "t.db"))

    run_correlation(conn, first, [log])
    matches = run_correlation(conn, second, [log])

    assert list(matches["ioc_value"]) == ["203.0.113.11"]


def test_rejected_iocs_are_not_duplicated_on_rerun(tmp_path) -> None:
    ioc = write(tmp_path / "iocs.csv", IOC_HEADER + "999.1.1.1,ip,F,2026-01-01\n")
    log = write(tmp_path / "l.csv", "timestamp,src_ip\n2026-01-01 10:00:00,1.1.1.1\n")
    conn = init_db(str(tmp_path / "t.db"))

    run_correlation(conn, ioc, [log])
    run_correlation(conn, ioc, [log])

    assert conn.execute("SELECT COUNT(*) FROM rejected_iocs").fetchone()[0] == 1


def test_all_digit_hash_keeps_leading_zeros(tmp_path) -> None:
    value = "00112233445566778899001122334455"
    ioc = write(tmp_path / "iocs.csv", IOC_HEADER + f"{value},md5,F,2026-01-01\n")
    log = write(tmp_path / "l.csv", f"timestamp,file_md5\n2026-01-01 10:00:00,{value}\n")
    conn = init_db(str(tmp_path / "t.db"))

    matches = run_correlation(conn, ioc, [log])

    assert len(matches) == 1
    assert conn.execute("SELECT COUNT(*) FROM rejected_iocs").fetchone()[0] == 0


def test_empty_type_cell_means_no_declared_type() -> None:
    frame = pd.DataFrame({"value": ["1.2.3.4"], "type": [None], "source": ["F"]})

    valid, rejected = normalize_ioc_dataframe(frame)

    assert len(valid) == 1 and rejected.empty


def test_matching_is_fast_on_larger_input(tmp_path) -> None:
    iocs = IOC_HEADER + "".join(f"evil{i}.com,domain,F,2026-01-01\n" for i in range(500))
    rows = "timestamp,src_ip,query\n" + "".join(
        f"2026-01-01 10:00:00,192.168.{i % 250}.{i % 200},site{i}.example.com\n" for i in range(5000))
    conn = init_db(str(tmp_path / "t.db"))

    start = time.time()
    run_correlation(conn, write(tmp_path / "i.csv", iocs), [write(tmp_path / "l.csv", rows)])

    assert time.time() - start < 10
