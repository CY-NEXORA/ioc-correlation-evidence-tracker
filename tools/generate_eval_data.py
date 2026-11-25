"""
Generate a larger synthetic evaluation dataset together with its ground truth.

Evidence is planted by construction, so the correct answer is known in advance and does not
depend on the matcher under test. Hard negatives (near-misses and wrong-field values) are
planted too, so false positives can be measured.

Run from the project root:  python -m tools.generate_eval_data
Output: data/eval/
"""
import csv
import ipaddress
import random
from datetime import datetime, timedelta
from itertools import cycle
from pathlib import Path

SEED = 5010
OUT_DIR = Path("data/eval")
BENIGN_ROWS = 250
START_TIME = datetime(2026, 10, 10, 8, 0, 0)

rng = random.Random(SEED)


def hex_string(length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


# ------------------------------------------------------------------ IOC sets (canonical form)
IPV4 = [f"203.0.113.{n}" for n in range(10, 25)]
IPV6 = ["2001:db8::a1", "2001:db8::a2", "2001:db8::a3"]
DOMAIN_WORDS = ["evil-login", "update-check", "secure-pay", "cdn-fast", "mail-verify", "docs-share",
                "vpn-portal", "free-gift", "track-parcel", "bank-alert", "cloud-sync", "app-store-x"]
DOMAINS = [f"{w}.{t}" for w, t in zip(DOMAIN_WORDS, cycle(["com", "net", "org", "info"]))]
URL_HOSTS = ["dl-tools.com", "patch-now.xyz", "invoice-view.com", "resume-open.xyz",
             "pkg-fetch.com", "img-host.xyz", "file-drop.com", "setup-win.xyz"]
URLS = [f"http://{h}/dl/setup{i}.exe" for i, h in enumerate(URL_HOSTS)]
MD5 = [hex_string(32) for _ in range(8)]
SHA1 = [hex_string(40) for _ in range(6)]
SHA256 = [hex_string(64) for _ in range(8)]
EMAILS = [f"user{i}@mail-evil-{i}.org" for i in range(8)]

ALL_HASHES = set(MD5 + SHA1 + SHA256)


# ------------------------------------------------------------------ messy IOC file
def messy_ioc_rows() -> list:
    """Return IOC file rows with realistic formatting problems."""
    rows = []

    def add(value: str, declared: str, source: str) -> None:
        rows.append({"value": value, "type": declared, "source": source, "added_date": "2026-10-01"})

    for ip in IPV4:
        add(ip, "ip", "FeedA")
    for i, ip in enumerate(IPV6):
        add(ipaddress.ip_address(ip).exploded.upper() if i == 0 else ip, "ip", "FeedA")
    for i, d in enumerate(DOMAINS):
        forms = [d.upper(), d + ".", d.replace(".", "[.]"), f"  {d}  "]
        add(forms[i % 4], "domain", "FeedB")
    for i, u in enumerate(URLS):
        host = URL_HOSTS[i]
        add(u.replace("http://", "hxxp://").replace(host, host.replace(".", "[.]")) if i % 2 == 0 else u,
            "url", "FeedB")
    for i, h in enumerate(MD5):
        add(h.upper() if i % 2 else h, "md5", "FeedC")
    for i, h in enumerate(SHA1):
        add(h.upper() if i % 2 else h, "sha1", "FeedC")
    for i, h in enumerate(SHA256):
        add(h.upper() if i % 2 else h, "sha256", "FeedC")
    for i, e in enumerate(EMAILS):
        add(e.upper() if i % 2 else e, "email", "FeedC")

    # duplicates after normalisation
    add(IPV4[0], "ip", "FeedD")
    add(DOMAINS[1].upper(), "domain", "FeedD")
    add(MD5[0].upper(), "md5", "FeedD")
    # invalid rows
    add("999.1.1.1", "ip", "BadFeed")
    add("bad domain", "domain", "BadFeed")
    add("abc123", "md5", "BadFeed")
    add("", "domain", "BadFeed")
    add(DOMAINS[2], "ip", "BadFeed")  # declared type does not match

    rng.shuffle(rows)
    return rows


# ------------------------------------------------------------------ surface variants
def domain_variant(domain: str):
    kind = rng.choice(["exact", "upper", "trailing_dot", "capitalized"])
    text = {"exact": domain, "upper": domain.upper(), "trailing_dot": domain + ".",
            "capitalized": domain.capitalize()}[kind]
    return text, kind


def hash_variant(value: str):
    return (value.upper(), "upper_hash") if rng.random() < 0.5 else (value, "exact")


def email_variant(value: str):
    return (value.upper(), "upper_email") if rng.random() < 0.5 else (value, "exact")


def ip_variant(value: str):
    if ":" in value and rng.random() < 0.5:
        return ipaddress.ip_address(value).exploded.upper(), "expanded_ipv6"
    return value, "exact"


def url_variant(value: str):
    if rng.random() < 0.5:
        rest = value[len("http://"):]
        host, _, path = rest.partition("/")
        return f"HTTP://{host.upper()}/{path}", "upper_host_url"
    return value, "exact"


def near_ip() -> str:
    return f"203.0.113.{rng.randint(25, 60)}"  # never an IOC


def near_domain(domain: str):
    kind = rng.choice(["subdomain", "prefix", "suffix_tld"])
    text = {"subdomain": "www." + domain, "prefix": "x" + domain, "suffix_tld": domain + ".au"}[kind]
    return text, kind


def off_by_one(value: str) -> str:
    last = "0" if value[-1] != "0" else "1"
    return value[:-1] + last


# ------------------------------------------------------------------ row model
def new_row(columns, **values) -> dict:
    cells = {c: "" for c in columns}
    cells.update(values)
    return {"cells": cells, "truth": [], "neg": []}


def truth(row, field, ioc_value, ioc_type, category) -> None:
    row["truth"].append((field, ioc_value, ioc_type, category))


def negative(row, field, kind) -> None:
    row["neg"].append((field, kind))


def benign_ip() -> str:
    return f"192.168.{rng.randint(0, 5)}.{rng.randint(2, 250)}"


def benign_domain() -> str:
    return f"site{rng.randint(1, 400)}.example.com"


def benign_public_ip() -> str:
    return f"198.51.100.{rng.randint(1, 250)}"


# ------------------------------------------------------------------ log builders
DNS_COLS = ["timestamp", "src_ip", "query", "record_type", "response_ip"]
AUTH_COLS = ["timestamp", "host", "username", "src_ip", "event", "status"]
PROXY_COLS = ["timestamp", "client_ip", "host", "url", "bytes"]
ENDPOINT_COLS = ["timestamp", "hostname", "file_name", "file_md5", "file_sha1", "file_sha256", "sender_email"]


def build_dns() -> list:
    rows = [new_row(DNS_COLS, src_ip=benign_ip(), query=benign_domain(), record_type="A",
                    response_ip=benign_public_ip()) for _ in range(BENIGN_ROWS)]
    for _ in range(20):  # domain IOC in query
        d = rng.choice(DOMAINS)
        text, kind = domain_variant(d)
        r = new_row(DNS_COLS, src_ip=benign_ip(), query=text, record_type="A", response_ip=benign_public_ip())
        truth(r, "query", d, "domain", kind)
        rows.append(r)
    for _ in range(10):  # IP IOC in response_ip
        ip = rng.choice(IPV4)
        r = new_row(DNS_COLS, src_ip=benign_ip(), query=benign_domain(), record_type="A", response_ip=ip)
        truth(r, "response_ip", ip, "ipv4", "exact")
        rows.append(r)
    for _ in range(5):  # domain and IP in the same row
        d, ip = rng.choice(DOMAINS), rng.choice(IPV4)
        text, kind = domain_variant(d)
        r = new_row(DNS_COLS, src_ip=benign_ip(), query=text, record_type="A", response_ip=ip)
        truth(r, "query", d, "domain", kind)
        truth(r, "response_ip", ip, "ipv4", "exact")
        rows.append(r)
    for _ in range(15):  # near-miss domains
        text, kind = near_domain(rng.choice(DOMAINS))
        r = new_row(DNS_COLS, src_ip=benign_ip(), query=text, record_type="A", response_ip=benign_public_ip())
        negative(r, "query", kind)
        rows.append(r)
    for _ in range(8):  # near-miss IPs
        r = new_row(DNS_COLS, src_ip=benign_ip(), query=benign_domain(), record_type="A", response_ip=near_ip())
        negative(r, "response_ip", "near_ip")
        rows.append(r)
    return rows


def build_auth() -> list:
    rows = [new_row(AUTH_COLS, host="srv-web01", username=rng.choice(["admin", "sara", "mona", "hassan"]),
                    src_ip=benign_ip(), event="ssh_login", status=rng.choice(["success", "failed"]))
            for _ in range(BENIGN_ROWS)]
    for _ in range(25):  # IP IOC as source
        ip = rng.choice(IPV4 + IPV6)
        text, kind = ip_variant(ip)
        r = new_row(AUTH_COLS, host="srv-web01", username=rng.choice(["admin", "root"]), src_ip=text,
                    event="ssh_login", status="failed")
        truth(r, "src_ip", ip, "ipv6" if ":" in ip else "ipv4", kind)
        rows.append(r)
    for _ in range(10):
        r = new_row(AUTH_COLS, host="srv-web01", username="admin", src_ip=near_ip(), event="ssh_login",
                    status="failed")
        negative(r, "src_ip", "near_ip")
        rows.append(r)
    for _ in range(5):  # domain IOC in a field it must not be matched against
        r = new_row(AUTH_COLS, host="srv-web01", username=rng.choice(DOMAINS), src_ip=benign_ip(),
                    event="ssh_login", status="failed")
        negative(r, "username", "wrong_field")
        rows.append(r)
    return rows


def build_proxy() -> list:
    rows = []
    for _ in range(BENIGN_ROWS):
        d = benign_domain()
        rows.append(new_row(PROXY_COLS, client_ip=benign_ip(), host=d, url=f"https://{d}/page{rng.randint(1, 99)}",
                            bytes=str(rng.randint(200, 90000))))
    for _ in range(15):  # URL IOC in url
        u = rng.choice(URLS)
        text, kind = url_variant(u)
        r = new_row(PROXY_COLS, client_ip=benign_ip(), host=benign_domain(), url=text, bytes="4096")
        truth(r, "url", u, "url", kind)
        rows.append(r)
    for _ in range(12):  # domain IOC in host
        d = rng.choice(DOMAINS)
        text, kind = domain_variant(d)
        r = new_row(PROXY_COLS, client_ip=benign_ip(), host=text, url=f"https://benign-path.example.com/{rng.randint(1, 9)}",
                    bytes="2048")
        truth(r, "host", d, "domain", kind)
        rows.append(r)
    for _ in range(6):  # IP IOC as client
        ip = rng.choice(IPV4)
        r = new_row(PROXY_COLS, client_ip=ip, host=benign_domain(), url="https://news.example.com/today", bytes="1024")
        truth(r, "client_ip", ip, "ipv4", "exact")
        rows.append(r)
    for _ in range(8):  # same host as a URL IOC but a different path
        u = rng.choice(URLS)
        host = u[len("http://"):].split("/")[0]
        r = new_row(PROXY_COLS, client_ip=benign_ip(), host=benign_domain(), url=f"http://{host}/other/file.bin", bytes="512")
        negative(r, "url", "url_other_path")
        rows.append(r)
    for _ in range(4):  # IOC IP inside a URL (exact matching must not look inside)
        ip = rng.choice(IPV4)
        r = new_row(PROXY_COLS, client_ip=benign_ip(), host=benign_domain(), url=f"http://{ip}/index.html", bytes="256")
        negative(r, "url", "ip_inside_url")
        rows.append(r)
    for _ in range(5):  # IOC domain only inside the url column
        d = rng.choice(DOMAINS)
        r = new_row(PROXY_COLS, client_ip=benign_ip(), host=benign_domain(), url=f"http://{d}/login", bytes="300")
        negative(r, "url", "domain_in_url_only")
        rows.append(r)
    return rows


def build_endpoint() -> list:
    rows = [new_row(ENDPOINT_COLS, hostname=f"PC-{rng.randint(1, 60):03d}", file_name=f"doc{rng.randint(1, 500)}.docx",
                    file_md5=hex_string(32), file_sha1=hex_string(40), file_sha256=hex_string(64),
                    sender_email=f"person{rng.randint(1, 200)}@company.com") for _ in range(BENIGN_ROWS)]

    def planted(column, pool, ioc_type, count, variant):
        for _ in range(count):
            v = rng.choice(pool)
            text, kind = variant(v)
            r = new_row(ENDPOINT_COLS, hostname=f"PC-{rng.randint(1, 60):03d}", file_name="sample.bin")
            r["cells"][column] = text
            truth(r, column, v, ioc_type, kind)
            rows.append(r)

    planted("file_md5", MD5, "md5", 8, hash_variant)
    planted("file_sha1", SHA1, "sha1", 6, hash_variant)
    planted("file_sha256", SHA256, "sha256", 8, hash_variant)
    planted("sender_email", EMAILS, "email", 8, email_variant)

    for column, pool in (("file_md5", MD5), ("file_sha256", SHA256)):
        for _ in range(6):  # hash that differs in the last character
            v = off_by_one(rng.choice(pool))
            if v in ALL_HASHES:
                continue
            r = new_row(ENDPOINT_COLS, hostname=f"PC-{rng.randint(1, 60):03d}", file_name="near.bin")
            r["cells"][column] = v
            negative(r, column, "hash_off_by_one")
            rows.append(r)
    for _ in range(4):  # IOC domain in file_name
        r = new_row(ENDPOINT_COLS, hostname="PC-001", file_name=rng.choice(DOMAINS))
        negative(r, "file_name", "wrong_field")
        rows.append(r)
    for _ in range(3):  # MD5 IOC placed in the SHA-256 column
        r = new_row(ENDPOINT_COLS, hostname="PC-002", file_name="misplaced.bin")
        r["cells"]["file_sha256"] = rng.choice(MD5)
        negative(r, "file_sha256", "wrong_field")
        rows.append(r)
    return rows


# ------------------------------------------------------------------ writing
def write_log(name, columns, rows, truth_out, negatives_out) -> None:
    rng.shuffle(rows)
    path = OUT_DIR / name
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for index, row in enumerate(rows):
            row_id = index + 2  # header is line 1
            row["cells"]["timestamp"] = (START_TIME + timedelta(seconds=index * 7)).strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow(row["cells"])
            for field, ioc_value, ioc_type, category in row["truth"]:
                truth_out.append([name, row_id, field, ioc_value, ioc_type, category])
            for field, kind in row["neg"]:
                negatives_out.append([name, row_id, field, kind])


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUT_DIR / "iocs_eval.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["value", "type", "source", "added_date"])
        writer.writeheader()
        writer.writerows(messy_ioc_rows())

    truth_rows, negative_rows = [], []
    write_log("dns_eval.csv", DNS_COLS, build_dns(), truth_rows, negative_rows)
    write_log("auth_eval.csv", AUTH_COLS, build_auth(), truth_rows, negative_rows)
    write_log("proxy_eval.csv", PROXY_COLS, build_proxy(), truth_rows, negative_rows)
    write_log("endpoint_eval.csv", ENDPOINT_COLS, build_endpoint(), truth_rows, negative_rows)

    with open(OUT_DIR / "ground_truth.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "row_id", "matched_field", "ioc_value", "ioc_type", "category"])
        writer.writerows(truth_rows)
    with open(OUT_DIR / "negatives.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "row_id", "matched_field", "kind"])
        writer.writerows(negative_rows)

    print(f"Wrote evaluation data to {OUT_DIR}: {len(truth_rows)} true matches, {len(negative_rows)} hard negatives")


if __name__ == "__main__":
    main()
