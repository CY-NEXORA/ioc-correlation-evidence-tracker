import pandas as pd
from src.normalizer import normalize_indicator, normalize_ioc_dataframe


def test_ipv4_valid() -> None:
    r = normalize_indicator("185.220.101.45")
    assert r.valid and r.ioc_type == "ipv4" and r.value == "185.220.101.45"

def test_ipv6_is_compressed() -> None:
    r = normalize_indicator("2001:0db8:0000:0000:0000:0000:0000:0bad")
    assert r.valid and r.ioc_type == "ipv6" and r.value == "2001:db8::bad"

def test_domain_lowercase_and_trailing_dot() -> None:
    r = normalize_indicator("EVIL-Domain.COM.")
    assert r.valid and r.ioc_type == "domain" and r.value == "evil-domain.com"

def test_hash_types_by_length() -> None:
    assert normalize_indicator("44D88612FEA8A8F36DE82E1278ABB02F").ioc_type == "md5"
    assert normalize_indicator("a" * 40).ioc_type == "sha1"
    assert normalize_indicator("A" * 64).ioc_type == "sha256"

def test_hash_is_lowercased() -> None:
    assert normalize_indicator("44D88612FEA8A8F36DE82E1278ABB02F").value == "44d88612fea8a8f36de82e1278abb02f"

def test_email_lowercased() -> None:
    r = normalize_indicator("Phish@Bad-Mail.ORG")
    assert r.valid and r.ioc_type == "email" and r.value == "phish@bad-mail.org"

def test_defanged_url_is_restored() -> None:
    r = normalize_indicator("hxxp://malware-site[.]net/payload.exe")
    assert r.valid and r.ioc_type == "url" and r.value == "http://malware-site.net/payload.exe"

def test_url_keeps_path_case_but_lowercases_host() -> None:
    r = normalize_indicator("HTTP://Evil.COM/Path/File.EXE")
    assert r.value == "http://evil.com/Path/File.EXE"


def test_bad_ip_rejected() -> None:
    r = normalize_indicator("999.999.1.1")
    assert not r.valid and r.reason

def test_ip_with_leading_zeros_rejected() -> None:
    assert not normalize_indicator("010.001.001.001").valid

def test_text_with_spaces_rejected() -> None:
    assert not normalize_indicator("not a domain").valid

def test_short_hash_rejected() -> None:
    assert not normalize_indicator("123abc").valid

def test_non_hex_hash_rejected() -> None:
    assert not normalize_indicator("z" * 32).valid


def test_empty_none_and_nan() -> None:
    assert not normalize_indicator("").valid
    assert not normalize_indicator("   ").valid
    assert not normalize_indicator(None).valid
    assert not normalize_indicator(float("nan")).valid

def test_whitespace_is_stripped() -> None:
    assert normalize_indicator("  10.66.6.6  ").value == "10.66.6.6"

def test_declared_type_mismatch_rejected() -> None:
    r = normalize_indicator("c2.badhost.org", declared_type="ip")
    assert not r.valid and "mismatch" in r.reason

def test_declared_ip_accepts_ipv6() -> None:
    assert normalize_indicator("::1", declared_type="ip").valid

def test_declared_hash_accepts_sha256() -> None:
    assert normalize_indicator("a" * 64, declared_type="hash").valid

def test_unknown_declared_type_rejected() -> None:
    assert not normalize_indicator("1.1.1.1", declared_type="banana").valid


def test_dataframe_end_to_end() -> None:
    df = pd.read_csv("data/iocs.csv")
    valid, rejected = normalize_ioc_dataframe(df)
    assert len(rejected) == 5
    assert len(valid) == 9
    assert valid["norm_value"].is_unique
    assert "evil-domain.com" in set(valid["norm_value"])
    assert set(rejected["reason"]) >= {"empty value"}

def test_duplicates_merge_sources() -> None:
    df = pd.read_csv("data/iocs.csv")
    valid, _ = normalize_ioc_dataframe(df)
    row = valid[valid["norm_value"] == "185.220.101.45"].iloc[0]
    assert "ThreatFeedA" in row["source"] and "ThreatFeedB" in row["source"]

def test_rejected_rows_keep_line_number() -> None:
    df = pd.read_csv("data/iocs.csv")
    _, rejected = normalize_ioc_dataframe(df)
    bad_ip = rejected[rejected["value"] == "999.999.1.1"].iloc[0]
    assert bad_ip["row_id"] == 13
