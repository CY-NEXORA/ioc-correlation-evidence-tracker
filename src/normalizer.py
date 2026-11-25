"""
normalizer.py - Validate and normalise indicators of compromise (IOCs).

Main entry points:
    normalize_indicator(raw, declared_type=None) -> Indicator
    normalize_ioc_dataframe(df)                  -> (valid_df, rejected_df)
"""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import pandas as pd

# ---------------------------------------------------------------- patterns
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[0-9a-f]+$")
EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@([a-z0-9\-]+\.)+[a-z]{2,}$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
URL_SCHEMES = ("http://", "https://", "ftp://")

# What the "type" column in the IOC file is allowed to say, mapped to
# the real types the detector can return.
DECLARED_TO_DETECTED = {
    "ip": {"ipv4", "ipv6"},
    "ipv4": {"ipv4"},
    "ipv6": {"ipv6"},
    "domain": {"domain"},
    "url": {"url"},
    "md5": {"md5"},
    "sha1": {"sha1"},
    "sha256": {"sha256"},
    "hash": {"md5", "sha1", "sha256"},
    "email": {"email"},
}


@dataclass
class Indicator:
    original: str          # exactly what we received
    value: str             # normalised value ("" if invalid)
    ioc_type: str          # ipv4, ipv6, domain, url, md5, sha1, sha256, email, or ""
    valid: bool
    reason: str = ""       # why it was rejected (empty if valid)


# ---------------------------------------------------------------- helpers
def is_blank(value) -> bool:
    """True for None, NaN and empty or whitespace-only text."""
    return value is None or (isinstance(value, float) and pd.isna(value)) or not str(value).strip()


def refang(text: str) -> str:
    """Undo 'defanging' used to share IOCs safely: hxxp://evil[.]com -> http://evil.com"""
    t = text.strip()
    t = re.sub(r"^hxxp", "http", t, flags=re.IGNORECASE)
    for fake, real in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("[:]", ":"), ("[@]", "@"), ("[at]", "@")):
        t = t.replace(fake, real)
    return t


def is_valid_domain(name: str) -> bool:
    if not name or len(name) > 253 or "." not in name:
        return False
    labels = name.split(".")
    if not all(LABEL_RE.match(label) for label in labels):
        return False
    tld = labels[-1]
    return len(tld) >= 2 and tld.isalpha()  # blocks things like 999.999.1.1


def detect_type(value: str) -> str:
    """Guess the type of an already-cleaned (lowercase, refanged) value. '' if unknown."""
    if value.startswith(URL_SCHEMES):
        return "url"
    if EMAIL_RE.match(value):
        return "email"
    try:
        ip = ipaddress.ip_address(value)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if HEX_RE.match(value) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)]
    if is_valid_domain(value.rstrip(".")):
        return "domain"
    return ""


def _normalize_url(value: str) -> str:
    """Lowercase scheme and host, keep path/query case (they can be case-sensitive)."""
    parts = urlsplit(value)
    host = (parts.hostname or "").rstrip(".")
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))


# ---------------------------------------------------------------- main API
def normalize_indicator(raw, declared_type=None) -> Indicator:
    """Clean one indicator and decide whether it is valid."""
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return Indicator("", "", "", False, "empty value")

    original = str(raw)
    cleaned = refang(original)
    if not cleaned:
        return Indicator(original, "", "", False, "empty value")

    # URLs keep path case; everything else is safe to lowercase fully.
    is_url = cleaned.lower().startswith(URL_SCHEMES)
    probe = cleaned if is_url else cleaned.lower()
    detected = detect_type(cleaned.lower() if is_url else probe)

    if not detected:
        return Indicator(original, "", "", False, "unrecognised or malformed indicator")

    # If the file declared a type, it must agree with what we detected.
    if not is_blank(declared_type):
        declared = str(declared_type).strip().lower()
        allowed = DECLARED_TO_DETECTED.get(declared)
        if allowed is None:
            return Indicator(original, "", "", False, f"unknown declared type '{declared}'")
        if detected not in allowed:
            return Indicator(original, "", "", False,
                             f"type mismatch: declared '{declared}' but looks like '{detected}'")

    # Build the canonical form.
    if detected == "url":
        value = _normalize_url(cleaned)
    elif detected in ("ipv4", "ipv6"):
        value = str(ipaddress.ip_address(probe))
    elif detected == "domain":
        value = probe.rstrip(".")
    else:  # hashes and emails
        value = probe
    return Indicator(original, value, detected, True)


def normalize_ioc_dataframe(df: pd.DataFrame):
    """
    Normalise a whole IOC table (needs a 'value' column, optional 'type').
    Returns (valid_df, rejected_df).
      - valid_df: unique normalised indicators (duplicates are merged, sources kept)
      - rejected_df: every bad row with the reason - nothing disappears silently
    """
    if "value" not in df.columns:
        raise ValueError("IOC file must contain a 'value' column")

    good, bad = [], []
    for row_id, row in df.iterrows():
        ind = normalize_indicator(row.get("value"), row.get("type"))
        record = row.to_dict()
        record["row_id"] = int(row_id) + 2  # +2 = spreadsheet line number (header is line 1)
        if ind.valid:
            record.update(norm_value=ind.value, norm_type=ind.ioc_type)
            good.append(record)
        else:
            record["reason"] = ind.reason
            bad.append(record)

    valid_df = pd.DataFrame(good)
    if not valid_df.empty:
        agg = {c: "first" for c in valid_df.columns if c not in ("norm_value", "norm_type")}
        if "source" in valid_df.columns:
            agg["source"] = lambda s: ", ".join(sorted(set(map(str, s))))
        valid_df = (valid_df.groupby(["norm_value", "norm_type"], as_index=False, sort=False)
                    .agg(agg))
    rejected_df = pd.DataFrame(bad)
    return valid_df, rejected_df
