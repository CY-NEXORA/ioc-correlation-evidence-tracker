import hashlib
from pathlib import Path

import pandas as pd


def _check_supported_file(path: str) -> Path:
    """Validate a CSV or JSON file path."""
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        raise ValueError(f"File not found: {path}")
    if file_path.suffix.lower() not in (".csv", ".json"):
        raise ValueError(f"Unsupported file extension: {file_path.suffix}")
    return file_path


def load_ioc_file(path: str) -> pd.DataFrame:
    """Load an IOC CSV or JSON file."""
    file_path = _check_supported_file(path)
    if file_path.suffix.lower() == ".csv":
        return pd.read_csv(file_path, dtype=str)
    return pd.read_json(file_path, dtype=str)


def load_evidence_file(path: str) -> pd.DataFrame:
    """Load an evidence file with string columns and row IDs."""
    file_path = _check_supported_file(path)
    if file_path.suffix.lower() == ".csv":
        df = pd.read_csv(file_path, dtype=str)
        df["row_id"] = range(2, len(df) + 2)
    else:
        df = pd.read_json(file_path, dtype=str)
        df["row_id"] = range(1, len(df) + 1)
    return df


def file_sha256(path: str) -> str:
    """Return the SHA-256 hash of a file."""
    file_path = _check_supported_file(path)
    digest = hashlib.sha256()
    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
