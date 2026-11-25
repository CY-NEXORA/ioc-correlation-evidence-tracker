"""
Evaluate the correlation backend against the ground truth in data/eval/.

Metrics: precision, recall, F1 (overall, per IOC type, per variant category), false positives
per hard-negative kind, and evidence completeness / traceability.

Run from the project root:  python -m tools.evaluate
"""
import hashlib
import os
import sqlite3
import tempfile
from pathlib import Path

import pandas as pd

from src.database import init_db
from src.matcher import run_correlation
from src.normalizer import normalize_indicator

EVAL_DIR = Path("data/eval")
IOC_FILE = EVAL_DIR / "iocs_eval.csv"
LOG_FILES = [EVAL_DIR / name for name in
             ("dns_eval.csv", "auth_eval.csv", "proxy_eval.csv", "endpoint_eval.csv")]
RESULTS_FILE = EVAL_DIR / "evaluation_results.md"
ERRORS_FILE = EVAL_DIR / "evaluation_errors.csv"


def ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_ground_truth() -> pd.DataFrame:
    truth = pd.read_csv(EVAL_DIR / "ground_truth.csv", dtype=str)
    truth["row_id"] = truth["row_id"].astype(int)
    return truth


def match_keys(df: pd.DataFrame, value_column: str) -> set:
    return {(os.path.basename(str(r.filename if hasattr(r, "filename") else r.file)), int(r.row_id),
             r.matched_field, str(getattr(r, value_column)))
            for r in df.itertuples()}


def check_completeness(conn, matches: pd.DataFrame) -> dict:
    """Check that every match carries full evidence and can be traced back to the raw file."""
    stored = {os.path.basename(f): h for f, h in conn.execute("SELECT filename, sha256 FROM evidence_files")}
    raw_cache = {}
    complete = traceable = 0
    for r in matches.itertuples():
        name = os.path.basename(str(r.filename))
        has_fields = bool(name) and pd.notna(r.row_id) and bool(str(r.event_time).strip()) and bool(r.matched_field)
        has_hash = name in stored and stored[name] == sha256_of(EVAL_DIR / name)
        complete += int(has_fields and has_hash)

        if name not in raw_cache:
            raw_cache[name] = pd.read_csv(EVAL_DIR / name, dtype=str, keep_default_na=False)
        raw = raw_cache[name]
        index = int(r.row_id) - 2
        if 0 <= index < len(raw) and r.matched_field in raw.columns:
            cell = normalize_indicator(raw.at[index, r.matched_field])
            same_time = raw.at[index, "timestamp"] == str(r.event_time)
            logged = normalize_indicator(r.matched_value)
            traceable += int(cell.valid and logged.valid and cell.value == logged.value and same_time)
    total = len(matches)
    return {"complete": complete, "traceable": traceable, "total": total,
            "completeness": ratio(complete, total), "traceability": ratio(traceable, total)}


def evaluate() -> dict:
    workdir = tempfile.mkdtemp()
    conn = init_db(os.path.join(workdir, "eval.db"))
    matches = run_correlation(conn, str(IOC_FILE), [str(p) for p in LOG_FILES])

    truth = load_ground_truth()
    truth_keys = {(r.file, r.row_id, r.matched_field, r.ioc_value) for r in truth.itertuples()}
    found_keys = {(os.path.basename(str(r.filename)), int(r.row_id), r.matched_field, str(r.ioc_value))
                  for r in matches.itertuples()}

    tp_keys = truth_keys & found_keys
    fn_keys = truth_keys - found_keys
    fp_keys = found_keys - truth_keys

    precision = ratio(len(tp_keys), len(found_keys))
    recall = ratio(len(tp_keys), len(truth_keys))
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    # per IOC type
    type_of_key = {(r.file, r.row_id, r.matched_field, r.ioc_value): r.ioc_type for r in truth.itertuples()}
    found_type = {(os.path.basename(str(r.filename)), int(r.row_id), r.matched_field, str(r.ioc_value)): r.ioc_type
                  for r in matches.itertuples()}
    per_type = []
    for ioc_type in sorted(set(type_of_key.values()) | set(found_type.values())):
        t = {k for k, v in type_of_key.items() if v == ioc_type}
        f = {k for k, v in found_type.items() if v == ioc_type}
        per_type.append({"type": ioc_type, "expected": len(t), "found": len(f), "correct": len(t & f),
                         "precision": ratio(len(t & f), len(f)), "recall": ratio(len(t & f), len(t))})

    # per variant category (recall only)
    category_of_key = {(r.file, r.row_id, r.matched_field, r.ioc_value): r.category for r in truth.itertuples()}
    per_category = []
    for category in sorted(set(category_of_key.values())):
        t = {k for k, v in category_of_key.items() if v == category}
        per_category.append({"category": category, "expected": len(t), "found": len(t & found_keys),
                             "recall": ratio(len(t & found_keys), len(t))})

    # false positives per hard-negative kind
    negatives = pd.read_csv(EVAL_DIR / "negatives.csv", dtype=str)
    negatives["row_id"] = negatives["row_id"].astype(int)
    neg_kind = {(r.file, r.row_id, r.matched_field): r.kind for r in negatives.itertuples()}
    fp_by_kind = {}
    for kind in sorted(set(neg_kind.values())):
        planted = sum(1 for v in neg_kind.values() if v == kind)
        wrong = sum(1 for k in fp_keys if neg_kind.get(k[:3]) == kind)
        fp_by_kind[kind] = {"planted": planted, "false_positives": wrong}

    completeness = check_completeness(conn, matches)
    conn.close()

    errors = ([("missed", *k) for k in sorted(fn_keys)] + [("false_positive", *k) for k in sorted(fp_keys)])
    pd.DataFrame(errors, columns=["error", "file", "row_id", "matched_field", "ioc_value"]).to_csv(
        ERRORS_FILE, index=False)

    return {"expected": len(truth_keys), "found": len(found_keys), "tp": len(tp_keys), "fp": len(fp_keys),
            "fn": len(fn_keys), "precision": precision, "recall": recall, "f1": f1,
            "per_type": per_type, "per_category": per_category, "fp_by_kind": fp_by_kind,
            "completeness": completeness}


def table(headers: list, rows: list) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def render_markdown(r: dict) -> str:
    pct = lambda x: f"{x * 100:.1f}%"
    c = r["completeness"]
    parts = [
        "# Evaluation Results", "",
        "## Overall",
        table(["Metric", "Value"], [
            ["Expected matches (ground truth)", r["expected"]], ["Matches found", r["found"]],
            ["True positives", r["tp"]], ["False positives", r["fp"]], ["False negatives", r["fn"]],
            ["Precision", pct(r["precision"])], ["Recall", pct(r["recall"])], ["F1 score", pct(r["f1"])]]),
        "", "## Per IOC type",
        table(["Type", "Expected", "Found", "Correct", "Precision", "Recall"],
              [[t["type"], t["expected"], t["found"], t["correct"], pct(t["precision"]), pct(t["recall"])]
               for t in r["per_type"]]),
        "", "## Recall per surface variant",
        table(["Variant", "Expected", "Found", "Recall"],
              [[x["category"], x["expected"], x["found"], pct(x["recall"])] for x in r["per_category"]]),
        "", "## Hard negatives (must not match)",
        table(["Kind", "Planted", "False positives"],
              [[k, v["planted"], v["false_positives"]] for k, v in r["fp_by_kind"].items()]),
        "", "## Evidence completeness",
        table(["Check", "Result"], [
            ["Matches with all evidence fields and a verified file hash", f"{c['complete']} / {c['total']} ({pct(c['completeness'])})"],
            ["Matches traceable to the raw file row (value and time re-verified)", f"{c['traceable']} / {c['total']} ({pct(c['traceability'])})"]]),
        ""]
    return "\n".join(parts)


def main() -> None:
    results = evaluate()
    report = render_markdown(results)
    RESULTS_FILE.write_text(report, encoding="utf-8")
    print(report)
    print(f"Saved: {RESULTS_FILE} and {ERRORS_FILE}")


if __name__ == "__main__":
    main()
