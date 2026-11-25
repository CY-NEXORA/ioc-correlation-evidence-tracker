# IOC Correlation and Incident Evidence Tracker

Offline tool that correlates a list of indicators of compromise (IOCs) with local log records and keeps traceable evidence for every match: source file, row ID, event time and matched field.

**Team:** NEXORA (Next Plus Aura)


## Features
- Import an IOC list and one or more evidence files (CSV or JSON).
- Validate and normalise indicators (IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256, email), including defanged forms such as `hxxp://evil[.]com`.
- Reject invalid indicators with a recorded reason instead of dropping them silently.
- Exact matching, restricted to the log fields that correspond to each indicator type.
- Evidence integrity: every imported file is registered with its SHA-256 hash.
- Streamlit dashboard with filters, incident timeline and CSV, JSON and Markdown report export.

## Tech stack
Python, Pandas, SQLite, Streamlit, pytest.

## Setup
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run the app
```powershell
python -m streamlit run app.py
```
Click **Use bundled sample data**, then **Run correlation**. The sample data produces 14 matches and 5 rejected indicators.

## Verify the project
```powershell
python -m pytest -v            # unit and regression tests
python verify_backend.py       # independent check against a hand-verified result
python -m tools.evaluate       # precision, recall and evidence completeness
```
The evaluation uses a synthetic dataset with a known ground truth (about 1,200 log rows, 128 planted matches and 74 hard negatives). Regenerate it with `python -m tools.generate_eval_data`. Results are written to `data/eval/evaluation_results.md`.

## Project structure
```text
ioc-tracker/
  app.py                  Streamlit interface
  src/
    normalizer.py         validation and normalisation of indicators
    importer.py           CSV and JSON loading, file hashing
    database.py           SQLite storage for IOCs, evidence files and matches
    matcher.py            exact matching and the correlation pipeline
    report.py             CSV, JSON, timeline and Markdown case report
  tools/
    generate_eval_data.py synthetic evaluation data with ground truth
    evaluate.py           accuracy and evidence completeness metrics
  tests/                  pytest suite
  data/                   sample data, data dictionary and evaluation data
  verify_backend.py       independent backend verification
```

## Design notes
- Matched values are stored exactly as they appear in the log, so the evidence shows the original text. Normalisation is only used for comparison.
- Matches are linked to the exact evidence file record (by hash), so two different files with the same name never share evidence.

## Limitations
- Matching is exact and offline only: no fuzzy matching, enrichment or network lookups.
- All bundled and evaluation data is synthetic. Performance on real logs may differ.

## Team members

- Mostafa Yasser Abdelfattah Ewis
- Ali Waleed Abdalhay
- Yousef Hamada Yousef Aissa
