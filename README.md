# IOC Tracker

A Streamlit application for normalizing, importing, matching, and reporting indicators of compromise (IOCs).

## Run the app

Use the project virtual environment:

```powershell
python -m streamlit run app.py
```

## Run the tests

```powershell
python -m pytest -v
```

## Project structure

```text
ioc-tracker/
  data/
  src/
    normalizer.py
    importer.py
    database.py
    matcher.py
    report.py
  app.py
  tests/
  README.md
  requirements.txt
```
