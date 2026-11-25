"""Smoke test for the Streamlit application."""
from pathlib import Path

import pytest


try:
    from streamlit.testing.v1 import AppTest
except ImportError:
    AppTest = None


def test_app_starts_without_exceptions() -> None:
    """Run the app with Streamlit AppTest when it is available."""
    if AppTest is None:
        pytest.skip("Streamlit AppTest is not available in this environment.")

    app_path = Path(__file__).resolve().parent.parent / "app.py"
    app = AppTest.from_file(app_path)
    app.run(timeout=20)
    assert not app.exception

    db_conn = app.session_state["db_conn"]
    db_conn.close()
