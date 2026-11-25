from tools.evaluate import evaluate


def test_backend_matches_ground_truth():
    """The backend must reproduce the planted ground truth exactly."""
    results = evaluate()
    assert results["fn"] == 0, "some planted evidence was missed"
    assert results["fp"] == 0, "the backend produced false positives"


def test_every_match_is_complete_and_traceable():
    """Each match must carry full evidence and point to the correct raw file row."""
    completeness = evaluate()["completeness"]
    assert completeness["completeness"] == 1.0
    assert completeness["traceability"] == 1.0
