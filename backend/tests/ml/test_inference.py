"""
Tests for Secure ML Inference Pipeline.
"""

from app.ml.inference import ScamClassifier
from app.ml.schemas import InferenceRequest, ScamCategory


def test_empty_text(classifier=None):
    if classifier is None:
        classifier = ScamClassifier.get_instance()
    req = InferenceRequest(text="   \n  ")
    res = classifier.predict(req)
    
    assert res.risk_level == "SAFE"
    assert res.risk_score == 0.0
    assert res.scam_family == ScamCategory.SAFE
    assert res.confidence == 1.0
    assert not res.is_low_confidence


def test_mock_inference_output(classifier=None):
    if classifier is None:
        classifier = ScamClassifier.get_instance()
    req = InferenceRequest(text="Suspicious text here")
    res = classifier.predict(req)
    
    assert res.model_version == "mock-v1"
    assert res.risk_level == "MALICIOUS"
    assert res.scam_family == ScamCategory.OTHER_SCAM


def test_extremely_long_text(classifier=None):
    if classifier is None:
        classifier = ScamClassifier.get_instance()
    req = InferenceRequest(text="A" * 10000)
    res = classifier.predict(req)
    
    assert len(res.text_analysis.original_text) == 10000
    assert res.risk_level == "MALICIOUS"
