"""
Unit and integration tests for PhishGuard SOC threat engine.
Covers heuristic scoring, template classification, and pydantic schema validation.
"""

import pytest
from app import run_heuristics, PhishingAnalysisResult

def test_advance_fee_scam_heuristics():
    """Verify that payment gateways and urgency trigger high heuristic penalty."""
    scam_text = (
        "Congratulations! You must pay $350 via Zelle or CashApp for your MacBook equipment "
        "within 24 hours to secure your employment."
    )
    score, flags, _ = run_heuristics(scam_text)
    
    assert score >= 40, f"Expected score >= 40, got {score}"
    assert any("Zelle" in f or "advance-fee" in f.lower() for f in flags)
    assert any("urgency" in f.lower() for f in flags)

def test_legitimate_offer_heuristics():
    """Verify that official corporate offers without money demands receive 0 heuristic score."""
    legit_text = (
        "We are pleased to offer you the position of Software Engineer at Stripe. "
        "Your compensation is $120,000 annually. All hardware is provisioned by corporate IT."
    )
    score, flags, _ = run_heuristics(legit_text)
    
    assert score == 0
    assert len(flags) == 0

def test_webmail_impersonation_detection():
    """Verify detection of free webmail (@gmail.com) in corporate hiring."""
    webmail_text = "Please send your ID verification to amazon.recruitment.desk@gmail.com"
    score, flags, _ = run_heuristics(webmail_text)
    
    assert score >= 30
    assert any("@gmail.com" in f for f in flags)

def test_pydantic_schema_validation():
    """Verify PhishingAnalysisResult schema enforces boundary ranges."""
    valid_data = {
        "scam_likelihood_score": 85,
        "risk_level": "Critical Threat",
        "scam_type": "Advance-Fee Equipment Scam",
        "detected_red_flags": ["Zelle transfer demanded"],
        "communication_analysis": "Uses fake Gmail domain",
        "verdict_summary": "Extortion attempt detected",
        "recommended_actions": ["Block sender"]
    }
    result = PhishingAnalysisResult(**valid_data)
    assert result.scam_likelihood_score == 85
    assert result.risk_level == "Critical Threat"

def test_invalid_score_boundary():
    """Verify Pydantic rejects out-of-bounds threat scores."""
    with pytest.raises(ValueError):
        PhishingAnalysisResult(
            scam_likelihood_score=150,  # Invalid: > 100
            risk_level="Critical",
            scam_type="Scam",
            communication_analysis="test",
            verdict_summary="test"
        )