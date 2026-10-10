"""Unit tests for automated security posture and ASVS auditor."""

import pytest
from auth_service.core.security.security_posture import SecurityPostureAuditor, security_auditor


def test_calculate_entropy():
    # Empty
    assert SecurityPostureAuditor.calculate_entropy("") == 0.0

    # Low entropy (repeated characters)
    low_ent = SecurityPostureAuditor.calculate_entropy("aaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    # High entropy (random hex)
    high_ent = SecurityPostureAuditor.calculate_entropy("4f8a2c9e7b1d6f0a3e5c8b2a1f4d9e0b")
    assert high_ent > 3.0


def test_run_audit_structure():
    auditor = SecurityPostureAuditor()
    report = auditor.run_audit()

    assert "security_score" in report
    assert "rating" in report
    assert "findings" in report
    assert "frameworks_evaluated" in report
    assert isinstance(report["findings"], list)
    assert 0 <= report["security_score"] <= 100
    assert report["rating"] in ["EXCELLENT", "GOOD", "FAIR", "POOR"]
