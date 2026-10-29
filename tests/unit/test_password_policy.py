"""Unit Tests for Enterprise Password Policy & Breach Evaluation (Phase 8)."""

from auth_service.core.security.password import hash_password
from auth_service.services.password_policy_service import password_policy_service


def test_calculate_entropy():
    e_low = password_policy_service.calculate_entropy("aaaa")
    e_high = password_policy_service.calculate_entropy("K7#mP9$xL2@qZ8!w")
    assert e_high > e_low
    assert e_high > 60.0


def test_breached_dictionary_detection():
    assert password_policy_service.check_breached_dictionary("password") is True
    assert password_policy_service.check_breached_dictionary("12345678") is True
    assert password_policy_service.check_breached_dictionary("UniqueUnbreachedPassphrase2026!") is False


def test_password_history_prevent_reuse():
    historical_plain = "OldPassword2025!#"
    h1 = hash_password(historical_plain)
    h2 = hash_password("AnotherOldPassword123!")

    # Candidate matches previous password -> violation
    assert password_policy_service.check_password_history(historical_plain, [h1, h2]) is True
    # Candidate is fresh -> allowed
    assert password_policy_service.check_password_history("BrandNewPassword2026!@", [h1, h2]) is False
