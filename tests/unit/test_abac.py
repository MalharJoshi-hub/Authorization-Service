"""Unit Tests for Attribute-Based Access Control (Phase 8: Layer 3)."""

from datetime import time
import pytest
from auth_service.core.rbac.abac import abac_evaluator
from auth_service.core.exceptions import AuthorizationError


def test_abac_resource_ownership():
    assert abac_evaluator.is_resource_owner("user-1", "user-1") is True
    assert abac_evaluator.is_resource_owner("user-1", "user-2") is False
    assert abac_evaluator.is_resource_owner("user-1", None) is False


def test_abac_operating_hours():
    noon = time(12, 0)
    midnight = time(2, 0)
    assert abac_evaluator.is_within_business_hours(current_time=noon, start_hour=8, end_hour=19) is True
    assert abac_evaluator.is_within_business_hours(current_time=midnight, start_hour=8, end_hour=19) is False


def test_abac_evaluate_access_policy():
    user_id = "user-alice"
    resource = {"id": "res-101", "owner_id": user_id, "allowed_cidrs": ["192.168.1.10"]}
    context = {"client_ip": "192.168.1.10"}

    # Allowed
    assert abac_evaluator.evaluate_access(user_id, resource, context, require_ownership=True) is True

    # Denied by ownership
    with pytest.raises(AuthorizationError):
        abac_evaluator.evaluate_access("user-bob", resource, context, require_ownership=True)

    # Denied by IP constraint
    with pytest.raises(AuthorizationError):
        abac_evaluator.evaluate_access(user_id, resource, {"client_ip": "10.0.0.99"}, require_ownership=True)
