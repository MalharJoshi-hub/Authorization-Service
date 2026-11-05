"""Unit tests for bulk user provisioning and CSV parsing service."""

import pytest
from auth_service.services.bulk_user_service import BulkUserService


def test_parse_csv_data():
    csv_text = """email,username,full_name\nalice@example.com,alice,Alice Smith\nbob@example.com,bob,Bob Jones\n"""
    service = BulkUserService(session=None)
    rows = service.parse_csv_data(csv_text)
    assert len(rows) == 2
    assert rows[0]["email"] == "alice@example.com"
    assert rows[0]["username"] == "alice"
    assert rows[1]["email"] == "bob@example.com"


def test_validate_user_row_valid():
    service = BulkUserService(session=None)
    row = {"email": "valid@example.com", "username": "validuser"}
    err = service.validate_user_row(row, 1)
    assert err is None


def test_validate_user_row_invalid():
    service = BulkUserService(session=None)

    # Missing email
    err1 = service.validate_user_row({"email": "", "username": "u1"}, 1)
    assert "Missing required 'email'" in err1

    # Bad email format
    err2 = service.validate_user_row({"email": "not-an-email", "username": "u1"}, 2)
    assert "Invalid email format" in err2

    # Short username
    err3 = service.validate_user_row({"email": "test@domain.com", "username": "a"}, 3)
    assert "Username must be at least 3 characters" in err3


@pytest.mark.asyncio
async def test_import_users_dry_run(db_session):
    service = BulkUserService(session=db_session)
    users_data = [
        {"email": "bulk1@tenant.io", "username": "bulkuser1", "full_name": "Bulk User 1"},
        {"email": "bulk2@tenant.io", "username": "bulkuser2", "full_name": "Bulk User 2"},
        {"email": "invalid-email", "username": "bad", "full_name": "Bad User"},
    ]

    res = await service.import_users(users_data, tenant_id="tenant-1", dry_run=True)
    assert res.total_processed == 3
    assert res.created_count == 2
    assert res.error_count == 1
    d = res.to_dict()
    assert d["created_count"] == 2
    assert d["error_count"] == 1


@pytest.mark.asyncio
async def test_import_users_commit_and_collision(db_session):
    service = BulkUserService(session=db_session)
    users_data = [
        {"email": "col1@tenant.io", "username": "coluser1", "full_name": "Col User 1"},
    ]

    # First import succeeds
    res1 = await service.import_users(users_data, tenant_id="tenant-2", dry_run=False)
    assert res1.created_count == 1

    # Second import with same email detects collision and skips
    res2 = await service.import_users(users_data, tenant_id="tenant-2", dry_run=False)
    assert res2.created_count == 0
    assert res2.skipped_count == 1

