"""Unit tests for MFA backup recovery codes service."""

import pytest
from auth_service.services.backup_codes_service import BackupCodesService, backup_codes_service


def test_generate_single_code_format():
    code = BackupCodesService.generate_single_code()
    assert "-" in code
    parts = code.split("-")
    assert len(parts) == 2
    assert len(parts[0]) == 5
    assert len(parts[1]) == 5


def test_generate_backup_codes_batch():
    plain, hashed = BackupCodesService.generate_backup_codes(count=8)
    assert len(plain) == 8
    assert len(hashed) == 8
    assert len(set(plain)) == 8
    assert len(set(hashed)) == 8


def test_normalize_code():
    raw1 = "abcd-1234"
    raw2 = "  ab cd- 1234 "
    assert BackupCodesService.normalize_code(raw1) == "ABCD1234"
    assert BackupCodesService.normalize_code(raw2) == "ABCD1234"


def test_verify_and_consume_success():
    plain_codes, hashed_codes = BackupCodesService.generate_backup_codes(count=5)
    code_to_use = plain_codes[2]

    # Verify matching code
    success, updated_hashes = BackupCodesService.verify_and_consume(code_to_use, hashed_codes)
    assert success is True
    assert len(updated_hashes) == 4

    # Using the same code a second time must fail (single-use)
    success2, updated_hashes2 = BackupCodesService.verify_and_consume(code_to_use, updated_hashes)
    assert success2 is False
    assert len(updated_hashes2) == 4


def test_verify_and_consume_invalid():
    _, hashed_codes = BackupCodesService.generate_backup_codes(count=5)
    success, updated_hashes = BackupCodesService.verify_and_consume("INVALID-CODE-9999", hashed_codes)
    assert success is False
    assert len(updated_hashes) == 5


def test_verify_and_consume_empty_list():
    success, updated = BackupCodesService.verify_and_consume("ABC-123", [])
    assert success is False
    assert updated == []
