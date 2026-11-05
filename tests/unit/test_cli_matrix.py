"""Unit tests for administrative Command Line Interface (CLI)."""

import argparse
import pytest
from unittest.mock import AsyncMock, patch
from auth_service.cli import cmd_create_user, cmd_create_api_key


@pytest.mark.asyncio
async def test_cmd_create_user_mock():
    mock_args = argparse.Namespace(
        email="cli.admin@test.org",
        password="SecureCLIPassword123!",
        name="CLI Admin",
        tenant_id="00000000-0000-0000-0000-000000000001",
        role="admin",
        verified=True,
        superuser=True,
    )

    with patch("auth_service.cli.init_db", new_callable=AsyncMock), \
         patch("auth_service.cli.close_db", new_callable=AsyncMock), \
         patch("auth_service.cli.TenantRepository") as mock_t_repo, \
         patch("auth_service.cli.UserRepository") as mock_u_repo, \
         patch("auth_service.cli.RoleRepository") as mock_r_repo:

        mock_tenant = type("Tenant", (), {"id": "t-1", "name": "Default Org"})()
        mock_t_repo.return_value.get_by_id = AsyncMock(return_value=mock_tenant)

        mock_user = type("User", (), {"id": "u-1", "email": "cli.admin@test.org"})()
        mock_u_repo.return_value.create = AsyncMock(return_value=mock_user)
        mock_u_repo.return_value.assign_role = AsyncMock()

        mock_r_repo.return_value.get_by_name = AsyncMock(return_value=type("Role", (), {"id": "r-1"})())

        await cmd_create_user(mock_args)
        assert mock_u_repo.return_value.create.called


@pytest.mark.asyncio
async def test_cmd_create_api_key_mock():
    mock_args = argparse.Namespace(
        name="CLI Worker Key",
        tenant_id="00000000-0000-0000-0000-000000000001",
        scopes="read:users,write:users",
    )

    with patch("auth_service.cli.init_db", new_callable=AsyncMock), \
         patch("auth_service.cli.close_db", new_callable=AsyncMock), \
         patch("auth_service.cli.APIKeyRepository") as mock_k_repo:

        mock_key = type("APIKey", (), {
            "id": "key-123",
            "name": "CLI Worker Key",
            "prefix": "aas_live_123456",
        })()
        mock_k_repo.return_value.create = AsyncMock(return_value=mock_key)

        await cmd_create_api_key(mock_args)
        assert mock_k_repo.return_value.create.called

