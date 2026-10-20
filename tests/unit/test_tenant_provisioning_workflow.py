"""Unit tests for automated tenant onboarding workflow."""

import pytest
from auth_service.services.tenant_provisioning_workflow import TenantProvisioningWorkflow


@pytest.mark.asyncio
async def test_provision_new_tenant(db_session):
    workflow = TenantProvisioningWorkflow(session=db_session)

    result = await workflow.provision_new_tenant(
        tenant_name="Acme Corp",
        tenant_slug="acme-corp",
        admin_email="admin@acme.com",
        admin_username="acmeadmin",
    )

    assert result.tenant.id is not None
    assert result.tenant.name == "Acme Corp"
    assert result.tenant.slug == "acme-corp"
    assert result.admin_user.email == "admin@acme.com"
    assert result.initial_api_key.startswith("aas_live_")
    assert len(result.roles_created) == 4

    summary = result.to_dict()
    assert summary["tenant_name"] == "Acme Corp"
    assert summary["admin_email"] == "admin@acme.com"
