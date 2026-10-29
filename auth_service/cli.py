"""Command-Line Interface (CLI) Management Tool for Auth-as-a-Service.

Enables DevOps engineers to provision tenants, seed administrator accounts,
mint emergency API keys, and inspect system telemetry from the terminal.
"""

import argparse
import asyncio
import sys
from auth_service.config import settings
from auth_service.core.security.password import hash_password
from auth_service.core.security.api_keys import generate_api_key
from auth_service.storage.postgres.database import async_session_factory, init_db, close_db
from auth_service.storage.postgres.tenant_repo import TenantRepository
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.api_key_repo import APIKeyRepository


async def cmd_create_user(args):
    """CLI handler to create a new user."""
    await init_db()
    async with async_session_factory() as session:
        user_repo = UserRepository(session)
        role_repo = RoleRepository(session)
        tenant_repo = TenantRepository(session)

        tenant = await tenant_repo.get_by_id(args.tenant_id)
        if not tenant:
            print(f"Error: Tenant '{args.tenant_id}' does not exist.")
            return

        hashed = hash_password(args.password)
        user = await user_repo.create(
            tenant_id=tenant.id,
            email=args.email,
            hashed_password=hashed,
            full_name=args.name,
            is_active=True,
            is_verified=args.verified,
            is_superuser=args.superuser,
        )

        role = await role_repo.get_by_name(tenant.id, args.role)
        if role:
            await user_repo.assign_role(user, role)

        await session.commit()
        print(f"Successfully provisioned user {user.email} (ID: {user.id}) in tenant {tenant.name}")
    await close_db()


async def cmd_create_api_key(args):
    """CLI handler to issue a machine API key."""
    await init_db()
    async with async_session_factory() as session:
        key_repo = APIKeyRepository(session)
        raw_key, prefix, key_hash = generate_api_key(is_live=True)

        scopes = args.scopes.split(",") if args.scopes else ["*"]
        key = await key_repo.create(
            tenant_id=args.tenant_id,
            name=args.name,
            prefix=prefix,
            key_hash=key_hash,
            scopes=scopes,
        )
        await session.commit()
        print("=" * 60)
        print("API KEY SUCCESSFULLY CREATED")
        print("=" * 60)
        print(f"Key ID:   {key.id}")
        print(f"Key Name: {key.name}")
        print(f"Prefix:   {key.prefix}")
        print(f"Raw Key:  {raw_key}")
        print(f"Scopes:   {', '.join(scopes)}")
        print("WARNING: Save this key now! It will never be shown again.")
        print("=" * 60)
    await close_db()


def main():
    parser = argparse.ArgumentParser(description="Auth-as-a-Service CLI Management Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create-user
    user_p = subparsers.add_parser("create-user", help="Provision a new user account")
    user_p.add_argument("--email", required=True, help="User email address")
    user_p.add_argument("--password", required=True, help="User password")
    user_p.add_argument("--name", default=None, help="Display name")
    user_p.add_argument("--tenant-id", default=settings.DEFAULT_TENANT_ID, help="Tenant UUID")
    user_p.add_argument("--role", default="member", help="Initial role (admin, member, viewer)")
    user_p.add_argument("--verified", action="store_true", help="Mark email as pre-verified")
    user_p.add_argument("--superuser", action="store_true", help="Grant superuser privilege")

    # create-api-key
    key_p = subparsers.add_parser("create-api-key", help="Mint a machine API credential")
    key_p.add_argument("--name", required=True, help="Key description name")
    key_p.add_argument("--tenant-id", default=settings.DEFAULT_TENANT_ID, help="Tenant UUID")
    key_p.add_argument("--scopes", default="*", help="Comma-separated scopes")

    args = parser.parse_args()

    if args.command == "create-user":
        asyncio.run(cmd_create_user(args))
    elif args.command == "create-api-key":
        asyncio.run(cmd_create_api_key(args))


if __name__ == "__main__":
    main()
