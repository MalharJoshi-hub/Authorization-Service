"""System Permission Catalog & Standard Definitions (Layer 3: RBAC).

Defines canonical permissions structured as '<resource>:<action>' along with
descriptive metadata for RBAC policy definitions.
"""

from typing import Dict, List, NamedTuple


class PermissionDef(NamedTuple):
    name: str
    resource: str
    action: str
    description: str


class SystemPermissions:
    # User Resource Permissions
    USERS_READ = "users:read"
    USERS_CREATE = "users:create"
    USERS_UPDATE = "users:update"
    USERS_DELETE = "users:delete"
    USERS_MANAGE = "users:manage"

    # Role & Policy Resource Permissions
    ROLES_READ = "roles:read"
    ROLES_CREATE = "roles:create"
    ROLES_UPDATE = "roles:update"
    ROLES_DELETE = "roles:delete"
    ROLES_ASSIGN = "roles:assign"

    # Permission Resource Permissions
    PERMISSIONS_READ = "permissions:read"
    PERMISSIONS_CREATE = "permissions:create"

    # API Key Machine Identity Permissions
    API_KEYS_READ = "api_keys:read"
    API_KEYS_CREATE = "api_keys:create"
    API_KEYS_DELETE = "api_keys:delete"
    API_KEYS_MANAGE = "api_keys:manage"

    # Multi-Tenant Resource Permissions
    TENANTS_READ = "tenants:read"
    TENANTS_CREATE = "tenants:create"
    TENANTS_UPDATE = "tenants:update"
    TENANTS_MANAGE = "tenants:manage"

    # Audit & Observability Resource Permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    ANALYTICS_READ = "analytics:read"

    # Wildcard Superuser Permissions
    ADMIN_ALL = "admin:*"
    ALL = "*"


ALL_SYSTEM_PERMISSIONS: List[PermissionDef] = [
    PermissionDef(SystemPermissions.USERS_READ, "users", "read", "View user details and account listings"),
    PermissionDef(SystemPermissions.USERS_CREATE, "users", "create", "Provision new user accounts"),
    PermissionDef(SystemPermissions.USERS_UPDATE, "users", "update", "Modify user profile and account details"),
    PermissionDef(SystemPermissions.USERS_DELETE, "users", "delete", "Soft or hard delete user accounts"),
    PermissionDef(SystemPermissions.USERS_MANAGE, "users", "manage", "Full administrative control of users"),

    PermissionDef(SystemPermissions.ROLES_READ, "roles", "read", "Inspect configured roles and assignments"),
    PermissionDef(SystemPermissions.ROLES_CREATE, "roles", "create", "Define new tenant or system roles"),
    PermissionDef(SystemPermissions.ROLES_UPDATE, "roles", "update", "Edit role parameters and permission sets"),
    PermissionDef(SystemPermissions.ROLES_DELETE, "roles", "delete", "Remove obsolete custom roles"),
    PermissionDef(SystemPermissions.ROLES_ASSIGN, "roles", "assign", "Bind roles to users within tenants"),

    PermissionDef(SystemPermissions.PERMISSIONS_READ, "permissions", "read", "Inspect all available system permissions"),
    PermissionDef(SystemPermissions.PERMISSIONS_CREATE, "permissions", "create", "Register new granular permission identifiers"),

    PermissionDef(SystemPermissions.API_KEYS_READ, "api_keys", "read", "List issued machine API keys"),
    PermissionDef(SystemPermissions.API_KEYS_CREATE, "api_keys", "create", "Mint new machine credentials"),
    PermissionDef(SystemPermissions.API_KEYS_DELETE, "api_keys", "delete", "Revoke active API keys"),
    PermissionDef(SystemPermissions.API_KEYS_MANAGE, "api_keys", "manage", "Full lifecycle administration of API keys"),

    PermissionDef(SystemPermissions.TENANTS_READ, "tenants", "read", "View tenant organization metadata"),
    PermissionDef(SystemPermissions.TENANTS_CREATE, "tenants", "create", "Provision isolated tenant realms"),
    PermissionDef(SystemPermissions.TENANTS_UPDATE, "tenants", "update", "Modify organization policies and settings"),
    PermissionDef(SystemPermissions.TENANTS_MANAGE, "tenants", "manage", "Full tenant lifecycle control"),

    PermissionDef(SystemPermissions.AUDIT_READ, "audit", "read", "Access immutable security audit ledger"),
    PermissionDef(SystemPermissions.AUDIT_EXPORT, "audit", "export", "Stream and export audit logs to CSV"),
    PermissionDef(SystemPermissions.ANALYTICS_READ, "analytics", "read", "Inspect authentication metrics and telemetry"),

    PermissionDef(SystemPermissions.ADMIN_ALL, "admin", "*", "Unrestricted administrative privilege across tenant"),
    PermissionDef(SystemPermissions.ALL, "*", "*", "Global superuser privilege across all platform boundaries"),
]

