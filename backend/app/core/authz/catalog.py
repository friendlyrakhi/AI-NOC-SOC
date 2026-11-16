"""Permission catalog and system roles (docs/05-api-specification.md, docs/03 §2.1).

Permissions are ``resource:action`` strings. ``PRIVILEGED`` permissions require MFA on the
holder's account (IAM-1). ``MSP_ONLY`` permissions are only effective in an MSP tenant.
Permissions for later phases are declared now so that role definitions stay stable.
"""

from dataclasses import dataclass

PERMISSIONS: dict[str, str] = {
    # Portals
    "portal:noc": "Access the NOC portal",
    "portal:soc": "Access the SOC portal",
    "portal:command": "Access the Executive Command Center",
    # Tenant administration
    "tenant:read": "View tenant settings",
    "tenant:update": "Change tenant settings",
    "user:read": "List tenant members",
    "user:invite": "Invite users into the tenant",
    "user:update": "Suspend or reactivate members",
    "user:remove": "Remove members from the tenant",
    "role:read": "View roles and permissions",
    "role:manage": "Create, change and delete custom roles",
    "role:assign": "Assign roles to members",
    "apikey:read": "List API keys",
    "apikey:manage": "Create and revoke API keys",
    "audit:read": "Read the audit log",
    "audit:export": "Export the audit log",
    # MSP (only effective in an MSP tenant)
    "msp:customers:read": "List customer tenants",
    "msp:customers:manage": "Onboard customer tenants",
    "msp:aggregate_read": "Use the read-only 'All customers' view",
    # Delegations (MSP side grants; customer side reviews and revokes)
    "delegation:read": "View MSP delegations",
    "delegation:manage": "Grant or revoke MSP delegations",
    # Later phases (declared for stable role definitions)
    "connector:read": "View integrations",
    "connector:manage": "Configure integrations",
    "connector:secret:write": "Set integration credentials",
    "asset:read": "View assets",
    "asset:update": "Update assets",
    "service:read": "View business services and topology",
    "service:manage": "Change business services",
    "maintenance:read": "View maintenance windows",
    "maintenance:manage": "Create and cancel maintenance windows",
    "alert:read": "View alerts",
    "alert:update": "Triage alerts",
    "alert:suppress": "Manage suppression rules",
    "incident:read": "View incidents",
    "incident:create": "Create incidents",
    "incident:update": "Update incidents",
    "incident:comment": "Comment on incidents",
    "incident:escalate": "Escalate incidents",
    "incident:sync": "Link incidents to external ticketing (ServiceNow)",
    "correlation:manage": "Tune correlation rules",
    "sla:manage": "Manage SLA policies",
    "vuln:read": "View vulnerabilities",
    "vuln:update": "Update vulnerability findings",
    "ai:use": "Use AI assistance",
    "ai:admin": "Configure AI settings",
    "knowledge:read": "Read runbooks and the knowledge base",
    "knowledge:publish": "Publish runbooks used as AI evidence",
    "action:read": "View actions",
    "action:request": "Request actions",
    "action:approve": "Approve or deny actions",
    "playbook:read": "View playbooks",
    "playbook:edit": "Edit playbooks",
    "playbook:publish": "Publish playbooks",
    "playbook:run": "Run playbooks",
    "automation:killswitch": "Engage the automation kill switch",
    "analytics:read": "View analytics",
    "search:read": "Search",
    "hunt:run": "Run hunts",
    "report:read": "View reports",
}

PRIVILEGED: frozenset[str] = frozenset(
    {
        "tenant:update",
        "user:invite",
        "user:update",
        "user:remove",
        "role:manage",
        "role:assign",
        "apikey:manage",
        "audit:export",
        "msp:customers:manage",
        "delegation:manage",
        "connector:manage",
        "connector:secret:write",
        "correlation:manage",
        "sla:manage",
        "ai:admin",
        "knowledge:publish",
        "action:approve",
        "playbook:publish",
        "automation:killswitch",
    }
)

MSP_ONLY: frozenset[str] = frozenset({"msp:customers:read", "msp:customers:manage", "msp:aggregate_read"})

# Admin portal visibility: any of these.
ADMIN_PORTAL_ANY: frozenset[str] = frozenset(
    {"tenant:read", "user:read", "role:read", "apikey:read", "audit:read", "delegation:read", "ai:admin"}
)

_NOC_READ = {
    "portal:noc",
    "alert:read",
    "incident:read",
    "asset:read",
    "service:read",
    "maintenance:read",
    "search:read",
    "ai:use",
    "knowledge:read",
}
_SOC_READ = {
    "portal:soc",
    "alert:read",
    "incident:read",
    "asset:read",
    "service:read",
    "search:read",
    "ai:use",
    "knowledge:read",
}


@dataclass(frozen=True)
class SystemRole:
    key: str
    name: str
    description: str
    permissions: frozenset[str]


SYSTEM_ROLES: tuple[SystemRole, ...] = (
    # Holds every permission (MSP-only ones are dropped in customer tenants), so the
    # "cannot grant what you do not hold" rule never stops a tenant admin.
    SystemRole(
        "tenant_admin",
        "Tenant administrator",
        "Full administration of the tenant, all portals.",
        frozenset(PERMISSIONS),
    ),
    SystemRole(
        "integration_admin",
        "Integration administrator",
        "Configures integrations and their credentials.",
        frozenset({"connector:read", "connector:manage", "connector:secret:write", "tenant:read"}),
    ),
    SystemRole(
        "noc_analyst",
        "NOC analyst",
        "Watches and triages operational alerts.",
        frozenset(_NOC_READ | {"alert:update", "incident:create", "incident:comment", "msp:aggregate_read"}),
    ),
    SystemRole(
        "noc_engineer",
        "NOC engineer",
        "Root cause analysis, maintenance and automation for operations.",
        frozenset(
            _NOC_READ
            | {
                "alert:update",
                "alert:suppress",
                "asset:update",
                "service:manage",
                "maintenance:manage",
                "incident:create",
                "incident:update",
                "incident:comment",
                "incident:escalate",
                "incident:sync",
                "playbook:read",
                "playbook:edit",
                "playbook:run",
                "action:read",
                "action:request",
                "analytics:read",
                "report:read",
                "msp:aggregate_read",
            }
        ),
    ),
    SystemRole(
        "soc_analyst_l1",
        "SOC analyst (L1)",
        "Triages security alerts.",
        frozenset(
            _SOC_READ | {"alert:update", "incident:create", "incident:comment", "vuln:read", "msp:aggregate_read"}
        ),
    ),
    SystemRole(
        "soc_analyst_l2",
        "SOC analyst (L2) / incident responder",
        "Investigates and contains security incidents.",
        frozenset(
            _SOC_READ
            | {
                "alert:update",
                "alert:suppress",
                "incident:create",
                "incident:update",
                "incident:comment",
                "incident:escalate",
                "incident:sync",
                "vuln:read",
                "vuln:update",
                "playbook:read",
                "playbook:run",
                "action:read",
                "action:request",
                "hunt:run",
                "report:read",
                "msp:aggregate_read",
            }
        ),
    ),
    SystemRole(
        "threat_hunter",
        "Threat hunter",
        "Hunts across security telemetry.",
        frozenset(_SOC_READ | {"hunt:run", "vuln:read", "incident:comment", "report:read"}),
    ),
    SystemRole(
        "incident_commander",
        "Incident commander",
        "Coordinates major incidents across NOC and SOC.",
        frozenset(
            _NOC_READ
            | _SOC_READ
            | {
                "portal:command",
                "incident:create",
                "incident:update",
                "incident:comment",
                "incident:escalate",
                "incident:sync",
                "maintenance:read",
                "action:read",
                "action:request",
                "action:approve",
                "report:read",
                "msp:aggregate_read",
            }
        ),
    ),
    SystemRole(
        "approver",
        "Approver",
        "Approves or denies high-impact actions.",
        frozenset({"action:read", "action:approve", "incident:read", "alert:read"}),
    ),
    SystemRole(
        "executive_viewer",
        "Executive viewer",
        "Read-only Command Center.",
        frozenset({"portal:command", "analytics:read", "report:read", "incident:read", "msp:aggregate_read"}),
    ),
    SystemRole(
        "auditor",
        "Auditor",
        "Read-only access to the audit log and administration settings.",
        frozenset({"audit:read", "audit:export", "tenant:read", "user:read", "role:read", "delegation:read"}),
    ),
)

SYSTEM_ROLE_KEYS: frozenset[str] = frozenset(r.key for r in SYSTEM_ROLES)


def portals_for(permissions: frozenset[str]) -> list[str]:
    portals = [p for p in ("noc", "soc", "command") if f"portal:{p}" in permissions]
    if permissions & ADMIN_PORTAL_ANY:
        portals.append("admin")
    return portals


def effective_for_tenant_kind(permissions: frozenset[str], tenant_kind: str) -> frozenset[str]:
    """MSP-only permissions are dropped outside MSP tenants."""
    if tenant_kind == "msp":
        return permissions
    return permissions - MSP_ONLY


def requires_mfa(permissions: frozenset[str]) -> bool:
    return bool(permissions & PRIVILEGED)
