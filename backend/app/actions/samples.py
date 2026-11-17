"""Sample playbooks (P5), seeded as DEMO content and used by the tests.

- Enrich & ticket: T0/T1, runs without approval.
- Restart unhealthy service: T2, one approval.
- Contain host: T3, two distinct approvers.
"""

from typing import Any

SAMPLE_PLAYBOOKS: list[dict[str, Any]] = [
    {
        "key": "enrich-and-ticket",
        "name": "Enrich & ticket (DEMO)",
        "domain": "joint",
        "description": "Adds context about the affected asset to the timeline and opens a ServiceNow ticket.",
        "definition": {
            "description": "Low-risk triage helper.",
            "approval_timeout_minutes": 30,
            "steps": [
                {
                    "id": "note",
                    "action": "platform.timeline_note",
                    "target": "incident",
                    "params": {"text": "Playbook 'Enrich & ticket' started."},
                },
                {"id": "enrich", "action": "platform.enrich_asset", "target": "incident.primary_asset"},
                {
                    "id": "ticket",
                    "action": "itsm.create_incident",
                    "target": "incident",
                    "requires": ["note"],
                    "justification": "Track the incident in ServiceNow.",
                },
            ],
        },
    },
    {
        "key": "restart-unhealthy-service",
        "name": "Restart unhealthy service (DEMO)",
        "domain": "noc",
        "description": "Reboots the affected instance after a human approves (simulated in this build).",
        "definition": {
            "description": "Service-affecting: one approval.",
            "approval_timeout_minutes": 30,
            "steps": [
                {
                    "id": "note",
                    "action": "platform.timeline_note",
                    "target": "incident",
                    "params": {"text": "Restart requested by playbook; awaiting approval."},
                },
                {
                    "id": "restart",
                    "action": "aws.reboot_instance",
                    "target": "incident.primary_asset",
                    "justification": "Instance unhealthy; restart to restore service.",
                    "requires": ["note"],
                },
            ],
        },
    },
    {
        "key": "contain-host",
        "name": "Contain host (DEMO)",
        "domain": "soc",
        "description": "Isolates the affected host with the EDR, then opens a ticket. Two approvers required.",
        "definition": {
            "description": "High impact: two distinct approvers.",
            "approval_timeout_minutes": 60,
            "steps": [
                {
                    "id": "note",
                    "action": "platform.timeline_note",
                    "target": "incident",
                    "params": {"text": "Containment playbook started."},
                },
                {
                    "id": "isolate",
                    "action": "edr.isolate_host",
                    "target": "incident.primary_asset",
                    "justification": "Contain suspected ransomware activity.",
                    "requires": ["note"],
                },
                {
                    "id": "ticket",
                    "action": "itsm.create_incident",
                    "target": "incident",
                    "requires": ["isolate"],
                    "on_failure": "continue",
                },
            ],
        },
    },
]
