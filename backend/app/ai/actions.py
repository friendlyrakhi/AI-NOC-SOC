"""Action keys the AI may *suggest* (never execute), by connector.

A static copy of the connector manifests' action keys: the AI module must not import the
connector catalog, which holds the executors (architecture rule AI-5, LLM06). A test checks this
table against the manifests so it cannot drift. Suggestions become approval requests in P5,
and AI-originated requests always need a human approval.
"""

SUGGESTIBLE: dict[str, tuple[str, ...]] = {
    "aws.cloudwatch": ("aws.reboot_instance",),
    "azure.monitor": ("azure.restart_vm",),
    "crowdstrike.falcon": ("edr.isolate_host", "edr.release_host"),
    "datadog": ("dd.mute_monitor",),
    "gcp.cloud_ops": ("gcp.restart_instance",),
    "generic.webhook": (),
    "grafana": ("grafana.silence", "grafana.annotate"),
    "microsoft.defender": ("mde.isolate_device", "mde.run_av_scan"),
    "microsoft.sentinel": ("sentinel.update_incident",),
    "prometheus": ("am.create_silence",),
    "qualys.vmdr": (),
    "servicenow.itsm": ("itsm.create_incident", "itsm.update_incident", "itsm.create_change"),
    "solarwinds.orion": ("nms.ack_alert", "nms.unmanage_node"),
    "splunk": ("splunk.update_notable",),
    "tenable": (),
    "wazuh": ("wazuh.active_response",),
}


def allowed_for(connectors: set[str]) -> list[str]:
    return sorted({key for c in connectors for key in SUGGESTIBLE.get(c, ())})
