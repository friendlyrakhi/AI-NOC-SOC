# Core network outage (switch or distribution layer down)

Applies when a core or distribution switch stops responding and hosts behind it go down at the same time.

Signs: node down and interface down alerts on a core switch, BGP or OSPF neighbor loss on the distribution switch, then scrape target down and error-rate alerts on application hosts behind it.

Steps:
1. Confirm the switch is unreachable from two monitoring sources (NMS and metrics).
2. Check power, the uplinks and the redundant peer switch. Engage the network on-call.
3. Treat downstream host and application alerts as symptoms; do not restart application servers.
4. Open or link a ServiceNow incident for the affected business services.
5. After recovery, confirm targets are scraped again and error rates return to baseline.
