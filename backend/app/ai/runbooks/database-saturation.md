# Database CPU saturation and connection exhaustion

Applies when a database instance runs at high CPU and connections approach the limit.

Signs: cloud CPU utilisation alarm on the database, too-many-connections alerts, latency or SLO alerts on the services that use it.

Steps:
1. Identify the top queries by CPU and recent deploys or schema changes.
2. Check connection pool sizing in the calling services; look for retry storms.
3. Consider read replicas or scaling only after the cause is understood.
4. Communicate impact on order processing to the service owner.
