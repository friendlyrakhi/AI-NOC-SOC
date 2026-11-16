import { Badge, Card, NotAvailable, PageHeader, Table, Td, formatDate } from "@/components/ui";
import { PORTAL_NAV } from "@/lib/nav";
import { apiGetOptional, getMe, has, type Schemas } from "@/lib/server/api";

type Portal = "noc" | "soc" | "command";

const TEXT: Record<Portal, { title: string; description: string }> = {
  noc: {
    title: "AI NOC",
    description: "Infrastructure and service health, operational alerts, topology and incidents.",
  },
  soc: {
    title: "AI SOC",
    description: "Security alert triage, cases, investigation and vulnerability exposure.",
  },
  command: {
    title: "Executive Command Center",
    description: "Cross-domain KPIs, SLA attainment, major incidents and risk posture.",
  },
};

export async function PortalOverview({ portal }: { portal: Portal }) {
  const me = await getMe();
  if (!me.portals.includes(portal)) return <NotAvailable what={TEXT[portal].title} />;
  const active = me.tenants.find((t) => t.id === me.active_tenant_id);

  if (me.mode === "aggregate") {
    const customers = (await apiGetOptional<Schemas["AggregateCustomerOut"][]>("/aggregate/customers")) ?? [];
    const activity = has(me, "audit:read")
      ? ((await apiGetOptional<Schemas["AggregateActivityOut"][]>("/aggregate/activity?limit=15")) ?? [])
      : null;
    return (
      <>
        <PageHeader
          title={`${TEXT[portal].title}: all customers`}
          description="Read-only view across the customers your MSP role is delegated to. Select a single customer to make changes."
        />
        <div className="grid gap-6 xl:grid-cols-2">
          <Card title={`Customers (${customers.length})`}>
            <Table head={["Customer", "Status", "Events (24h)"]} empty={customers.length === 0}>
              {customers.map((c) => (
                <tr key={c.id}>
                  <Td>
                    {c.name} <span className="text-muted font-mono text-xs">{c.slug}</span>
                  </Td>
                  <Td>
                    <Badge tone={c.status === "active" ? "success" : "warning"}>{c.status}</Badge>
                  </Td>
                  <Td>{c.events_24h}</Td>
                </tr>
              ))}
            </Table>
          </Card>
          <Card title="Recent activity across customers">
            {activity === null ? (
              <p className="text-muted text-sm">Requires the audit:read permission.</p>
            ) : (
              <Table head={["When", "Customer", "Action", "Outcome"]} empty={activity.length === 0}>
                {activity.map((a) => (
                  <tr key={a.id}>
                    <Td className="text-muted whitespace-nowrap text-xs">{formatDate(a.at)}</Td>
                    <Td>
                      <Badge>{a.tenant_name}</Badge>
                    </Td>
                    <Td className="font-mono text-xs">{a.action}</Td>
                    <Td>
                      <Badge tone={a.outcome === "success" ? "success" : "danger"}>{a.outcome}</Badge>
                    </Td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        </div>
      </>
    );
  }

  const upcoming = PORTAL_NAV[portal].filter((i) => i.phase);
  return (
    <>
      <PageHeader title={TEXT[portal].title} description={TEXT[portal].description} />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Current context">
          <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
            <dt className="text-muted">Tenant</dt>
            <dd>
              {active?.name ?? "—"}{" "}
              {active && <Badge tone={active.kind === "msp" ? "info" : "neutral"}>{active.kind}</Badge>}
            </dd>
            <dt className="text-muted">Access</dt>
            <dd>{me.via_msp_tenant_id ? "Delegated by your MSP" : "Member"}</dd>
            <dt className="text-muted">Permissions</dt>
            <dd>{me.permissions.length}</dd>
          </dl>
        </Card>
        <Card title="Arriving in later phases">
          <ul className="space-y-1.5 text-sm">
            {upcoming.map((i) => (
              <li key={i.label} className="flex justify-between">
                <span>{i.label}</span>
                <Badge>{i.phase}</Badge>
              </li>
            ))}
          </ul>
          <p className="text-muted mt-4 text-xs">
            Data comes from sandbox connectors with mock data (P2). No live integrations are connected.
          </p>
        </Card>
      </div>
    </>
  );
}
