import { BarList, TimeSeriesChart } from "@/components/charts";
import { DemoBadge, DemoNotice } from "@/components/indicators";
import { gate } from "@/components/page-states";
import { Card, PageHeader } from "@/components/ui";
import { minutes } from "@/lib/format";
import { getDemo } from "@/lib/server/demo";
import { avgLast } from "@/lib/severity";

export async function DemoReports() {
  const { me, data, aggregate } = await getDemo();
  const denied = gate(me, "report:read", "Reports");
  if (denied) return denied;
  const k = data.kpis;
  const breakdown = (aggregate ? data.tenants : []).map((t) => ({
    label: t.name,
    value: data.incidents.filter((i) => i.tenant.id === t.id).length,
  }));
  return (
    <>
      <PageHeader
        title="Reports"
        description="30-day operational and security reporting. Every chart has a table view and a CSV download (files are suffixed -DEMO)."
        actions={<DemoBadge />}
      />
      <DemoNotice>Demo trend charts. Saved reports with CSV and PDF export need the analytics store and a selected customer.</DemoNotice>

      <h2 className="mb-3 text-sm font-semibold">Operations</h2>
      <div className="grid gap-6 xl:grid-cols-2">
        <Card title={`Mean time to acknowledge · 7-day average ${minutes(avgLast(k.mttaMinutes))}`}>
          <TimeSeriesChart title="Daily mean time to acknowledge" series={[{ name: "MTTA", slot: 1, points: k.mttaMinutes }]} format="minutes" exportName="report-mtta" />
        </Card>
        <Card title={`Mean time to resolve · 7-day average ${minutes(avgLast(k.mttrMinutes))}`}>
          <TimeSeriesChart title="Daily mean time to resolve" series={[{ name: "MTTR", slot: 1, points: k.mttrMinutes }]} format="minutes" exportName="report-mttr" />
        </Card>
        <Card title="Alert volume by domain">
          <TimeSeriesChart
            title="Daily alert volume for NOC and SOC"
            series={[
              { name: "NOC", slot: 1, points: k.nocAlerts },
              { name: "SOC", slot: 2, points: k.socAlerts },
            ]}
            exportName="report-alert-volume"
          />
        </Card>
        <Card title="SLA attainment">
          <TimeSeriesChart title="Daily SLA attainment" series={[{ name: "SLA attainment", slot: 1, points: k.slaAttainment }]} format="percent" yMin={90} yMax={100} exportName="report-sla" />
        </Card>
      </div>

      <h2 className="mt-8 mb-3 text-sm font-semibold">Security and automation</h2>
      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="Open critical vulnerabilities">
          <TimeSeriesChart title="Open critical vulnerabilities per day" series={[{ name: "Critical vulnerabilities", slot: 2, points: k.criticalVulns }]} exportName="report-critical-vulns" />
        </Card>
        <Card title="Automation rate (simulated actions)">
          <TimeSeriesChart title="Share of response steps automated per day" series={[{ name: "Automation rate", slot: 3, points: k.automationRate }]} format="percent" exportName="report-automation" />
        </Card>
        {aggregate && (
          <Card title="Incidents by customer (30 days)">
            <BarList label="Incidents by customer" items={breakdown} />
          </Card>
        )}
      </div>
    </>
  );
}
