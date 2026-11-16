import { describe, expect, it } from "vitest";

import { CONNECTORS, connectorStatus } from "./connectors";
import { formatTime, minutes, relativeTime, weekDelta } from "./format";

describe("connector catalog", () => {
  it("covers every target integration", () => {
    const ids = CONNECTORS.map((c) => c.id);
    for (const id of [
      "solarwinds.orion", "datadog", "prometheus", "grafana", "aws.cloudwatch", "azure.monitor", "gcp.cloud_ops",
      "microsoft.sentinel", "splunk", "wazuh", "crowdstrike.falcon", "microsoft.defender", "qualys.vmdr", "tenable", "servicenow.itsm",
    ]) {
      expect(ids).toContain(id);
    }
  });

  it("never reports a connection that does not exist", () => {
    const status = connectorStatus();
    expect(status.status).toBe("not_configured");
    expect(status.label).not.toMatch(/connected|healthy|live/i);
  });
});

describe("formatting", () => {
  it("is deterministic in UTC", () => {
    expect(formatTime("2026-11-16T09:05:00Z")).toBe("16 Nov 09:05 UTC");
  });

  it("formats durations and relative times", () => {
    expect(minutes(45)).toBe("45 min");
    expect(minutes(135)).toBe("2 h 15 min");
    const now = Date.parse("2026-11-16T10:00:00Z");
    expect(relativeTime("2026-11-16T09:00:00Z", now)).toBe("1 h ago");
    expect(relativeTime("2026-11-18T10:00:00Z", now)).toBe("in 2 d");
  });

  it("computes week-over-week change", () => {
    const pts = [...Array(7).fill({ value: 10 }), ...Array(7).fill({ value: 15 })];
    expect(weekDelta(pts)).toBeCloseTo(50);
  });
});
