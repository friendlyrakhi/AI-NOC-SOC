import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { BarList, SegmentBar, TimeSeriesChart, fmt } from "./charts";
import { DemoBadge, HealthBadge, KpiTile, SeverityBadge } from "./indicators";
import { Tabs } from "./tabs";

const points = (n: number, base: number) =>
  Array.from({ length: n }, (_, i) => ({ date: `2026-11-${String(i + 1).padStart(2, "0")}`, value: base + i }));

describe("status indicators", () => {
  it("never rely on color alone: every state has a text label", () => {
    for (const s of ["critical", "high", "medium", "low", "info"] as const) {
      const { unmount } = render(<SeverityBadge severity={s} />);
      expect(screen.getByText(new RegExp(`^${s}$`, "i"))).toBeTruthy();
      unmount();
    }
    render(<HealthBadge status="down" />);
    expect(screen.getByText("Down")).toBeTruthy();
  });

  it("labels demo content", () => {
    render(<DemoBadge />);
    expect(screen.getByText("DEMO").getAttribute("title")).toMatch(/not from a live system/i);
  });

  it("states whether a delta is good or bad for the metric", () => {
    render(<KpiTile label="MTTR" value={3} delta={-12} goodWhen="down" />);
    expect(screen.getByText(/12%/).className).toContain("text-success");
  });
});

describe("TimeSeriesChart", () => {
  const series = [
    { name: "NOC", slot: 1 as const, points: points(10, 5) },
    { name: "SOC", slot: 2 as const, points: points(10, 2) },
  ];

  it("has an accessible name, a legend for 2+ series and a table view", () => {
    render(<TimeSeriesChart title="Alert volume" series={series} />);
    expect(screen.getByRole("img", { name: "Alert volume" })).toBeTruthy();
    expect(screen.getByRole("list", { name: "Legend" }).textContent).toContain("SOC");
    expect(screen.getByText("View data as table")).toBeTruthy();
    expect(screen.getAllByRole("row")).toHaveLength(11);
  });

  it("reads values with the keyboard", () => {
    render(<TimeSeriesChart title="Alert volume" series={series} />);
    const chart = screen.getByRole("img", { name: "Alert volume" });
    fireEvent.keyDown(chart, { key: "ArrowRight" });
    const tip = screen.getByRole("status");
    expect(tip.textContent).toContain("1 Nov");
    expect(tip.textContent).toContain("5");
  });

  it("shows an empty state without data", () => {
    render(<TimeSeriesChart title="Empty" series={[{ name: "x", slot: 1, points: [] }]} />);
    expect(screen.getByText("No data in this scope.")).toBeTruthy();
  });
});

describe("BarList and SegmentBar", () => {
  it("lists values as text", () => {
    render(<BarList label="Sources" items={[{ label: "Datadog", value: 12 }, { label: "SolarWinds", value: 4 }]} />);
    expect(screen.getByRole("list", { name: "Sources" }).textContent).toContain("Datadog12");
  });

  it("describes all parts for assistive tech", () => {
    render(<SegmentBar label="Severity" parts={[{ label: "Critical", value: 2, color: "red" }, { label: "Low", value: 5, color: "gray" }]} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("Severity: Critical 2, Low 5");
  });

  it("formats values", () => {
    expect(fmt(95, "minutes")).toBe("1.6 h");
    expect(fmt(12.345, "percent")).toBe("12.3%");
    expect(fmt(1234)).toBe("1,234");
  });
});

describe("Tabs", () => {
  it("switches panels with arrow keys", async () => {
    render(
      <Tabs
        tabs={[
          { label: "One", content: <p>first</p> },
          { label: "Two", content: <p>second</p> },
        ]}
      />,
    );
    expect(screen.getByRole("tabpanel").textContent).toBe("first");
    screen.getByRole("tab", { name: "One" }).focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Two" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tabpanel").textContent).toBe("second");
  });
});
