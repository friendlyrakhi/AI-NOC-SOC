import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { DataTable, toCsv, type ColumnSpec, type Row } from "./data-table";

const columns: ColumnSpec[] = [
  { key: "name", header: "Name" },
  { key: "severity", header: "Severity", type: "severity", filter: true },
  { key: "count", header: "Count", type: "number" },
];

const rows: Row[] = Array.from({ length: 30 }, (_, i) => ({
  _id: `r${i}`,
  name: `host-${String(i).padStart(2, "0")}`,
  severity: (["critical", "high", "medium", "low"] as const)[i % 4],
  count: i,
  _details: { Host: `host-${i}`, Note: "details" },
}));

function bodyRows() {
  return screen.getAllByRole("row").slice(1);
}

describe("DataTable", () => {
  it("paginates", async () => {
    render(<DataTable caption="Hosts" rows={rows} columns={columns} pageSize={10} />);
    expect(bodyRows()).toHaveLength(10);
    expect(screen.getByText("Page 1 of 3")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Next →" }));
    expect(screen.getByText("Page 2 of 3")).toBeTruthy();
    expect(screen.getByText("host-10")).toBeTruthy();
  });

  it("searches across columns and reports the count", async () => {
    render(<DataTable caption="Hosts" rows={rows} columns={columns} />);
    await userEvent.type(screen.getByRole("searchbox", { name: "Search Hosts" }), "host-2");
    expect(screen.getByRole("status").textContent).toContain("10 of 30");
  });

  it("filters by a column value", async () => {
    render(<DataTable caption="Hosts" rows={rows} columns={columns} pageSize={100} />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Severity" }), "critical");
    expect(bodyRows()).toHaveLength(8);
    for (const row of bodyRows()) expect(within(row).getByText("Critical")).toBeTruthy();
  });

  it("sorts with aria-sort and orders severity by rank", async () => {
    render(<DataTable caption="Hosts" rows={rows} columns={columns} pageSize={100} />);
    const header = screen.getByRole("columnheader", { name: /Severity/ });
    await userEvent.click(within(header).getByRole("button"));
    expect(header.getAttribute("aria-sort")).toBe("ascending");
    expect(within(bodyRows()[0]).getByText("Critical")).toBeTruthy();
    await userEvent.click(within(header).getByRole("button"));
    expect(header.getAttribute("aria-sort")).toBe("descending");
    expect(within(bodyRows()[0]).getByText("Low")).toBeTruthy();
  });

  it("opens a details dialog for drill-down", async () => {
    render(<DataTable caption="Hosts" rows={rows} columns={columns} />);
    await userEvent.click(screen.getByRole("button", { name: "host-00" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("details")).toBeTruthy();
    await userEvent.click(within(dialog).getByRole("button", { name: "Close details" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("shows an empty state", () => {
    render(<DataTable caption="Hosts" rows={[]} columns={columns} emptyText="Nothing here." />);
    expect(screen.getByText("Nothing here.")).toBeTruthy();
  });
});

describe("CSV export", () => {
  it("escapes quotes and neutralises spreadsheet formulas", () => {
    const csv = toCsv(
      [{ key: "a", header: "A" }],
      [
        { _id: "1", a: '=HYPERLINK("http://x")' },
        { _id: "2", a: 'say "hi", ok' },
      ],
    );
    expect(csv.split("\n")[1]).toBe(`"'=HYPERLINK(""http://x"")"`);
    expect(csv.split("\n")[2]).toBe(`"say ""hi"", ok"`);
  });

  it("neutralises every formula trigger, including tab and carriage return", () => {
    for (const lead of ["=", "+", "-", "@", "\t", "\r"]) {
      const csv = toCsv([{ key: "a", header: "A" }], [{ _id: "1", a: `${lead}cmd|' /C calc'!A0` }]);
      expect(csv.slice(csv.indexOf("\n") + 1).replace(/^"/, "")).toMatch(/^'/);
    }
  });
});

describe("health sorting", () => {
  it("orders by operational impact, not alphabetically", async () => {
    const hosts: Row[] = ["healthy", "maintenance", "degraded", "down"].map((status, i) => ({ _id: String(i), name: `h${i}`, status }));
    render(<DataTable caption="Health" rows={hosts} columns={[{ key: "name", header: "Name" }, { key: "status", header: "Health", type: "health" }]} initialSort={{ key: "status", dir: "asc" }} />);
    const order = screen.getAllByRole("row").slice(1).map((r) => r.textContent);
    expect(order).toEqual(["h3Down", "h2Degraded", "h1Maintenance", "h0Healthy"]);
  });
});
