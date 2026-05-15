import { Activity } from "lucide-react";
import { collectorLabel, nodeLabel, signalTypeLabel } from "../model/viewModels";
import type { SignalRow } from "../types";
import { formatRelative } from "../utils/time";
import { Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";

export function SignalsPage({ rows }: { rows: SignalRow[] }) {
  const serviceCounts = summarizeServices(rows);
  return (
    <Panel
      title="Signals"
      icon={Activity}
      action={<SignalSummary counts={serviceCounts} total={rows.length} />}
    >
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Time</th>
            <th>Site</th>
            <th>Signal</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Target</th>
            <th>Linked issue</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const tone = signalTone(row);
            return (
              <tr className={`signal-row ${tone} ${signalRisk(row)} ${row.issue ? "has-issue" : ""}`} key={`${row.instance.key}:${row.event.id}`}>
                <td className="signal-time">
                  <strong>{formatRelative(row.event.event_time)}</strong>
                  <small>{formatRelative(row.event.received_time)} received</small>
                </td>
                <td>
                  <SiteIdentity row={row} />
                </td>
                <td>
                  <div className="signal-title">
                    <StatusPill value={signalTypeLabel(row.event)} tone={tone} />
                    <strong>{row.event.message || signalTypeLabel(row.event)}</strong>
                    <small>{row.event.type}</small>
                  </div>
                </td>
                <td>
                  <div className="signal-badges">
                    <StatusPill value={row.service} tone={tone} />
                    <span className="signal-badge">{collectorLabel(row.event)}</span>
                    <span className="signal-badge">{nodeLabel(row.instance)}</span>
                  </div>
                </td>
                <td><SeverityPill value={row.event.severity} /></td>
                <td>
                  <strong>{signalTarget(row)}</strong>
                  <small>{signalContext(row)}</small>
                </td>
                <td>
                  {row.issue ? (
                    <div className="linked-issue">
                      <SeverityPill value={row.issue.severity} />
                      <span>{row.issue.title}</span>
                    </div>
                  ) : (
                    <span className="signal-muted">No issue</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}

function SignalSummary({ counts, total }: { counts: Array<[string, number]>; total: number }) {
  return (
    <div className="signal-summary" aria-label="Signal counts">
      <span>{total} total</span>
      {counts.slice(0, 4).map(([service, count]) => (
        <span key={service}>{service}: {count}</span>
      ))}
    </div>
  );
}

function SiteIdentity({ row }: { row: SignalRow }) {
  const iconURL = row.instance.iconUrls[0] ?? "";
  const initials = siteInitials(row.instance.projectName);
  return (
    <div className="signal-site">
      <span className="site-favicon" aria-hidden="true">
        <span>{initials}</span>
        {iconURL && <img src={iconURL} alt="" loading="lazy" onError={(event) => event.currentTarget.remove()} />}
      </span>
      <span>
        <strong>{row.instance.projectName}</strong>
        <small>{row.instance.companyName}</small>
      </span>
    </div>
  );
}

function summarizeServices(rows: SignalRow[]) {
  const counts = new Map<string, number>();
  for (const row of rows) {
    counts.set(row.service, (counts.get(row.service) ?? 0) + 1);
  }
  return Array.from(counts.entries()).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
}

function signalTone(row: SignalRow) {
  if (row.event.type.startsWith("db.")) return "database";
  if (row.event.type.startsWith("file.")) return "files";
  if (row.event.type.startsWith("browser.")) return "browser";
  if (row.event.type.includes("coverage") || row.event.type.includes("config")) return "config";
  if (row.event.type.startsWith("agent.")) return "agent";
  return "neutral";
}

function signalRisk(row: SignalRow) {
  return row.event.severity === "critical" || row.event.severity === "high" ? "risk" : "";
}

function signalTarget(row: SignalRow) {
  return firstText(
    payloadText(row.event.payload, "url_redacted"),
    payloadText(row.event.payload, "domain"),
    payloadText(row.event.payload, "relative_path"),
    payloadText(row.event.payload, "table"),
    row.event.target,
    row.event.host,
    row.event.hostname
  ) || "-";
}

function signalContext(row: SignalRow) {
  return firstText(
    payloadText(row.event.payload, "page_host"),
    payloadText(row.event.payload, "page_url"),
    payloadText(row.event.payload, "final_url"),
    payloadText(row.event.payload, "database"),
    payloadText(row.event.payload, "hash"),
    row.event.agent
  );
}

function payloadText(payload: Record<string, unknown>, key: string) {
  const value = payload[key];
  if (typeof value !== "string") return "";
  return value.trim();
}

function firstText(...values: Array<string | undefined>) {
  return values.find((value) => value && value.trim())?.trim() ?? "";
}

function siteInitials(value: string) {
  const parts = value.split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  return parts.slice(0, 2).map((part) => part[0]?.toUpperCase()).join("");
}
