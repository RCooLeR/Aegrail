import { collectorIsProblem, type CollectorState, type InstanceModel } from "../../estate";
import type { InventoryOrganization } from "../../types";
import { nodeLabel, serviceFromCollector, signalTypeLabel } from "../model/viewModels";
import type { IssueRow, SignalRow, SiteRow } from "../types";
import { formatRelative, titleCase } from "../utils/time";
import { EmptyState, MiniBlock, SeverityPill, StatusPill } from "./common";

export function IssueList({ onIssue, rows }: { onIssue: (row: IssueRow) => void; rows: IssueRow[] }) {
  if (rows.length === 0) {
    return <EmptyState title="No open issues" />;
  }
  return (
    <div className="stack-list">
      {rows.map((row) => (
        <button className="stack-row" key={`${row.instance.key}:${row.finding.id}`} type="button" onClick={() => onIssue(row)}>
          <SeverityPill value={row.finding.severity} />
          <span>
            <strong>{row.finding.title}</strong>
            <small>{row.instance.companyName} / {row.instance.projectName} / {nodeLabel(row.instance)} / {row.service}</small>
          </span>
          <em>{formatRelative(row.finding.last_event_at)}</em>
        </button>
      ))}
    </div>
  );
}

export function SignalList({ rows }: { rows: SignalRow[] }) {
  if (rows.length === 0) {
    return <EmptyState title="No signals" />;
  }
  return (
    <div className="timeline-list">
      {rows.map((row) => (
        <div className="timeline-row" key={`${row.instance.key}:${row.event.id}`}>
          <span className={`status-dot ${row.event.severity}`} />
          <span>
            <strong>{signalTypeLabel(row.event)}</strong>
            <small>{row.instance.projectName} / {nodeLabel(row.instance)} / {formatRelative(row.event.event_time)}</small>
            <p>{row.event.message || row.event.target}</p>
          </span>
        </div>
      ))}
    </div>
  );
}

export function SiteRiskList({ sites }: { sites: SiteRow[] }) {
  if (sites.length === 0) {
    return <EmptyState title="No sites" />;
  }
  return (
    <div className="stack-list">
      {sites.map((site) => (
        <div className="stack-row passive" key={site.key}>
          <StatusPill value={site.status} />
          <span>
            <strong>{site.companyName} / {site.projectName}</strong>
            <small>{site.openIssues} open / {site.instances.length} nodes / {site.statusReason}</small>
          </span>
          <em>{formatRelative(site.lastSignalAt)}</em>
        </div>
      ))}
    </div>
  );
}

export function HealthRows({ instances }: { instances: InstanceModel[] }) {
  const collectorRows = ["files", "database", "logs", "browser", "config"].map((key) => {
    const collectors = instances.flatMap((instance) => instance.collectors).filter((collector) => collector.key === key);
    const bad = collectors.filter(collectorIsProblem).length;
    return { bad, key, total: collectors.length };
  });
  return (
    <div className="health-grid">
      <MiniBlock label="Agents online" value={`${instances.reduce((sum, instance) => sum + instance.activeAgentCount, 0)}/${instances.reduce((sum, instance) => sum + instance.agentCount, 0)}`} />
      {collectorRows.map((row) => <MiniBlock key={row.key} label={`${titleCase(row.key)} collector`} value={row.bad === 0 ? "OK" : `${row.bad}/${row.total} warning`} />)}
    </div>
  );
}

export function ServiceGrid({ instance, issueRows }: { instance: InstanceModel; issueRows: IssueRow[] }) {
  return (
    <div className="service-grid">
      {instance.collectors.map((collector) => {
        const openIssues = issueRows.filter((row) => row.service === serviceFromCollector(collector.key) && row.finding.status === "open");
        return (
          <div className="service-card" key={collector.key}>
            <StatusPill value={collector.status} />
            <strong>{serviceFromCollector(collector.key)}</strong>
            <small>Collector: {collector.label}</small>
            <small>{collector.detail}</small>
            <small>Last scan: {formatRelative(collector.lastSeenAt)}</small>
            <small>Open issues: {openIssues.length}</small>
          </div>
        );
      })}
    </div>
  );
}

export function CollectorBadges({ collectors }: { collectors: CollectorState[] }) {
  return <div className="collector-badges">{collectors.map((collector) => <StatusPill key={collector.key} value={collector.label} tone={collector.status === "disabled" ? "neutral" : collector.status} />)}</div>;
}

export function InventorySummary({ organizations }: { organizations: InventoryOrganization[] }) {
  const sites = organizations.reduce((total, organization) => total + organization.projects.length, 0);
  const nodes = organizations.reduce((total, organization) =>
    total + organization.projects.reduce((projectTotal, project) =>
      projectTotal + project.environments.reduce((environmentTotal, environment) => environmentTotal + Math.max(environment.apps.length, 1), 0),
      0
    ),
    0
  );
  return (
    <div className="health-grid">
      <MiniBlock label="Companies" value={String(organizations.length)} />
      <MiniBlock label="Sites" value={String(sites)} />
      <MiniBlock label="Nodes" value={String(nodes)} />
    </div>
  );
}
