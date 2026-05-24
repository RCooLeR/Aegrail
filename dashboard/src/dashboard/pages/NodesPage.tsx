import { CheckCircle2, Eye, MonitorCog, Server, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import type { InstanceModel } from "../../estate";
import type { CoverageRecord } from "../../types";
import { nodeLabel } from "../model/viewModels";
import type { IssueRow } from "../types";
import { formatRelative } from "../utils/time";
import { EmptyState, MiniBlock, Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";
import { CollectorBadges, ServiceGrid } from "../components/summary";

export function NodesPage({
  actionLoading,
  instances,
  issueRows,
  onIssue,
  onStatus
}: {
  actionLoading: boolean;
  instances: InstanceModel[];
  issueRows: IssueRow[];
  onIssue: (row: IssueRow) => void;
  onStatus: (row: IssueRow, status: string) => void;
}) {
  const [selectedNodeKey, setSelectedNodeKey] = useState("");
  const selected = instances.find((instance) => instance.key === selectedNodeKey) ?? instances[0];

  useEffect(() => {
    if (!selected || selected.key !== selectedNodeKey) {
      setSelectedNodeKey(selected?.key ?? "");
    }
  }, [selected, selectedNodeKey]);

  return (
    <div className="page-stack">
      <Panel title="Nodes" icon={MonitorCog}>
        <ResponsiveTable>
          <thead>
            <tr>
              <th>Node</th>
              <th>Site</th>
              <th>Status</th>
              <th>Services</th>
              <th>Agent</th>
              <th>Open issues</th>
              <th>Last scan</th>
            </tr>
          </thead>
          <tbody>
            {instances.map((instance) => (
              <tr className={selected?.key === instance.key ? "selected" : ""} key={instance.key} onClick={() => setSelectedNodeKey(instance.key)}>
                <td><strong>{nodeLabel(instance)}</strong><small>{instance.appName}</small></td>
                <td>{instance.companyName} / {instance.projectName}</td>
                <td><StatusPill value={instance.status} /></td>
                <td><CollectorBadges collectors={instance.collectors} /></td>
                <td>{instance.activeAgentCount}/{instance.agentCount} online</td>
                <td>{instance.openFindings}</td>
                <td>{formatRelative(instance.lastSignalAt)}</td>
              </tr>
            ))}
            {instances.length === 0 && (
              <tr><td colSpan={7}><EmptyState title="No nodes match the current filters" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>
      {selected && (
        <Panel title={`${nodeLabel(selected)} overview`} icon={Server}>
          <div className="node-overview-grid">
            <MiniBlock label="Company" value={selected.companyName} />
            <MiniBlock label="Site" value={selected.projectName} />
            <MiniBlock label="Status" value={selected.status} />
            <MiniBlock label="Last scan" value={formatRelative(selected.lastSignalAt)} />
          </div>
          <h3>Services</h3>
          <ServiceGrid instance={selected} issueRows={issueRows.filter((row) => row.instance.key === selected.key)} />
          <h3>Agent config</h3>
          <AgentConfigSummary coverage={selected.latestCoverage} />
          <h3>Open issues</h3>
          <NodeIssueList
            actionLoading={actionLoading}
            rows={issueRows.filter((row) => row.instance.key === selected.key && row.finding.status === "open").slice(0, 6)}
            onIssue={onIssue}
            onStatus={onStatus}
          />
        </Panel>
      )}
    </div>
  );
}

type SafeFileIgnore = {
  path: string;
  risk: string;
  scope: string;
};

function AgentConfigSummary({ coverage }: { coverage?: CoverageRecord }) {
  const config = coverageConfig(coverage);
  if (!coverage || !config) {
    return <EmptyState title="No agent config coverage yet" />;
  }

  const files = section(config, "files");
  const logs = section(config, "logs");
  const databases = section(config, "databases");
  const browser = section(config, "browser");
  const ignoredPaths = fileIgnores(files);
  const profiles = stringList(files.profiles);
  const databaseNames = stringList(databases.names);
  const databaseProfiles = stringList(databases.profiles);
  const logKinds = stringList(logs.kinds);
  const highRiskIgnores = ignoredPaths.filter((item) => item.risk === "high").length;

  return (
    <div className="agent-config-grid">
      <div className="agent-config-card">
        <strong>Files</strong>
        <span>{enabledLabel(files.enabled)} / {profiles.join(", ") || "no profile"}</span>
        <small>{numberValue(files.extra_paths)} extra path(s), {numberValue(files.exclude_patterns)} ignore rule(s)</small>
        {highRiskIgnores > 0 && <em>{highRiskIgnores} high-risk ignore{highRiskIgnores === 1 ? "" : "s"}</em>}
      </div>
      <div className="agent-config-card">
        <strong>Database</strong>
        <span>{enabledLabel(databases.enabled)} / {databaseNames.join(", ") || "no database"}</span>
        <small>{databaseProfiles.join(", ") || "no profile"}; DSN env {databases.all_dsn_env_configured === false ? "missing" : "configured"}; {databases.all_persistent === false ? "one-shot" : "persistent"} connections</small>
      </div>
      <div className="agent-config-card">
        <strong>Logs</strong>
        <span>{enabledLabel(logs.enabled)} / {numberValue(logs.count)} file(s)</span>
        <small>{logKinds.join(", ") || "no log kinds"}</small>
      </div>
      <div className="agent-config-card">
        <strong>Browser</strong>
        <span>{enabledLabel(browser.enabled)} / {numberValue(browser.urls)} URL(s)</span>
        <small>{browser.rendered ? "rendered" : "basic"} crawl, max {numberValue(browser.max_pages)} page(s)</small>
      </div>
      <div className="agent-config-card wide">
        <strong>Ignored by agent</strong>
        {ignoredPaths.length > 0 ? (
          <ul className="agent-ignore-list">
            {ignoredPaths.map((item) => (
              <li className={item.risk} key={`${item.scope}:${item.path}`}>
                <span>{item.path}</span>
                <small>{ignoreScopeLabel(item.scope)} / {item.risk || "medium"} risk</small>
              </li>
            ))}
          </ul>
        ) : (
          <small>No file ignore paths reported by this agent.</small>
        )}
      </div>
    </div>
  );
}

function coverageConfig(record?: CoverageRecord) {
  const value = record?.payload.coverage;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function section(config: Record<string, unknown>, key: string) {
  const value = config[key];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {} as Record<string, unknown>;
  }
  return value as Record<string, unknown>;
}

function fileIgnores(files: Record<string, unknown>): SafeFileIgnore[] {
  const value = files.ignored_paths;
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const path = typeof record.path === "string" ? record.path.trim() : "";
    if (!path) return [];
    return [{
      path,
      risk: typeof record.risk === "string" && record.risk.trim() ? record.risk.trim() : "medium",
      scope: typeof record.scope === "string" && record.scope.trim() ? record.scope.trim() : "unknown"
    }];
  });
}

function stringList(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function numberValue(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function enabledLabel(value: unknown) {
  return value === false ? "disabled" : value === true ? "enabled" : "unknown";
}

function ignoreScopeLabel(scope: string) {
  switch (scope) {
    case "site_relative":
      return "site path";
    case "site_root":
      return "whole site";
    case "outside_site_root":
      return "outside site root";
    default:
      return scope || "unknown";
  }
}

function NodeIssueList({
  actionLoading,
  rows,
  onIssue,
  onStatus
}: {
  actionLoading: boolean;
  rows: IssueRow[];
  onIssue: (row: IssueRow) => void;
  onStatus: (row: IssueRow, status: string) => void;
}) {
  if (rows.length === 0) {
    return <EmptyState title="No open issues" />;
  }

  return (
    <div className="node-issue-list">
      {rows.map((row) => (
        <div className="node-issue-row" key={`${row.instance.key}:${row.finding.id}`}>
          <SeverityPill value={row.finding.severity} />
          <span>
            <strong>{row.finding.title}</strong>
            <small>{row.service} / {formatRelative(row.finding.last_event_at)}</small>
          </span>
          <div className="node-issue-actions">
            <button className="ghost-button compact" type="button" onClick={() => onIssue(row)}>
              <Eye size={14} />
              Details
            </button>
            <button className="ghost-button compact" type="button" disabled={actionLoading} onClick={() => onStatus(row, "acknowledged")}>
              <Eye size={14} />
              Acknowledge
            </button>
            <button className="ghost-button compact" type="button" disabled={actionLoading} onClick={() => onStatus(row, "resolved")}>
              <CheckCircle2 size={14} />
              Fixed
            </button>
            <button className="ghost-button compact" type="button" disabled={actionLoading} onClick={() => onStatus(row, "false_positive")}>
              <XCircle size={14} />
              False positive
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
