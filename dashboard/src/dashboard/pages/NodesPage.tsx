import { CheckCircle2, Eye, MonitorCog, Server, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import type { InstanceModel } from "../../estate";
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
              Triaged
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
