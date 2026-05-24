import { AlertTriangle, CheckCircle2, Eye, Loader2, XCircle } from "lucide-react";
import { useState } from "react";
import type { RuleDefinition } from "../../types";
import { issueStatusLabel, nodeLabel } from "../model/viewModels";
import type { IssueRow } from "../types";
import { formatRelative } from "../utils/time";
import { EmptyState, Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";

export function IssuesPage({
  actionLoading,
  issueRows,
  onIssue,
  onBulkStatus,
  onStatus,
  ruleByID,
  selectedIssue
}: {
  actionLoading: boolean;
  issueRows: IssueRow[];
  onIssue: (row: IssueRow) => void;
  onBulkStatus: (rows: IssueRow[], status: string) => Promise<void>;
  onStatus: (row: IssueRow, status: string) => void;
  ruleByID: Map<string, RuleDefinition>;
  selectedIssue?: IssueRow;
}) {
  const [status, setStatus] = useState("active");
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(() => new Set());
  const rows = issueRows.filter((row) => status === "all" || (status === "active" ? row.finding.status === "open" : row.finding.status === status));
  const selectedRows = rows.filter((row) => selectedKeys.has(issueRowKey(row)));
  const allVisibleSelected = rows.length > 0 && selectedRows.length === rows.length;

  function toggleRow(row: IssueRow, checked: boolean) {
    setSelectedKeys((current) => {
      const next = new Set(current);
      const key = issueRowKey(row);
      if (checked) {
        next.add(key);
      } else {
        next.delete(key);
      }
      return next;
    });
  }

  function toggleVisible(checked: boolean) {
    setSelectedKeys((current) => {
      const next = new Set(current);
      for (const row of rows) {
        const key = issueRowKey(row);
        if (checked) {
          next.add(key);
        } else {
          next.delete(key);
        }
      }
      return next;
    });
  }

  async function handleBulkStatus(nextStatus: string) {
    try {
      await onBulkStatus(selectedRows, nextStatus);
      setSelectedKeys(new Set());
    } catch {
      // The controller already exposes the error in the global action banner.
    }
  }

  return (
    <section className="issue-queue">
      <Panel title="Issue queue" icon={AlertTriangle} action={<select value={status} onChange={(event) => setStatus(event.target.value)}>
        <option value="active">New only</option>
        <option value="all">All statuses</option>
        <option value="acknowledged">Acknowledged</option>
        <option value="resolved">Fixed</option>
        <option value="false_positive">False positive</option>
      </select>}>
        <div className="bulk-action-bar">
          <span>{selectedRows.length} selected</span>
          <button className="ghost-button compact" type="button" disabled={actionLoading || selectedRows.length === 0} onClick={() => void handleBulkStatus("acknowledged")}>
            {actionLoading ? <Loader2 size={14} className="spin" /> : <Eye size={14} />}
            Acknowledge
          </button>
          <button className="ghost-button compact" type="button" disabled={actionLoading || selectedRows.length === 0} onClick={() => void handleBulkStatus("resolved")}>
            <CheckCircle2 size={14} />
            Fixed
          </button>
          <button className="ghost-button compact" type="button" disabled={actionLoading || selectedRows.length === 0} onClick={() => void handleBulkStatus("false_positive")}>
            <XCircle size={14} />
            False positive
          </button>
          {selectedRows.length > 0 && (
            <button className="link-button" type="button" disabled={actionLoading} onClick={() => setSelectedKeys(new Set())}>
              Clear
            </button>
          )}
        </div>
        <ResponsiveTable>
          <thead>
            <tr>
              <th className="select-cell">
                <input
                  aria-label="Select all visible issues"
                  checked={allVisibleSelected}
                  disabled={rows.length === 0}
                  onChange={(event) => toggleVisible(event.target.checked)}
                  type="checkbox"
                />
              </th>
              <th>Severity</th>
              <th>Issue</th>
              <th>Company</th>
              <th>Site</th>
              <th>Node</th>
              <th>Service</th>
              <th>Status</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr className={selectedIssue?.finding.id === row.finding.id ? "selected" : ""} key={`${row.instance.key}:${row.finding.id}`} onClick={() => onIssue(row)}>
                <td className="select-cell" onClick={(event) => event.stopPropagation()}>
                  <input
                    aria-label={`Select ${row.finding.title}`}
                    checked={selectedKeys.has(issueRowKey(row))}
                    onChange={(event) => toggleRow(row, event.target.checked)}
                    type="checkbox"
                  />
                </td>
                <td><SeverityPill value={row.finding.severity} /></td>
                <td><strong>{row.finding.title}</strong><small>{ruleByID.get(row.finding.rule_id)?.category ?? row.finding.rule_id}</small></td>
                <td>{row.instance.companyName}</td>
                <td>{row.instance.projectName}</td>
                <td>{nodeLabel(row.instance)}</td>
                <td>{row.service}</td>
                <td>
                  <StatusPill value={issueStatusLabel(row.finding.status, row.finding.status_reason)} />
                  <div className="inline-row-actions">
                    <button type="button" disabled={actionLoading} onClick={(event) => { event.stopPropagation(); onStatus(row, "acknowledged"); }}>Acknowledge</button>
                    <button type="button" disabled={actionLoading} onClick={(event) => { event.stopPropagation(); onStatus(row, "resolved"); }}>Fixed</button>
                  </div>
                </td>
                <td>{formatRelative(row.finding.last_event_at)}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={9}><EmptyState title="No issues match" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>
    </section>
  );
}

function issueRowKey(row: IssueRow) {
  return `${row.instance.key}:${row.finding.id}`;
}
