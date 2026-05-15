import { AlertTriangle } from "lucide-react";
import { useState } from "react";
import type { RuleDefinition } from "../../types";
import { issueStatusLabel, nodeLabel } from "../model/viewModels";
import type { IssueRow } from "../types";
import { formatRelative } from "../utils/time";
import { Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";

export function IssuesPage({
  actionLoading,
  issueRows,
  onIssue,
  onStatus,
  ruleByID,
  selectedIssue
}: {
  actionLoading: boolean;
  issueRows: IssueRow[];
  onIssue: (row: IssueRow) => void;
  onStatus: (row: IssueRow, status: string) => void;
  ruleByID: Map<string, RuleDefinition>;
  selectedIssue?: IssueRow;
}) {
  const [status, setStatus] = useState("active");
  const rows = issueRows.filter((row) => status === "all" || (status === "active" ? row.finding.status === "open" : row.finding.status === status));
  return (
    <section className="issue-queue">
      <Panel title="Issue queue" icon={AlertTriangle} action={<select value={status} onChange={(event) => setStatus(event.target.value)}>
        <option value="active">New only</option>
        <option value="all">All statuses</option>
        <option value="acknowledged">Triaged</option>
        <option value="resolved">Fixed</option>
        <option value="false_positive">False positive</option>
      </select>}>
        <ResponsiveTable>
          <thead>
            <tr>
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
                <td><SeverityPill value={row.finding.severity} /></td>
                <td><strong>{row.finding.title}</strong><small>{ruleByID.get(row.finding.rule_id)?.category ?? row.finding.rule_id}</small></td>
                <td>{row.instance.companyName}</td>
                <td>{row.instance.projectName}</td>
                <td>{nodeLabel(row.instance)}</td>
                <td>{row.service}</td>
                <td>
                  <StatusPill value={issueStatusLabel(row.finding.status, row.finding.status_reason)} />
                  <div className="inline-row-actions">
                    <button type="button" disabled={actionLoading} onClick={(event) => { event.stopPropagation(); onStatus(row, "acknowledged"); }}>Triaged</button>
                    <button type="button" disabled={actionLoading} onClick={(event) => { event.stopPropagation(); onStatus(row, "resolved"); }}>Fixed</button>
                  </div>
                </td>
                <td>{formatRelative(row.finding.last_event_at)}</td>
              </tr>
            ))}
          </tbody>
        </ResponsiveTable>
      </Panel>
    </section>
  );
}
