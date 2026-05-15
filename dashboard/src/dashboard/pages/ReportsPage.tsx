import { Download, FileText } from "lucide-react";
import type { InstanceModel } from "../../estate";
import type { IssueRow, ReportRow } from "../types";
import { exportDashboardBrief } from "../utils/reports";
import { formatRelative } from "../utils/time";
import { EmptyState, Panel, ResponsiveTable, StatusPill } from "../components/common";

export function ReportsPage({
  issueRows,
  reports,
  visibleInstances
}: {
  issueRows: IssueRow[];
  reports: ReportRow[];
  visibleInstances: InstanceModel[];
}) {
  return (
    <div className="page-stack">
      <Panel
        title="Reports"
        icon={FileText}
        action={<button className="ghost-button" type="button" onClick={() => exportDashboardBrief(visibleInstances, issueRows)}><Download size={15} /> Export summary</button>}
      >
        <ResponsiveTable>
          <thead>
            <tr>
              <th>Report</th>
              <th>Company</th>
              <th>Site</th>
              <th>Issues included</th>
              <th>Created</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {reports.map(({ instance, report }) => (
              <tr key={`${instance.key}:${report.id}`}>
                <td><strong>{report.prompt_template_id}</strong><small>{report.model_name || report.model_provider || "model report"}</small></td>
                <td>{instance.companyName}</td>
                <td>{instance.projectName}</td>
                <td>{report.source_finding_ids.length}</td>
                <td>{formatRelative(report.generated_at)}</td>
                <td><StatusPill value={report.status} /></td>
              </tr>
            ))}
            {reports.length === 0 && (
              <tr><td colSpan={6}><EmptyState title="No saved reports yet" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>
    </div>
  );
}
