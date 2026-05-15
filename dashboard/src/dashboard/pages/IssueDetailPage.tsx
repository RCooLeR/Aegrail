import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Brain,
  CheckCircle2,
  Eye,
  FileText,
  Link2,
  MessageSquare,
  ShieldCheck,
  XCircle
} from "lucide-react";
import { useState } from "react";
import type { RuleDefinition } from "../../types";
import { collectorLabel, issueStatusLabel, nodeLabel, recommendedAction, signalTypeLabel } from "../model/viewModels";
import type { IssueRow, ReportRow, SignalRow } from "../types";
import { firstMetadataString, metadataNumber, metadataString, metadataStringList } from "../utils/metadata";
import { exportIssueBrief } from "../utils/reports";
import { formatDate, formatRelative } from "../utils/time";
import { EmptyState, Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";

type IssueDetailTab = "overview" | "evidence" | "timeline" | "comments" | "related" | "analysis";

const tabs: Array<{ key: IssueDetailTab; label: string }> = [
  { key: "overview", label: "Overview" },
  { key: "evidence", label: "Evidence" },
  { key: "timeline", label: "Timeline" },
  { key: "comments", label: "Comments" },
  { key: "related", label: "Related issues" },
  { key: "analysis", label: "LLM analysis" }
];

export function IssueDetailPage({
  actionLoading,
  issueRows,
  onAllowScript,
  onBack,
  onIssue,
  onStatus,
  reportRows,
  row,
  rule,
  signalRows
}: {
  actionLoading: boolean;
  issueRows: IssueRow[];
  onAllowScript: (row: IssueRow) => void;
  onBack: () => void;
  onIssue: (row: IssueRow) => void;
  onStatus: (row: IssueRow, status: string) => void;
  reportRows: ReportRow[];
  row?: IssueRow;
  rule?: RuleDefinition;
  signalRows: SignalRow[];
}) {
  const [activeTab, setActiveTab] = useState<IssueDetailTab>("overview");

  if (!row) {
    return (
      <Panel
        title="Issue detail"
        icon={AlertTriangle}
        action={<button className="ghost-button" type="button" onClick={onBack}><ArrowLeft size={15} /> Issues</button>}
      >
        <EmptyState title="Issue not found" />
      </Panel>
    );
  }

  const { finding, instance, service } = row;
  const linkedEventIDs = new Set(finding.event_ids);
  const linkedSignals = signalRows.filter((signal) => signal.instance.key === instance.key && linkedEventIDs.has(signal.event.id));
  const relatedIssues = issueRows
    .filter((candidate) => candidate.finding.id !== finding.id)
    .filter((candidate) =>
      candidate.instance.key === instance.key ||
      candidate.finding.rule_id === finding.rule_id ||
      (candidate.instance.companySlug === instance.companySlug && candidate.instance.projectSlug === instance.projectSlug && candidate.service === service)
    )
    .slice(0, 8);
  const matchingReports = reportRows.filter((item) => item.report.source_finding_ids.includes(finding.id)).slice(0, 5);

  return (
    <section className="issue-workspace">
      <header className="issue-hero">
        <div className="issue-hero-main">
          <button className="link-button" type="button" onClick={onBack}><ArrowLeft size={15} /> Issues</button>
          <div className="issue-title-row">
            <SeverityPill value={finding.severity} />
            <StatusPill value={issueStatusLabel(finding.status, finding.status_reason)} />
          </div>
          <h2>{finding.title}</h2>
          <p>{finding.summary || finding.description || rule?.title || "No summary was returned."}</p>
        </div>
        <div className="issue-hero-actions">
          <button className="ghost-button" type="button" onClick={() => exportIssueBrief(row, rule)}><FileText size={15} /> Create report</button>
          <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onStatus(row, "acknowledged")}><Eye size={15} /> Triaged</button>
          <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onStatus(row, "resolved")}><CheckCircle2 size={15} /> Fixed</button>
          <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onStatus(row, "false_positive")}><XCircle size={15} /> False positive</button>
          {service === "Browser" && <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onAllowScript(row)}><ShieldCheck size={15} /> Allow script</button>}
        </div>
      </header>

      <BasicDetails row={row} rule={rule} />

      <nav className="detail-tabs" aria-label="Issue detail tabs">
        {tabs.map((tab) => (
          <button className={activeTab === tab.key ? "active" : ""} key={tab.key} type="button" onClick={() => setActiveTab(tab.key)}>
            {tab.label}
          </button>
        ))}
      </nav>

      {activeTab === "overview" && <OverviewTab row={row} rule={rule} />}
      {activeTab === "evidence" && <EvidenceTab row={row} rule={rule} />}
      {activeTab === "timeline" && <TimelineTab linkedSignals={linkedSignals} />}
      {activeTab === "comments" && <CommentsTab row={row} />}
      {activeTab === "related" && <RelatedIssuesTab onIssue={onIssue} rows={relatedIssues} />}
      {activeTab === "analysis" && <AnalysisTab reports={matchingReports} />}
    </section>
  );
}

function BasicDetails({ row, rule }: { row: IssueRow; rule?: RuleDefinition }) {
  const { finding, instance, service } = row;
  const account = firstMetadataString(finding.metadata, ["email", "account_display", "login", "email_masked", "login_masked"]);
  const risk = riskSummary(finding.metadata);
  return (
    <div className="issue-detail-grid">
      <DetailTile label="Company" value={instance.companyName} />
      <DetailTile label="Site" value={instance.projectName} />
      <DetailTile label="Node" value={nodeLabel(instance)} />
      <DetailTile label="Service" value={service} />
      <DetailTile label="Rule" value={rule?.title ?? finding.rule_id} />
      <DetailTile label="Confidence" value={finding.confidence} />
      <DetailTile label="First seen" value={formatDate(finding.first_event_at)} />
      <DetailTile label="Last seen" value={formatDate(finding.last_event_at)} />
      {account && <DetailTile label="Account" value={account} />}
      {risk && <DetailTile label="Risk" value={risk} />}
    </div>
  );
}

function OverviewTab({ row, rule }: { row: IssueRow; rule?: RuleDefinition }) {
  const { finding } = row;
  return (
    <div className="issue-tab-grid">
      <Panel title="Recommended action" icon={ShieldCheck}>
        <p className="tab-copy">{recommendedAction(row, rule)}</p>
      </Panel>
      <Panel title="Rule context" icon={AlertTriangle}>
        <dl className="compact-dl">
          <dt>Rule ID</dt><dd>{finding.rule_id}</dd>
          <dt>Rule version</dt><dd>{finding.rule_version}</dd>
          <dt>Category</dt><dd>{rule?.category ?? "unknown"}</dd>
          <dt>Evidence types</dt><dd>{rule?.evidence_types?.join(", ") || "-"}</dd>
        </dl>
      </Panel>
      <Panel title="Status" icon={Eye}>
        <dl className="compact-dl">
          <dt>Status</dt><dd>{issueStatusLabel(finding.status, finding.status_reason)}</dd>
          <dt>Reason</dt><dd>{finding.status_reason || "-"}</dd>
          <dt>Actor</dt><dd>{finding.status_actor || "-"}</dd>
          <dt>Updated</dt><dd>{finding.status_updated_at ? formatDate(finding.status_updated_at) : "-"}</dd>
        </dl>
      </Panel>
    </div>
  );
}

function EvidenceTab({ row, rule }: { row: IssueRow; rule?: RuleDefinition }) {
  const { finding } = row;
  const account = firstMetadataString(finding.metadata, ["email", "account_display", "login", "email_masked", "login_masked"]);
  const changedFiles = metadataStringList(finding.metadata, "files");
  const omittedFiles = metadataNumber(finding.metadata, "omitted_file_count");
  const visibleEventIDs = finding.event_ids.slice(0, 50);
  const omittedEventIDs = Math.max(0, finding.event_ids.length - visibleEventIDs.length);
  return (
    <div className="issue-tab-grid">
      <Panel title="Evidence summary" icon={FileText}>
        <dl className="compact-dl">
          <dt>Linked signals</dt><dd>{finding.event_ids.length}</dd>
          <dt>Rule evidence</dt><dd>{rule?.evidence_types?.join(", ") || "-"}</dd>
          {account && <><dt>Account</dt><dd>{account}</dd></>}
          {metadataString(finding.metadata, "file_group_root") && <><dt>File group</dt><dd>{metadataString(finding.metadata, "file_group_root")}</dd></>}
        </dl>
      </Panel>
      {changedFiles.length > 0 && (
        <Panel title="Changed files" icon={FileText}>
          <ul className="evidence-list tall">
            {changedFiles.map((file) => <li key={file}>{file}</li>)}
          </ul>
          {omittedFiles > 0 && <p className="muted-line">+ {omittedFiles} more file(s) in this group</p>}
        </Panel>
      )}
      <Panel title={`Signal IDs (${finding.event_ids.length})`} icon={Activity}>
        <ul className="evidence-list tall">
          {visibleEventIDs.map((eventID) => <li key={eventID}>{eventID}</li>)}
          {omittedEventIDs > 0 && <li>+ {omittedEventIDs} more linked signal(s)</li>}
          {finding.event_ids.length === 0 && <li>No linked signal IDs.</li>}
        </ul>
      </Panel>
    </div>
  );
}

function TimelineTab({ linkedSignals }: { linkedSignals: SignalRow[] }) {
  if (!linkedSignals.length) {
    return <Panel title="Linked timeline" icon={Activity}><EmptyState title="No linked timeline signals" /></Panel>;
  }
  return (
    <Panel title="Linked timeline" icon={Activity}>
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Collector</th>
            <th>Service</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody>
          {linkedSignals.map((signal) => (
            <tr key={`${signal.instance.key}:${signal.event.id}`}>
              <td>{formatRelative(signal.event.event_time)}</td>
              <td>{signalTypeLabel(signal.event)}</td>
              <td>{collectorLabel(signal.event)}</td>
              <td>{signal.service}</td>
              <td><strong>{signal.event.message || signal.event.type}</strong><small>{signal.event.target}</small></td>
            </tr>
          ))}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}

function CommentsTab({ row }: { row: IssueRow }) {
  const { finding } = row;
  const hasTriageNote = finding.status_note || finding.status_reason || finding.status_actor;
  return (
    <Panel title="Comments" icon={MessageSquare}>
      {hasTriageNote ? (
        <div className="comment-card">
          <strong>{finding.status_actor || "Aegrail"}</strong>
          <small>{finding.status_updated_at ? formatDate(finding.status_updated_at) : ""}</small>
          <p>{finding.status_note || finding.status_reason || "Status updated."}</p>
        </div>
      ) : (
        <EmptyState title="No comments yet" />
      )}
    </Panel>
  );
}

function RelatedIssuesTab({ onIssue, rows }: { onIssue: (row: IssueRow) => void; rows: IssueRow[] }) {
  if (!rows.length) {
    return <Panel title="Related issues" icon={Link2}><EmptyState title="No related issues" /></Panel>;
  }
  return (
    <Panel title="Related issues" icon={Link2}>
      <div className="stack-list">
        {rows.map((row) => (
          <button className="stack-row" key={`${row.instance.key}:${row.finding.id}`} type="button" onClick={() => onIssue(row)}>
            <SeverityPill value={row.finding.severity} />
            <span>
              <strong>{row.finding.title}</strong>
              <small>{row.instance.companyName} / {row.instance.projectName} / {nodeLabel(row.instance)}</small>
            </span>
            <em>{formatRelative(row.finding.last_event_at)}</em>
          </button>
        ))}
      </div>
    </Panel>
  );
}

function AnalysisTab({ reports }: { reports: ReportRow[] }) {
  if (!reports.length) {
    return <Panel title="LLM analysis" icon={Brain}><EmptyState title="No analysis yet" /></Panel>;
  }
  return (
    <Panel title="LLM analysis" icon={Brain}>
      <div className="stack-list">
        {reports.map(({ report }) => (
          <div className="analysis-card" key={report.id}>
            <strong>{report.model_name || report.model_provider || "Model report"}</strong>
            <small>{report.status} / {formatDate(report.generated_at)}</small>
            <p>{report.analysis || report.error || "No analysis text returned."}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function DetailTile({ label, value }: { label: string; value: string }) {
  return <div className="detail-tile"><span>{label}</span><strong>{value}</strong></div>;
}

function riskSummary(metadata: Record<string, unknown>) {
  const risk = metadata.risk;
  if (!risk || typeof risk !== "object" || Array.isArray(risk)) {
    return "";
  }
  const riskMap = risk as Record<string, unknown>;
  const score = riskMap.score;
  const band = riskMap.band;
  if (typeof score !== "number" || typeof band !== "string") {
    return "";
  }
  return `${score} / ${band}`;
}
