import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Brain,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  FileText,
  Link2,
  MessageSquare,
  ShieldCheck,
  XCircle
} from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { loadTimelineEventsByID } from "../../api";
import type { RuleDefinition } from "../../types";
import { modelPresetLabel } from "../config/modelPresets";
import { collectorLabel, issueStatusLabel, nodeLabel, recommendedAction, serviceForEvent, signalTypeLabel } from "../model/viewModels";
import type { IssueRow, ReportRow, SignalRow } from "../types";
import { fileIgnorePathCandidate, firstMetadataString, metadataNumber, metadataString, metadataStringList, operatorActionGuidance } from "../utils/metadata";
import { copyIssueBrief, exportIssueBrief } from "../utils/reports";
import {
  AnalysisLine,
  isModelAnalysisHTML,
  parseModelAnalysisSections,
  sanitizeModelAnalysisHTML,
  splitCodeTokens
} from "../utils/modelAnalysis";
import { formatDate, formatRelative } from "../utils/time";
import { EmptyState, Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";

type IssueDetailTab = "overview" | "evidence" | "timeline" | "comments" | "related" | "report" | "analysis";

const tabs: Array<{ key: IssueDetailTab; label: string }> = [
  { key: "overview", label: "Overview" },
  { key: "evidence", label: "Evidence" },
  { key: "timeline", label: "Timeline" },
  { key: "comments", label: "Comments" },
  { key: "related", label: "Related issues" },
  { key: "report", label: "Report" },
  { key: "analysis", label: "LLM analysis" }
];

export function IssueDetailPage({
  actionLoading,
  issueRows,
  onAllowScript,
  onBack,
  onGenerateAnalysis,
  onIgnoreFilePath,
  onIssue,
  onStatus,
  reportRows,
  row,
  rule,
  selectedModel,
  signalRows
}: {
  actionLoading: boolean;
  issueRows: IssueRow[];
  onAllowScript: (row: IssueRow) => void;
  onBack: () => void;
  onGenerateAnalysis: (row: IssueRow) => void;
  onIgnoreFilePath: (row: IssueRow) => void;
  onIssue: (row: IssueRow) => void;
  onStatus: (row: IssueRow, status: string) => void;
  reportRows: ReportRow[];
  row?: IssueRow;
  rule?: RuleDefinition;
  selectedModel: string;
  signalRows: SignalRow[];
}) {
  const [activeTab, setActiveTab] = useState<IssueDetailTab>("overview");
  const [hydratedLinkedSignals, setHydratedLinkedSignals] = useState<SignalRow[]>([]);
  const [linkedTimelineLoading, setLinkedTimelineLoading] = useState(false);
  const [linkedTimelineError, setLinkedTimelineError] = useState("");

  useEffect(() => {
    if (!row) {
      setHydratedLinkedSignals([]);
      setLinkedTimelineLoading(false);
      setLinkedTimelineError("");
      return;
    }
    const cachedIDs = new Set(
      signalRows
        .filter((signal) => signal.instance.key === row.instance.key)
        .map((signal) => signal.event.id)
    );
    const missingEventIDs = row.finding.event_ids.filter((eventID) => !cachedIDs.has(eventID));
    setHydratedLinkedSignals([]);
    setLinkedTimelineError("");
    if (!missingEventIDs.length) {
      setLinkedTimelineLoading(false);
      return;
    }

    let cancelled = false;
    setLinkedTimelineLoading(true);
    loadTimelineEventsByID(row.instance.scope, missingEventIDs)
      .then((events) => {
        if (cancelled) {
          return;
        }
        setHydratedLinkedSignals(events.map((event) => ({
          event,
          instance: row.instance,
          issue: row.finding,
          service: serviceForEvent(event)
        })));
      })
      .catch((error) => {
        if (!cancelled) {
          setLinkedTimelineError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLinkedTimelineLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [row, signalRows]);

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
  const ignorePath = fileIgnorePathCandidate(finding.metadata);
  const linkedEventIDs = new Set(finding.event_ids);
  const linkedSignals = mergeLinkedSignals(
    signalRows.filter((signal) => signal.instance.key === instance.key && linkedEventIDs.has(signal.event.id)),
    hydratedLinkedSignals,
    finding.event_ids
  );
  const relatedIssues = issueRows
    .filter((candidate) => candidate.finding.id !== finding.id)
    .filter((candidate) =>
      candidate.instance.key === instance.key ||
      candidate.finding.rule_id === finding.rule_id ||
      (candidate.instance.companySlug === instance.companySlug && candidate.instance.projectSlug === instance.projectSlug && candidate.service === service)
    )
    .slice(0, 8);
  const matchingReports = latestReportsForFinding(reportRows, finding.id);

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
          <button className="ghost-button" type="button" onClick={() => setActiveTab("report")}><FileText size={15} /> Report</button>
          <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onStatus(row, "acknowledged")}><Eye size={15} /> Acknowledge</button>
          <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onStatus(row, "resolved")}><CheckCircle2 size={15} /> Fixed</button>
          <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onStatus(row, "false_positive")}><XCircle size={15} /> False positive</button>
          {ignorePath && <button className="ghost-button" type="button" disabled={actionLoading} onClick={() => onIgnoreFilePath(row)}><XCircle size={15} /> Ignore directory</button>}
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
      {activeTab === "evidence" && <EvidenceTab linkedSignals={linkedSignals} loading={linkedTimelineLoading} onSignal={() => setActiveTab("timeline")} row={row} rule={rule} />}
      {activeTab === "timeline" && <TimelineTab error={linkedTimelineError} linkedSignals={linkedSignals} loading={linkedTimelineLoading} totalLinkedSignals={finding.event_ids.length} />}
      {activeTab === "comments" && <CommentsTab row={row} />}
      {activeTab === "related" && <RelatedIssuesTab onIssue={onIssue} rows={relatedIssues} />}
      {activeTab === "report" && <ReportTab actionLoading={actionLoading} modelValue={selectedModel} onGenerate={() => onGenerateAnalysis(row)} reports={matchingReports} row={row} rule={rule} />}
      {activeTab === "analysis" && <AnalysisTab actionLoading={actionLoading} modelValue={selectedModel} onGenerate={() => onGenerateAnalysis(row)} reports={matchingReports} />}
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
      <OperatorActionPanel row={row} rule={rule} />
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

function OperatorActionPanel({ row, rule }: { row: IssueRow; rule?: RuleDefinition }) {
  const guidance = operatorActionGuidance(row.finding);
  const steps = guidance.actions.length ? guidance.actions : [recommendedAction(row, rule)];
  return (
    <Panel title="Recommended action" icon={ShieldCheck}>
      <p className="tab-copy">{recommendedAction(row, rule)}</p>
      {(guidance.safeToAcknowledgeWhen || guidance.escalateWhen) && (
        <dl className="compact-dl action-guidance">
          {guidance.safeToAcknowledgeWhen && <><dt>Acknowledge when</dt><dd>{guidance.safeToAcknowledgeWhen}</dd></>}
          {guidance.escalateWhen && <><dt>Escalate when</dt><dd>{guidance.escalateWhen}</dd></>}
        </dl>
      )}
      <ul className="evidence-list action-list">
        {steps.map((step) => <li key={step}>{step}</li>)}
      </ul>
    </Panel>
  );
}

function EvidenceTab({
  linkedSignals,
  loading,
  onSignal,
  row,
  rule
}: {
  linkedSignals: SignalRow[];
  loading: boolean;
  onSignal: (eventID: string) => void;
  row: IssueRow;
  rule?: RuleDefinition;
}) {
  const { finding } = row;
  const account = firstMetadataString(finding.metadata, ["email", "account_display", "login", "email_masked", "login_masked"]);
  const changedFiles = metadataStringList(finding.metadata, "files");
  const omittedFiles = metadataNumber(finding.metadata, "omitted_file_count");
  const visibleEventIDs = finding.event_ids.slice(0, 50);
  const omittedEventIDs = Math.max(0, finding.event_ids.length - visibleEventIDs.length);
  const linkedSignalByID = new Map(linkedSignals.map((signal) => [signal.event.id, signal]));
  const handleSignal = (eventID: string) => {
    onSignal(eventID);
    window.setTimeout(() => {
      document.getElementById(signalAnchorID(eventID))?.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 0);
  };
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
          {visibleEventIDs.map((eventID) => (
            <li key={eventID}>
              {linkedSignalByID.has(eventID) ? (
                <button className="signal-id-link" type="button" onClick={() => handleSignal(eventID)}>
                  {eventID}
                  <small>{signalTypeLabel(linkedSignalByID.get(eventID)!.event)} / {formatRelative(linkedSignalByID.get(eventID)!.event.event_time)}</small>
                </button>
              ) : (
                <span className="signal-id-muted">
                  {eventID}
                  <small>{loading ? "Loading signal details..." : "Signal was not returned by Hub for this scope"}</small>
                </span>
              )}
            </li>
          ))}
          {omittedEventIDs > 0 && <li>+ {omittedEventIDs} more linked signal(s)</li>}
          {finding.event_ids.length === 0 && <li>No linked signal IDs.</li>}
        </ul>
      </Panel>
    </div>
  );
}

function TimelineTab({
  error,
  linkedSignals,
  loading,
  totalLinkedSignals
}: {
  error: string;
  linkedSignals: SignalRow[];
  loading: boolean;
  totalLinkedSignals: number;
}) {
  if (!linkedSignals.length) {
    return (
      <Panel title="Linked timeline" icon={Activity}>
        {loading ? <EmptyState title="Loading linked timeline signals" /> : <EmptyState title={totalLinkedSignals ? "No linked timeline signals returned" : "No linked timeline signals"} />}
        {error && <p className="muted-line">{error}</p>}
      </Panel>
    );
  }
  const timelineSignals = [...linkedSignals].sort((left, right) => new Date(left.event.event_time).getTime() - new Date(right.event.event_time).getTime());
  return (
    <Panel title="Linked timeline" icon={Activity}>
      {loading && <p className="muted-line">Loading older linked signals...</p>}
      {error && <p className="muted-line">{error}</p>}
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
          {timelineSignals.map((signal) => (
            <tr key={`${signal.instance.key}:${signal.event.id}`}>
              <td id={signalAnchorID(signal.event.id)}>{formatRelative(signal.event.event_time)}</td>
              <td>{signalTypeLabel(signal.event)}</td>
              <td>{collectorLabel(signal.event)}</td>
              <td>{signal.service}</td>
              <td><TimelineSummaryCell signal={signal} /></td>
            </tr>
          ))}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}

function TimelineSummaryCell({ signal }: { signal: SignalRow }) {
  const remote = timelineRemoteLabel(signal);
  return (
    <>
      <strong>{signal.event.message || signal.event.type}</strong>
      {remote && (
        <div className="signal-badges timeline-signal-badges">
          <span className="signal-badge">IP {remote}</span>
        </div>
      )}
      <small>{signal.event.target}</small>
    </>
  );
}

function mergeLinkedSignals(cached: SignalRow[], hydrated: SignalRow[], eventIDs: string[]) {
  const wanted = new Set(eventIDs);
  const byID = new Map<string, SignalRow>();
  for (const signal of cached) {
    if (wanted.has(signal.event.id)) {
      byID.set(signal.event.id, signal);
    }
  }
  for (const signal of hydrated) {
    if (wanted.has(signal.event.id) && !byID.has(signal.event.id)) {
      byID.set(signal.event.id, signal);
    }
  }
  return eventIDs.map((eventID) => byID.get(eventID)).filter((signal): signal is SignalRow => Boolean(signal));
}

function signalAnchorID(eventID: string) {
  return `signal-${eventID}`;
}

function timelineRemoteLabel(signal: SignalRow) {
  if (signal.event.type !== "log.access" && signal.event.type !== "log.php_error") {
    return "";
  }
  return payloadText(signal.event.payload, "remote_addr") || payloadText(signal.event.payload, "remote_addr_sha256");
}

function payloadText(payload: Record<string, unknown>, key: string) {
  const value = payload[key];
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
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

function ReportTab({
  actionLoading,
  modelValue,
  onGenerate,
  reports,
  row,
  rule
}: {
  actionLoading: boolean;
  modelValue: string;
  onGenerate: () => void;
  reports: ReportRow[];
  row: IssueRow;
  rule?: RuleDefinition;
}) {
  const [copyState, setCopyState] = useState("");
  const latestReport = reports[0]?.report;
  const guidance = operatorActionGuidance(row.finding);

  async function handleCopy() {
    setCopyState("");
    try {
      await copyIssueBrief(row, rule, latestReport);
      setCopyState("Copied");
    } catch (error) {
      setCopyState(error instanceof Error ? error.message : String(error));
    }
  }

  const action = (
    <div className="analysis-action">
      <button className="ghost-button compact" type="button" onClick={() => exportIssueBrief(row, rule, latestReport)}>
        <Download size={15} /> Download
      </button>
      <button className="ghost-button compact" type="button" onClick={() => void handleCopy()}>
        <Copy size={15} /> Copy
      </button>
      <button className="ghost-button compact" type="button" disabled={actionLoading} onClick={onGenerate}>
        <Brain size={15} /> Generate analysis
      </button>
    </div>
  );

  return (
    <div className="issue-tab-grid">
      <Panel title="Issue brief" icon={FileText} action={action}>
        <dl className="compact-dl">
          <dt>Status</dt><dd>{issueStatusLabel(row.finding.status, row.finding.status_reason)}</dd>
          <dt>Company</dt><dd>{row.instance.companyName}</dd>
          <dt>Site</dt><dd>{row.instance.projectName}</dd>
          <dt>Node</dt><dd>{nodeLabel(row.instance)}</dd>
          <dt>Primary action</dt><dd>{guidance.primaryAction || recommendedAction(row, rule)}</dd>
          {guidance.safeToAcknowledgeWhen && <><dt>Acknowledge when</dt><dd>{guidance.safeToAcknowledgeWhen}</dd></>}
          {guidance.escalateWhen && <><dt>Escalate when</dt><dd>{guidance.escalateWhen}</dd></>}
        </dl>
        {copyState && <p className="muted-line">{copyState}</p>}
      </Panel>
      <Panel title="Model section" icon={Brain} action={<span className="muted-line inline">{modelPresetLabel(modelValue)}</span>}>
        {latestReport ? (
          <div className="analysis-card">
            <strong>{latestReport.model_name || latestReport.model_provider || "Model report"}</strong>
            <small>{latestReport.status} / {formatDate(latestReport.generated_at)}</small>
            {latestReport.error && <p className="analysis-error">{latestReport.error}</p>}
            {latestReport.analysis ? <AnalysisOutput analysis={latestReport.analysis} /> : <p className="tab-copy">No analysis body was returned.</p>}
          </div>
        ) : (
          <EmptyState title="No model analysis yet" description="The brief still includes deterministic Hub guidance." />
        )}
      </Panel>
    </div>
  );
}

function AnalysisTab({ actionLoading, modelValue, onGenerate, reports }: { actionLoading: boolean; modelValue: string; onGenerate: () => void; reports: ReportRow[] }) {
  const action = (
    <div className="analysis-action">
      <span>{modelPresetLabel(modelValue)}</span>
      <button className="ghost-button compact" type="button" disabled={actionLoading} onClick={onGenerate}>
        <Brain size={15} /> Generate analysis
      </button>
    </div>
  );
  if (!reports.length) {
    return (
      <Panel title="LLM analysis" icon={Brain} action={action}>
        <EmptyState title="No analysis yet" />
      </Panel>
    );
  }
  return (
    <Panel title="LLM analysis" icon={Brain} action={action}>
      <div className="stack-list">
        {reports.map(({ report }) => (
          <div className="analysis-card" key={report.id}>
            <div className="analysis-meta">
              <strong>{report.model_name || report.model_provider || "Model report"}</strong>
              <small>{report.status} / {formatDate(report.generated_at)}</small>
            </div>
            {report.error && <p className="analysis-error">{report.error}</p>}
            <dl className="analysis-meta">
              <dt>Findings</dt>
              <dd>{report.source_finding_ids.join(", ") || "none"}</dd>
              <dt>Evidence bundle</dt>
              <dd>{report.evidence_bundle_sha256 ? `${report.evidence_bundle_sha256.slice(0, 12)}...` : "missing"}</dd>
              <dt>Perf</dt>
              <dd>{report.total_duration_millis ? `${report.total_duration_millis} ms` : "n/a"} / {report.prompt_eval_count || 0}+{report.eval_count || 0} tokens</dd>
            </dl>
            <AnalysisOutput analysis={report.analysis || ""} />
          </div>
        ))}
      </div>
    </Panel>
  );
}

function latestReportsForFinding(reportRows: ReportRow[], findingID: string) {
  const matching = reportRows.filter((item) => item.report.source_finding_ids.includes(findingID));
  const completed = matching.find((item) => item.report.status === "completed" && item.report.analysis);
  const latest = completed ?? matching[0];
  return latest ? [latest] : [];
}

function AnalysisOutput({ analysis }: { analysis: string }) {
  if (isModelAnalysisHTML(analysis)) {
    return <div className="analysis-output" dangerouslySetInnerHTML={{ __html: sanitizeModelAnalysisHTML(analysis) }} />;
  }
  return (
    <div className="analysis-output">
      {parseModelAnalysisSections(analysis).map((section) => (
        <section className="analysis-section" key={section.title}>
          <h5>{section.title}</h5>
          <div className="analysis-body">
            {renderAnalysisSectionLines(section.title, section.lines)}
          </div>
        </section>
      ))}
    </div>
  );
}

function renderAnalysisLine(value: string) {
  return splitCodeTokens(value).map((part, index) => {
    if (/^`[^`]+`$/.test(part)) {
      return <code key={`token-${index}`}>{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

function renderAnalysisSectionLines(sectionTitle: string, lines: AnalysisLine[]) {
  const nodes: ReactNode[] = [];
  let listBuffer: ReactNode[] = [];
  let kvBuffer: Array<{ key: string; value: string }> = [];

  const flushList = (keyPrefix: string) => {
    if (!listBuffer.length) {
      return;
    }
    nodes.push(
      <ul className="analysis-list" key={`${keyPrefix}-list`}>
        {listBuffer}
      </ul>
    );
    listBuffer = [];
  };

  const flushKV = (keyPrefix: string) => {
    if (!kvBuffer.length) {
      return;
    }
    nodes.push(
      <dl className="analysis-kv" key={`${keyPrefix}-kv`}>
        {kvBuffer.map((entry, entryIndex) => [
          <dt key={`${keyPrefix}-dt-${entryIndex}`}>{entry.key}</dt>,
          <dd key={`${keyPrefix}-dd-${entryIndex}`}>{renderAnalysisLine(entry.value)}</dd>
        ])}
      </dl>
    );
    kvBuffer = [];
  };

  lines.forEach((line, index) => {
    if (line.kind === "list") {
      flushKV(`section-${sectionTitle}-${index}`);
      listBuffer.push(<li key={`${sectionTitle}-li-${index}`}>{renderAnalysisLine(line.content)}</li>);
      return;
    }
    if (line.kind === "kv") {
      flushList(`section-${sectionTitle}-${index}`);
      kvBuffer.push({ key: line.key, value: line.value });
      return;
    }

    if (!line.content.trim()) {
      return;
    }

    flushList(`section-${sectionTitle}-${index}`);
    flushKV(`section-${sectionTitle}-${index}`);
    nodes.push(<p key={`${sectionTitle}-text-${index}`}>{renderAnalysisLine(line.content)}</p>);
  });
  flushList(`section-${sectionTitle}-tail`);
  flushKV(`section-${sectionTitle}-tail`);

  if (!nodes.length) {
    nodes.push(<p key={`${sectionTitle}-empty`}>No details available.</p>);
  }
  return <>{nodes}</>;
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
