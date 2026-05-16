import { AlertTriangle, GitBranch, Loader2, Rocket } from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import type { InstanceModel } from "../../estate";
import type { DeploymentRow, IssueRow } from "../types";
import { formatDate, formatRelative } from "../utils/time";
import { EmptyState, InlineAlert, InlineSuccess, Panel, ResponsiveTable, SeverityPill, StatusPill, TextInput } from "../components/common";

export function DeploymentsPage({
  actor,
  deploymentRows,
  issueRows,
  loading,
  onCreate,
  visibleInstances
}: {
  actor: string;
  deploymentRows: DeploymentRow[];
  issueRows: IssueRow[];
  loading: boolean;
  onCreate: (input: {
    actor: string;
    commitSha: string;
    finishedAt?: string;
    instance: InstanceModel;
    startedAt?: string;
    version: string;
  }) => Promise<void>;
  visibleInstances: InstanceModel[];
}) {
  const [instanceKey, setInstanceKey] = useState(visibleInstances[0]?.key ?? "");
  const [version, setVersion] = useState("");
  const [commitSha, setCommitSha] = useState("");
  const [actorDraft, setActorDraft] = useState(actor);
  const [startedAt, setStartedAt] = useState(() => localDateTimeInput(new Date(Date.now() - 30 * 60 * 1000)));
  const [finishedAt, setFinishedAt] = useState(() => localDateTimeInput(new Date()));
  const [reviewing, setReviewing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    if (!visibleInstances.some((instance) => instance.key === instanceKey)) {
      setInstanceKey(visibleInstances[0]?.key ?? "");
    }
  }, [instanceKey, visibleInstances]);

  useEffect(() => {
    setActorDraft(actor);
  }, [actor]);

  const selectedInstance = useMemo(
    () => visibleInstances.find((instance) => instance.key === instanceKey) ?? visibleInstances[0],
    [instanceKey, visibleInstances]
  );

  const windowStart = parseLocalDateTime(startedAt);
  const windowEnd = parseLocalDateTime(finishedAt);
  const previewRows = useMemo(() => {
    if (!selectedInstance || !windowStart || !windowEnd) {
      return [];
    }
    const startMs = windowStart.getTime();
    const endMs = windowEnd.getTime();
    return issueRows
      .filter((row) => row.instance.key === selectedInstance.key)
      .filter((row) => row.finding.status === "open")
      .filter((row) => issueOverlaps(row, startMs, endMs))
      .slice(0, 80);
  }, [issueRows, selectedInstance, windowEnd?.getTime(), windowStart?.getTime()]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (!selectedInstance) {
      setError("No node is available for deployment recording.");
      return;
    }
    if (!version.trim()) {
      setError("Enter a version, release name, or short deployment note.");
      return;
    }
    if (!windowStart || !windowEnd || windowEnd.getTime() < windowStart.getTime()) {
      setError("Pick a valid deployment timeframe.");
      return;
    }
    if (!reviewing) {
      setReviewing(true);
      return;
    }

    setSubmitting(true);
    try {
      await onCreate({
        actor: actorDraft.trim(),
        commitSha: commitSha.trim(),
        finishedAt: windowEnd.toISOString(),
        instance: selectedInstance,
        startedAt: windowStart.toISOString(),
        version: version.trim()
      });
      setSuccess(`Deployment marker recorded for ${selectedInstance.projectName}.`);
      setVersion("");
      setCommitSha("");
      setReviewing(false);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page-stack">
      {error && <InlineAlert message={error} />}
      {success && <InlineSuccess message={success} />}

      <Panel title="Mark deployment timeframe" icon={Rocket}>
        <form className="form-stack" onSubmit={submit}>
          <label>
            Node
            <select value={instanceKey} onChange={(event) => { setInstanceKey(event.target.value); setReviewing(false); }}>
              {visibleInstances.map((instance) => (
                <option key={instance.key} value={instance.key}>
                  {instance.companyName} / {instance.projectName} / {instance.environmentName} / {instance.appName}
                </option>
              ))}
            </select>
          </label>
          <div className="deployment-form-grid">
            <TextInput label="Version or note" value={version} onChange={(value) => { setVersion(value); setReviewing(false); }} placeholder="2026.05.16-1" />
            <TextInput label="Commit SHA (optional)" value={commitSha} onChange={(value) => { setCommitSha(value); setReviewing(false); }} placeholder="abc1234" />
            <TextInput label="Actor" value={actorDraft} onChange={setActorDraft} placeholder="dashboard" />
          </div>
          <div className="deployment-form-grid">
            <label>
              Start
              <input type="datetime-local" value={startedAt} onChange={(event) => { setStartedAt(event.target.value); setReviewing(false); }} />
            </label>
            <label>
              Finish
              <input type="datetime-local" value={finishedAt} onChange={(event) => { setFinishedAt(event.target.value); setReviewing(false); }} />
            </label>
          </div>
          <div className="deployment-preview">
            <span><AlertTriangle size={15} /> Open changes inside timeframe</span>
            <strong>{previewRows.length}</strong>
          </div>
          {reviewing && (
            <DeploymentPreview rows={previewRows} />
          )}
          <div className="button-row">
            <button className={reviewing ? "primary-button" : "ghost-button"} disabled={loading || submitting} type="submit">
              {submitting ? <Loader2 size={15} className="spin" /> : <Rocket size={15} />}
              {reviewing ? "Confirm deployment marker" : "Review affected changes"}
            </button>
            {reviewing && (
              <button className="ghost-button" type="button" onClick={() => setReviewing(false)}>
                Edit timeframe
              </button>
            )}
          </div>
        </form>
      </Panel>

      <Panel title="Deployment history" icon={GitBranch}>
        <ResponsiveTable>
          <thead>
            <tr>
              <th>Version</th>
              <th>Node</th>
              <th>Actor</th>
              <th>Started</th>
              <th>Finished</th>
            </tr>
          </thead>
          <tbody>
            {deploymentRows.map((row) => (
              <tr key={`${row.instance.key}:${row.deployment.id}`}>
                <td>
                  <strong>{row.deployment.version}</strong>
                  <small>{row.deployment.commit_sha ?? ""}</small>
                </td>
                <td>{row.instance.companyName} / {row.instance.projectName}<small>{row.instance.environmentName} / {row.instance.appName}</small></td>
                <td>{row.deployment.actor || "-"}</td>
                <td>{formatDate(row.deployment.started_at)}<small>{formatRelative(row.deployment.started_at)}</small></td>
                <td>
                  {row.deployment.finished_at ? (
                    <>{formatDate(row.deployment.finished_at)}<small>{formatRelative(row.deployment.finished_at)}</small></>
                  ) : (
                    <StatusPill value="open" />
                  )}
                </td>
              </tr>
            ))}
            {deploymentRows.length === 0 && (
              <tr><td colSpan={5}><EmptyState title="No deployment markers yet" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>
    </div>
  );
}

function DeploymentPreview({ rows }: { rows: IssueRow[] }) {
  if (rows.length === 0) {
    return <div className="deployment-empty">No open issues overlap this timeframe.</div>;
  }
  return (
    <div className="deployment-issue-preview">
      {rows.slice(0, 12).map((row) => (
        <div className="deployment-issue-row" key={`${row.instance.key}:${row.finding.id}`}>
          <SeverityPill value={row.finding.severity} />
          <span>
            <strong>{row.finding.title}</strong>
            <small>{row.service} / first {formatRelative(row.finding.first_event_at)} / last {formatRelative(row.finding.last_event_at)}</small>
          </span>
          <StatusPill value={row.finding.status} />
        </div>
      ))}
      {rows.length > 12 && <p className="muted-line">{rows.length - 12} more issue(s) omitted from preview.</p>}
    </div>
  );
}

function issueOverlaps(row: IssueRow, startMs: number, endMs: number) {
  const first = new Date(row.finding.first_event_at).getTime();
  const last = new Date(row.finding.last_event_at).getTime();
  if (Number.isNaN(first) || Number.isNaN(last)) {
    return false;
  }
  return first <= endMs && last >= startMs;
}

function localDateTimeInput(date: Date) {
  const offsetMs = date.getTimezoneOffset() * 60 * 1000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}

function parseLocalDateTime(value: string) {
  if (!value) {
    return undefined;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}
