import { GitBranch, Loader2, Rocket, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import type { InstanceModel } from "../../estate";
import type { DeploymentRow } from "../types";
import { EmptyState, InlineAlert, Panel, ResponsiveTable, StatusPill, TextInput } from "../components/common";
import { formatDate, formatRelative } from "../utils/time";

export function DeploymentsPage({
  deploymentRows,
  error,
  loading,
  onCreate,
  visibleInstances
}: {
  deploymentRows: DeploymentRow[];
  error: string;
  loading: boolean;
  onCreate: (input: { commitSha: string; instance: InstanceModel; version: string }) => Promise<void>;
  visibleInstances: InstanceModel[];
}) {
  const targets = useMemo(() => deploymentTargets(visibleInstances), [visibleInstances]);
  const [targetKey, setTargetKey] = useState(targets[0] ? scopeKey(targets[0]) : "");
  const [version, setVersion] = useState("");
  const [commitSha, setCommitSha] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    if (!targets.some((instance) => scopeKey(instance) === targetKey)) {
      setTargetKey(targets[0] ? scopeKey(targets[0]) : "");
    }
  }, [targetKey, targets]);

  const selectedTarget = targets.find((instance) => scopeKey(instance) === targetKey) ?? targets[0];

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError("");
    if (!selectedTarget) {
      setFormError("No monitored application is available.");
      return;
    }
    if (!version.trim()) {
      setFormError("Enter a release label or version.");
      return;
    }
    setSubmitting(true);
    try {
      await onCreate({
        commitSha: commitSha.trim(),
        instance: selectedTarget,
        version: version.trim()
      });
      setVersion("");
      setCommitSha("");
    } catch (caught) {
      setFormError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page-stack">
      {error && <InlineAlert message={error} />}
      {formError && <InlineAlert message={formError} />}

      <Panel title="Record deployment" icon={Rocket}>
        <div className="deployment-context-note">
          <ShieldCheck size={18} />
          <div>
            <strong>Deployment markers add investigation context only.</strong>
            <span>They do not hide, downgrade, or automatically acknowledge findings.</span>
          </div>
        </div>
        <form className="form-stack" onSubmit={submit}>
          <label>
            Application
            <select value={targetKey} onChange={(event) => setTargetKey(event.target.value)}>
              {targets.map((instance) => (
                <option key={scopeKey(instance)} value={scopeKey(instance)}>
                  {instance.companyName} / {instance.projectName} / {instance.environmentName} / {instance.appName}
                </option>
              ))}
            </select>
          </label>
          <div className="deployment-form-grid">
            <TextInput label="Release label" value={version} onChange={setVersion} placeholder="2026.08.04-1" />
            <TextInput label="Commit SHA (optional)" value={commitSha} onChange={setCommitSha} placeholder="abc1234" />
          </div>
          <div className="button-row">
            <button className="primary-button" disabled={loading || submitting || !selectedTarget} type="submit">
              {submitting ? <Loader2 size={15} className="spin" /> : <Rocket size={15} />}
              Record deployment now
            </button>
          </div>
        </form>
      </Panel>

      <Panel title="Deployment history" icon={GitBranch}>
        <ResponsiveTable>
          <thead>
            <tr>
              <th>Release</th>
              <th>Application</th>
              <th>Recorded by</th>
              <th>Recorded</th>
              <th>Context</th>
            </tr>
          </thead>
          <tbody>
            {deploymentRows.map((row) => (
              <tr key={row.deployment.id}>
                <td>
                  <strong>{row.deployment.version}</strong>
                  <small>{row.deployment.commit_sha || "No commit SHA"}</small>
                </td>
                <td>
                  {row.instance.companyName} / {row.instance.projectName}
                  <small>{row.instance.environmentName} / {row.instance.appName}</small>
                </td>
                <td>{row.deployment.actor || "Hub"}</td>
                <td>{formatDate(row.deployment.started_at)}<small>{formatRelative(row.deployment.started_at)}</small></td>
                <td>
                  <StatusPill value={deploymentContextState(row)} />
                  <small>{row.deployment.finished_at ? `Finished ${formatRelative(row.deployment.finished_at)}` : "Short release window"}</small>
                </td>
              </tr>
            ))}
            {!loading && deploymentRows.length === 0 && (
              <tr><td colSpan={5}><EmptyState title="No deployment markers yet" /></td></tr>
            )}
            {loading && deploymentRows.length === 0 && (
              <tr><td colSpan={5}><EmptyState title="Loading deployment history" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>
    </div>
  );
}

function deploymentTargets(instances: InstanceModel[]) {
  const byScope = new Map<string, InstanceModel>();
  for (const instance of instances) {
    if (!byScope.has(scopeKey(instance))) byScope.set(scopeKey(instance), instance);
  }
  return Array.from(byScope.values()).sort((left, right) =>
    left.companyName.localeCompare(right.companyName) ||
    left.projectName.localeCompare(right.projectName) ||
    left.environmentName.localeCompare(right.environmentName) ||
    left.appName.localeCompare(right.appName)
  );
}

function scopeKey(instance: InstanceModel) {
  const scope = instance.scope;
  return [scope.baseUrl, scope.org, scope.project, scope.environment, scope.app].join("\u0000");
}

function deploymentContextState(row: DeploymentRow) {
  const started = new Date(row.deployment.started_at).getTime();
  const finished = row.deployment.finished_at
    ? new Date(row.deployment.finished_at).getTime()
    : started + 30 * 60 * 1000;
  return Date.now() <= finished + 5 * 60 * 1000 ? "current" : "recorded";
}
