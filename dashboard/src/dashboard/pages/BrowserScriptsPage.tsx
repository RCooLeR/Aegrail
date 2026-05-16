import { CheckCircle2, Globe, Loader2, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { browserScriptLabel } from "../model/viewModels";
import type { AllowlistRow, BrowserScriptRow } from "../types";
import { formatRelative } from "../utils/time";
import { EmptyState, InlineAlert, Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";

type ScriptFilter = "all" | "unallowlisted" | "tag-managers" | "inline";

export function BrowserScriptsPage({
  actionLoading,
  allowlistRows,
  onAllowScript,
  onUpdateEntry,
  scriptRows
}: {
  actionLoading: boolean;
  allowlistRows: AllowlistRow[];
  onAllowScript: (row: BrowserScriptRow) => Promise<void>;
  onUpdateEntry: (row: AllowlistRow, status: string) => Promise<void>;
  scriptRows: BrowserScriptRow[];
}) {
  const [filter, setFilter] = useState<ScriptFilter>("unallowlisted");
  const [error, setError] = useState("");

  const filteredScripts = scriptRows.filter((row) => {
    switch (filter) {
      case "unallowlisted":
        return !row.allowlisted;
      case "tag-managers":
        return row.script.tag_manager;
      case "inline":
        return Boolean(row.script.sha256);
      default:
        return true;
    }
  });

  async function handleAllow(row: BrowserScriptRow) {
    setError("");
    try {
      await onAllowScript(row);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }

  async function handleEntry(row: AllowlistRow, status: string) {
    setError("");
    try {
      await onUpdateEntry(row, status);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }

  return (
    <div className="page-stack">
      {error && <InlineAlert message={error} />}
      <Panel
        title="Browser scripts"
        icon={Globe}
        action={
          <select value={filter} onChange={(event) => setFilter(event.target.value as ScriptFilter)}>
            <option value="unallowlisted">Not allow-listed</option>
            <option value="all">All recent scripts</option>
            <option value="tag-managers">Tag managers</option>
            <option value="inline">Inline scripts</option>
          </select>
        }
      >
        <ResponsiveTable>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Script</th>
              <th>Page</th>
              <th>Company / Site</th>
              <th>Node</th>
              <th>Status</th>
              <th>Seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {filteredScripts.slice(0, 200).map((row) => (
              <tr key={`${row.instance.key}:${row.script.event_id}`}>
                <td><SeverityPill value={row.script.severity} /></td>
                <td>
                  <strong>{browserScriptLabel(row.script)}</strong>
                  <small>{row.script.url_redacted ?? row.script.url ?? row.script.target}</small>
                </td>
                <td><small>{row.script.page_url || row.script.final_url || "-"}</small></td>
                <td>{row.instance.companyName}<small>{row.instance.projectName}</small></td>
                <td>{row.instance.appName}</td>
                <td>{row.allowlisted ? <StatusPill value="active" /> : <StatusPill value="new" />}</td>
                <td>{formatRelative(row.script.event_time)}</td>
                <td>
                  {!row.allowlisted && (
                    <button
                      className="ghost-button compact"
                      disabled={actionLoading}
                      onClick={() => void handleAllow(row)}
                      type="button"
                    >
                      {actionLoading ? <Loader2 size={14} className="spin" /> : <ShieldCheck size={14} />}
                      Allow
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {filteredScripts.length === 0 && (
              <tr><td colSpan={8}><EmptyState title="No browser scripts match" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>

      <Panel title="Script allowlist" icon={ShieldCheck}>
        <ResponsiveTable>
          <thead>
            <tr>
              <th>Kind</th>
              <th>Value</th>
              <th>Page scope</th>
              <th>Company / Site</th>
              <th>Reason</th>
              <th>Approved by</th>
              <th>Status</th>
              <th>Updated</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {allowlistRows.map((row) => (
              <tr key={`${row.instance.key}:${row.entry.id}`}>
                <td>{row.entry.kind}</td>
                <td><strong>{row.entry.value}</strong></td>
                <td><small>{row.entry.page_url || "all pages"}</small></td>
                <td>{row.instance.companyName}<small>{row.instance.projectName}</small></td>
                <td>{row.entry.reason || "-"}</td>
                <td>{row.entry.approved_by || "-"}</td>
                <td><StatusPill value={row.entry.status} /></td>
                <td>{formatRelative(row.entry.updated_at)}</td>
                <td>
                  {row.entry.status === "active" ? (
                    <button
                      className="ghost-button compact"
                      disabled={actionLoading}
                      onClick={() => void handleEntry(row, "revoked")}
                      type="button"
                    >
                      <XCircle size={14} />
                      Revoke
                    </button>
                  ) : (
                    <button
                      className="ghost-button compact"
                      disabled={actionLoading}
                      onClick={() => void handleEntry(row, "active")}
                      type="button"
                    >
                      <CheckCircle2 size={14} />
                      Reinstate
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {allowlistRows.length === 0 && (
              <tr><td colSpan={9}><EmptyState title="No allowlist entries yet" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>
    </div>
  );
}
