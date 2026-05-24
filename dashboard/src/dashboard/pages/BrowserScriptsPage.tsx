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
  onAllowScripts,
  onUpdateEntries,
  onUpdateEntry,
  scriptRows
}: {
  actionLoading: boolean;
  allowlistRows: AllowlistRow[];
  onAllowScript: (row: BrowserScriptRow) => Promise<void>;
  onAllowScripts: (rows: BrowserScriptRow[]) => Promise<void>;
  onUpdateEntries: (rows: AllowlistRow[], status: string) => Promise<void>;
  onUpdateEntry: (row: AllowlistRow, status: string) => Promise<void>;
  scriptRows: BrowserScriptRow[];
}) {
  const [filter, setFilter] = useState<ScriptFilter>("unallowlisted");
  const [error, setError] = useState("");
  const [selectedScriptKeys, setSelectedScriptKeys] = useState<Set<string>>(() => new Set());
  const [selectedAllowlistKeys, setSelectedAllowlistKeys] = useState<Set<string>>(() => new Set());

  const filteredScripts = scriptRows.filter((row) => {
    switch (filter) {
      case "unallowlisted":
        return !row.allowlisted;
      case "tag-managers":
        return row.script.tag_manager;
      case "inline":
        return isInlineScript(row.script);
      default:
        return true;
    }
  });
  const displayedScripts = filteredScripts.slice(0, 200);
  const selectedScriptRows = displayedScripts.filter((row) => selectedScriptKeys.has(scriptRowKey(row)));
  const allowableScriptRows = selectedScriptRows.filter((row) => !row.allowlisted);
  const allVisibleScriptsSelected = displayedScripts.length > 0 && selectedScriptRows.length === displayedScripts.length;
  const selectedAllowlistRows = allowlistRows.filter((row) => selectedAllowlistKeys.has(allowlistRowKey(row)));
  const allAllowlistRowsSelected = allowlistRows.length > 0 && selectedAllowlistRows.length === allowlistRows.length;

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

  async function handleBulkAllow() {
    setError("");
    try {
      await onAllowScripts(allowableScriptRows);
      setSelectedScriptKeys(new Set());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }

  async function handleBulkEntry(status: string) {
    setError("");
    try {
      await onUpdateEntries(selectedAllowlistRows, status);
      setSelectedAllowlistKeys(new Set());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }

  function toggleScript(row: BrowserScriptRow, checked: boolean) {
    setSelectedScriptKeys((current) => {
      const next = new Set(current);
      const key = scriptRowKey(row);
      if (checked) {
        next.add(key);
      } else {
        next.delete(key);
      }
      return next;
    });
  }

  function toggleVisibleScripts(checked: boolean) {
    setSelectedScriptKeys((current) => {
      const next = new Set(current);
      for (const row of displayedScripts) {
        const key = scriptRowKey(row);
        if (checked) {
          next.add(key);
        } else {
          next.delete(key);
        }
      }
      return next;
    });
  }

  function toggleAllowlistEntry(row: AllowlistRow, checked: boolean) {
    setSelectedAllowlistKeys((current) => {
      const next = new Set(current);
      const key = allowlistRowKey(row);
      if (checked) {
        next.add(key);
      } else {
        next.delete(key);
      }
      return next;
    });
  }

  function toggleAllAllowlistEntries(checked: boolean) {
    setSelectedAllowlistKeys((current) => {
      const next = new Set(current);
      for (const row of allowlistRows) {
        const key = allowlistRowKey(row);
        if (checked) {
          next.add(key);
        } else {
          next.delete(key);
        }
      }
      return next;
    });
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
        <div className="bulk-action-bar">
          <span>{selectedScriptRows.length} selected</span>
          <button
            className="ghost-button compact"
            disabled={actionLoading || allowableScriptRows.length === 0}
            onClick={() => void handleBulkAllow()}
            type="button"
          >
            {actionLoading ? <Loader2 size={14} className="spin" /> : <ShieldCheck size={14} />}
            Allow selected
          </button>
          {selectedScriptRows.length > 0 && (
            <button className="link-button" type="button" disabled={actionLoading} onClick={() => setSelectedScriptKeys(new Set())}>
              Clear
            </button>
          )}
        </div>
        <ResponsiveTable>
          <thead>
            <tr>
              <th className="select-cell">
                <input
                  aria-label="Select all visible scripts"
                  checked={allVisibleScriptsSelected}
                  disabled={displayedScripts.length === 0}
                  onChange={(event) => toggleVisibleScripts(event.target.checked)}
                  type="checkbox"
                />
              </th>
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
            {displayedScripts.map((row) => (
              <tr key={`${row.instance.key}:${row.script.event_id}`}>
                <td className="select-cell">
                  <input
                    aria-label={`Select ${browserScriptLabel(row.script)}`}
                    checked={selectedScriptKeys.has(scriptRowKey(row))}
                    onChange={(event) => toggleScript(row, event.target.checked)}
                    type="checkbox"
                  />
                </td>
                <td><SeverityPill value={row.script.severity} /></td>
                <td>
                  <strong>{browserScriptLabel(row.script)}</strong>
                  <small>{browserScriptMeta(row.script)}</small>
                  {row.script.inline_preview && (
                    <pre className="script-preview">{row.script.inline_preview}{row.script.inline_preview_truncated ? "\n..." : ""}</pre>
                  )}
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
              <tr><td colSpan={9}><EmptyState title="No browser scripts match" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>

      <Panel title="Script allowlist" icon={ShieldCheck}>
        <div className="bulk-action-bar">
          <span>{selectedAllowlistRows.length} selected</span>
          <button
            className="ghost-button compact"
            disabled={actionLoading || selectedAllowlistRows.length === 0}
            onClick={() => void handleBulkEntry("revoked")}
            type="button"
          >
            {actionLoading ? <Loader2 size={14} className="spin" /> : <XCircle size={14} />}
            Revoke
          </button>
          <button
            className="ghost-button compact"
            disabled={actionLoading || selectedAllowlistRows.length === 0}
            onClick={() => void handleBulkEntry("active")}
            type="button"
          >
            <CheckCircle2 size={14} />
            Reinstate
          </button>
          {selectedAllowlistRows.length > 0 && (
            <button className="link-button" type="button" disabled={actionLoading} onClick={() => setSelectedAllowlistKeys(new Set())}>
              Clear
            </button>
          )}
        </div>
        <ResponsiveTable>
          <thead>
            <tr>
              <th className="select-cell">
                <input
                  aria-label="Select all allowlist entries"
                  checked={allAllowlistRowsSelected}
                  disabled={allowlistRows.length === 0}
                  onChange={(event) => toggleAllAllowlistEntries(event.target.checked)}
                  type="checkbox"
                />
              </th>
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
                <td className="select-cell">
                  <input
                    aria-label={`Select ${row.entry.value}`}
                    checked={selectedAllowlistKeys.has(allowlistRowKey(row))}
                    onChange={(event) => toggleAllowlistEntry(row, event.target.checked)}
                    type="checkbox"
                  />
                </td>
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
              <tr><td colSpan={10}><EmptyState title="No allowlist entries yet" /></td></tr>
            )}
          </tbody>
        </ResponsiveTable>
      </Panel>
    </div>
  );
}

function browserScriptMeta(script: BrowserScriptRow["script"]) {
  if (isInlineScript(script)) {
    const parts = ["inline script"];
    if (script.inline_bytes) parts.push(`${script.inline_bytes.toLocaleString()} bytes`);
    if (script.sha256) parts.push(`sha256 ${script.sha256.slice(0, 12)}...`);
    return parts.join(" / ");
  }
  return script.url_redacted ?? script.url ?? script.target;
}

function isInlineScript(script: BrowserScriptRow["script"]) {
  return script.source_type === "inline" || Boolean(script.inline_preview) || (!script.url && !script.url_redacted && Boolean(script.sha256));
}

function scriptRowKey(row: BrowserScriptRow) {
  return `${row.instance.key}:${row.script.event_id}`;
}

function allowlistRowKey(row: AllowlistRow) {
  return `${row.instance.key}:${row.entry.id}`;
}
