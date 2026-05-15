import { DatabaseZap, Filter, Loader2, Save, ShieldCheck, UserPlus } from "lucide-react";
import { FormEvent, useEffect, useState } from "react";
import { createHubUser, defaultScope, enrollHubUserTOTP, loadHubUsers, updateHubUser } from "../../api";
import type { ApiScope, HubUser, HubUserTOTPEnrollment, InventoryOrganization } from "../../types";
import type { ActionState } from "../types";
import { upsertUser } from "../utils/users";
import { EmptyState, InlineAlert, LoadingBlock, Panel, ResponsiveTable, StatusPill, TextInput } from "../components/common";
import { InventorySummary } from "../components/summary";

export function SettingsPage({
  actionState,
  draftScope,
  inventory,
  loading,
  onActionChange,
  onScopeChange,
  onScopeSubmit,
  scope,
  user
}: {
  actionState: ActionState;
  draftScope: ApiScope;
  inventory: InventoryOrganization[];
  loading: boolean;
  onActionChange: (state: ActionState) => void;
  onScopeChange: (scope: ApiScope) => void;
  onScopeSubmit: (event: FormEvent<HTMLFormElement>) => void;
  scope: ApiScope;
  user?: HubUser;
}) {
  return (
    <div className="settings-grid">
      <Panel title="Hub scope" icon={Filter}>
        <form className="form-stack" onSubmit={onScopeSubmit}>
          <TextInput label="Hub base URL" value={draftScope.baseUrl} placeholder="Relative to current origin" onChange={(baseUrl) => onScopeChange({ ...draftScope, baseUrl })} />
          <TextInput label="Company slug" value={draftScope.org} onChange={(org) => onScopeChange({ ...draftScope, org })} />
          <TextInput label="Site slug" value={draftScope.project} onChange={(project) => onScopeChange({ ...draftScope, project })} />
          <TextInput label="Environment" value={draftScope.environment} onChange={(environment) => onScopeChange({ ...draftScope, environment })} />
          <TextInput label="App" value={draftScope.app} onChange={(app) => onScopeChange({ ...draftScope, app })} />
          <div className="button-row">
            <button className="primary-button" type="submit" disabled={loading}>{loading ? <Loader2 size={15} className="spin" /> : <Save size={15} />} Save</button>
            <button className="ghost-button" type="button" onClick={() => onScopeChange(defaultScope)}>Reset</button>
          </div>
        </form>
      </Panel>
      <Panel title="Triage defaults" icon={ShieldCheck}>
        <div className="form-stack">
          <TextInput label="Actor" value={actionState.actor} onChange={(actor) => onActionChange({ ...actionState, actor })} />
          <TextInput label="Reason" value={actionState.reason} onChange={(reason) => onActionChange({ ...actionState, reason })} />
          <label>Note<textarea rows={4} value={actionState.note} onChange={(event) => onActionChange({ ...actionState, note: event.target.value })} /></label>
        </div>
      </Panel>
      <Panel title="Inventory" icon={DatabaseZap}>
        <InventorySummary organizations={inventory} />
      </Panel>
      <UserAccessManager currentUser={user} scope={scope} />
    </div>
  );
}

function UserAccessManager({ currentUser, scope }: { currentUser?: HubUser; scope: ApiScope }) {
  const [users, setUsers] = useState<HubUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [savingID, setSavingID] = useState("");
  const [error, setError] = useState("");
  const [enrollment, setEnrollment] = useState<{ enrollment: HubUserTOTPEnrollment; user: HubUser } | null>(null);
  const [form, setForm] = useState({
    access_level: "operator",
    display_name: "",
    email: "",
    password: "",
    status: "active",
    two_factor_required: true
  });
  const canManage = !currentUser || ["owner", "admin"].includes(currentUser.access_level);

  async function refreshUsers() {
    setLoading(true);
    setError("");
    try {
      setUsers(await loadHubUsers(scope));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (canManage) {
      void refreshUsers();
    }
  }, [canManage, scope.baseUrl, scope.org, scope.project, scope.environment]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSavingID("new");
    setError("");
    try {
      const user = await createHubUser(scope, form);
      setUsers((current) => upsertUser(current, user));
      setForm({ access_level: "operator", display_name: "", email: "", password: "", status: "active", two_factor_required: true });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSavingID("");
    }
  }

  async function saveUser(user: HubUser, patch: Partial<Pick<HubUser, "access_level" | "display_name" | "status" | "two_factor_required">>) {
    setSavingID(user.id);
    setError("");
    try {
      const next = { ...user, ...patch };
      const saved = await updateHubUser(scope, user, {
        access_level: next.access_level,
        display_name: next.display_name,
        status: next.status,
        two_factor_required: next.two_factor_required
      });
      setUsers((current) => upsertUser(current, saved));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSavingID("");
    }
  }

  async function enroll(user: HubUser) {
    setSavingID(user.id);
    setError("");
    try {
      const result = await enrollHubUserTOTP(scope, user);
      setEnrollment(result);
      setUsers((current) => upsertUser(current, result.user));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSavingID("");
    }
  }

  if (!canManage) {
    return <Panel title="Users" icon={UserPlus}><EmptyState title="Admin access required" /></Panel>;
  }

  return (
    <Panel title="Users" icon={UserPlus}>
      <form className="user-form" onSubmit={submit}>
        <TextInput label="Email" value={form.email} onChange={(email) => setForm((current) => ({ ...current, email }))} />
        <TextInput label="Name" value={form.display_name} onChange={(display_name) => setForm((current) => ({ ...current, display_name }))} />
        <label>Password<input minLength={12} required type="password" value={form.password} onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))} /></label>
        <label>Access<select value={form.access_level} onChange={(event) => setForm((current) => ({ ...current, access_level: event.target.value }))}>
          <option value="owner">Owner</option>
          <option value="admin">Admin</option>
          <option value="operator">Operator</option>
          <option value="viewer">Viewer</option>
        </select></label>
        <label className="check-row"><input checked={form.two_factor_required} type="checkbox" onChange={(event) => setForm((current) => ({ ...current, two_factor_required: event.target.checked }))} />Require 2FA</label>
        <button className="primary-button" type="submit" disabled={savingID === "new"}>{savingID === "new" ? <Loader2 size={15} className="spin" /> : <UserPlus size={15} />} Add</button>
      </form>
      {error && <InlineAlert message={error} />}
      {loading ? <LoadingBlock /> : (
        <ResponsiveTable>
          <thead>
            <tr><th>User</th><th>Access</th><th>Status</th><th>2FA</th><th /></tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td><strong>{user.display_name || user.email}</strong><small>{user.email}</small></td>
                <td><select value={user.access_level} onChange={(event) => void saveUser(user, { access_level: event.target.value })}>
                  <option value="owner">Owner</option>
                  <option value="admin">Admin</option>
                  <option value="operator">Operator</option>
                  <option value="viewer">Viewer</option>
                </select></td>
                <td><select value={user.status} onChange={(event) => void saveUser(user, { status: event.target.value })}>
                  <option value="active">Active</option>
                  <option value="invited">Invited</option>
                  <option value="disabled">Disabled</option>
                </select></td>
                <td><StatusPill value={user.two_factor_enabled ? "enabled" : user.two_factor_required ? "required" : "optional"} /></td>
                <td><button className="ghost-button" type="button" disabled={savingID === user.id} onClick={() => void enroll(user)}>QR</button></td>
              </tr>
            ))}
          </tbody>
        </ResponsiveTable>
      )}
      {enrollment && (
        <div className="totp-box">
          <strong>{enrollment.user.email}</strong>
          <img src={enrollment.enrollment.qr_code_data_url} alt="2FA QR code" />
          <small>{enrollment.enrollment.otpauth_url}</small>
        </div>
      )}
    </Panel>
  );
}
