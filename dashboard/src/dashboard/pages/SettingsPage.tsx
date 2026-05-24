import {
  Bell,
  Building2,
  Copy,
  DatabaseZap,
  Filter,
  KeyRound,
  Loader2,
  MonitorCog,
  QrCode,
  Save,
  ShieldCheck,
  ShieldOff,
  SlidersHorizontal,
  UserCircle,
  UserPlus,
  Users
} from "lucide-react";
import { FormEvent, useEffect, useState } from "react";
import {
  createInventoryCompany,
  createInventoryNode,
  createInventorySite,
  createHubUser,
  defaultScope,
  deletePushSubscription,
  disableHubUserTOTP,
  loadHubUsers,
  loadPushNotificationConfig,
  savePushSubscription,
  startHubUserTOTP,
  updateInventoryAgent,
  updateInventoryApp,
  updateInventoryCompany,
  updateInventoryEnvironment,
  updateInventoryHost,
  updateInventoryProject,
  updateInventoryService,
  updateHubUser,
  verifyHubUserTOTP
} from "../../api";
import type { InstanceModel } from "../../estate";
import type { Agent, ApiScope, Host, HubUser, HubUserTOTPEnrollment, InventoryEnvironment, InventoryOrganization, InventoryProject, MonitoredApp, NodeProvisioning, PushNotificationConfig, Service } from "../../types";
import { autoModelValue, modelPresets } from "../config/modelPresets";
import type { ActionState, SiteRow } from "../types";
import { formatDate, formatRelative } from "../utils/time";
import { upsertUser } from "../utils/users";
import { EmptyState, InlineAlert, InlineSuccess, LoadingBlock, MiniBlock, Panel, ResponsiveTable, StatusPill, TextInput } from "../components/common";
import { InventorySummary } from "../components/summary";

type SettingsTab = "profile" | "scope" | "triage" | "companies" | "sites" | "nodes" | "users" | "inventory";

const tabs: Array<{ key: SettingsTab; label: string }> = [
  { key: "profile", label: "Profile" },
  { key: "scope", label: "Hub scope" },
  { key: "triage", label: "Triage" },
  { key: "companies", label: "Companies" },
  { key: "sites", label: "Sites" },
  { key: "nodes", label: "Nodes" },
  { key: "users", label: "Users & 2FA" },
  { key: "inventory", label: "Inventory" }
];

const appKindOptions = [
  { value: "wordpress", label: "WordPress" },
  { value: "wordpress-multisite", label: "WordPress network" },
  { value: "prestashop", label: "PrestaShop" },
  { value: "mautic", label: "Mautic" },
  { value: "yii2-rbac", label: "Yii2 RBAC" },
  { value: "laravel", label: "Laravel" },
  { value: "static", label: "Static site" },
  { value: "react", label: "React" },
  { value: "nodejs", label: "Node.js" },
  { value: "generic-php", label: "Generic PHP" }
];

export function SettingsPage({
  actionState,
  allInstances,
  allSites,
  draftScope,
  inventory,
  loading,
  onActionChange,
  onRefresh,
  onScopeChange,
  onScopeSubmit,
  scope,
  user
}: {
  actionState: ActionState;
  allInstances: InstanceModel[];
  allSites: SiteRow[];
  draftScope: ApiScope;
  inventory: InventoryOrganization[];
  loading: boolean;
  onActionChange: (state: ActionState) => void;
  onRefresh: () => void;
  onScopeChange: (scope: ApiScope) => void;
  onScopeSubmit: (event: FormEvent<HTMLFormElement>) => void;
  scope: ApiScope;
  user?: HubUser;
}) {
  const [activeTab, setActiveTab] = useState<SettingsTab>("profile");

  return (
    <div className="page-stack">
      <nav className="detail-tabs" aria-label="Settings tabs">
        {tabs.map((tab) => (
          <button
            className={activeTab === tab.key ? "active" : ""}
            key={tab.key}
            type="button"
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activeTab === "profile" && <ProfileSettings scope={scope} user={user} />}
      {activeTab === "scope" && (
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
      )}
      {activeTab === "triage" && (
        <Panel title="Triage defaults" icon={SlidersHorizontal}>
          <div className="form-stack">
            <TextInput label="Actor" value={actionState.actor} onChange={(actor) => onActionChange({ ...actionState, actor })} />
            <label>
              LLM model
              <select value={actionState.model} onChange={(event) => onActionChange({ ...actionState, model: event.target.value })}>
                <option value={autoModelValue}>Auto ranked installed model</option>
                {modelPresets.map((preset) => (
                  <option key={preset.value} value={preset.value}>
                    {preset.rank}. {preset.label} ({preset.size})
                  </option>
                ))}
              </select>
            </label>
            <div className="model-preset-list">
              {modelPresets.map((preset) => (
                <div className="model-preset-row" key={preset.value}>
                  <strong>{preset.rank}. {preset.label}</strong>
                  <small>{preset.size} / {preset.bestUse}</small>
                </div>
              ))}
            </div>
            <TextInput label="Reason" value={actionState.reason} onChange={(reason) => onActionChange({ ...actionState, reason })} />
            <label>Note<textarea rows={4} value={actionState.note} onChange={(event) => onActionChange({ ...actionState, note: event.target.value })} /></label>
          </div>
        </Panel>
      )}
      {activeTab === "companies" && <CompaniesSettings instances={allInstances} inventory={inventory} onRefresh={onRefresh} scope={scope} />}
      {activeTab === "sites" && <SitesSettings inventory={inventory} onRefresh={onRefresh} scope={scope} sites={allSites} />}
      {activeTab === "nodes" && <NodesSettings instances={allInstances} inventory={inventory} onRefresh={onRefresh} scope={scope} />}
      {activeTab === "users" && <UserAccessManager currentUser={user} scope={scope} />}
      {activeTab === "inventory" && (
        <Panel title="Inventory" icon={DatabaseZap}>
          <InventorySummary organizations={inventory} />
          <InventoryTree organizations={inventory} />
        </Panel>
      )}
    </div>
  );
}

function ProfileSettings({ scope, user }: { scope: ApiScope; user?: HubUser }) {
  return (
    <div className="page-stack">
      <Panel title="Profile" icon={UserCircle}>
        {user ? (
          <div className="settings-summary-grid">
            <MiniBlock label="User" value={user.display_name || user.email} />
            <MiniBlock label="Email" value={user.email} />
            <MiniBlock label="Access" value={user.access_level} />
            <MiniBlock label="Status" value={user.status} />
            <MiniBlock label="2FA" value={user.two_factor_enabled ? "enabled" : user.two_factor_pending ? "pending" : user.two_factor_required ? "required" : "optional"} />
            <MiniBlock label="Last sign-in" value={user.last_login_at ? formatRelative(user.last_login_at) : "never"} />
          </div>
        ) : (
          <EmptyState title="No signed-in user loaded" />
        )}
        <p className="muted-line">Current dashboard scope: {scope.org} / {scope.project} / {scope.environment} / {scope.app || "all apps"}</p>
      </Panel>
      <PushNotificationSettings scope={scope} />
    </div>
  );
}

function PushNotificationSettings({ scope }: { scope: ApiScope }) {
  const [config, setConfig] = useState<PushNotificationConfig | null>(null);
  const [supported, setSupported] = useState(false);
  const [permission, setPermission] = useState<NotificationPermission>("default");
  const [subscribed, setSubscribed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const nextConfig = await loadPushNotificationConfig(scope);
      setConfig(nextConfig);
      const canPush = browserPushSupported();
      setSupported(canPush);
      setPermission(canPush ? Notification.permission : "denied");
      if (canPush) {
        const registration = await navigator.serviceWorker.getRegistration("/dashboard/");
        const subscription = await registration?.pushManager.getSubscription();
        setSubscribed(Boolean(subscription));
      } else {
        setSubscribed(false);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, [scope.baseUrl]);

  async function enablePush() {
    setSaving(true);
    setError("");
    setMessage("");
    try {
      if (!config?.enabled || !config.public_key) {
        throw new Error("Browser push is not configured on this Hub");
      }
      if (!browserPushSupported()) {
        throw new Error("This browser cannot receive push notifications from this page");
      }
      const nextPermission = Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
      setPermission(nextPermission);
      if (nextPermission !== "granted") {
        throw new Error("Browser notification permission was not granted");
      }
      const registration = await navigator.serviceWorker.register("/dashboard/aegrail-sw.js", { scope: "/dashboard/" });
      const existing = await registration.pushManager.getSubscription();
      const subscription = existing ?? await registration.pushManager.subscribe({
        applicationServerKey: urlBase64ToUint8Array(config.public_key),
        userVisibleOnly: true
      });
      await savePushSubscription(scope, pushSubscriptionPayload(subscription));
      setSubscribed(true);
      setMessage("Push notifications are enabled for this browser.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  async function disablePush() {
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const registration = await navigator.serviceWorker.getRegistration("/dashboard/");
      const subscription = await registration?.pushManager.getSubscription();
      if (subscription) {
        const endpoint = subscription.endpoint;
        await subscription.unsubscribe();
        await deletePushSubscription(scope, endpoint);
      }
      setSubscribed(false);
      setMessage("Push notifications are disabled for this browser.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  const disabledReason = pushDisabledReason(config, supported, permission);
  return (
    <Panel title="Push notifications" icon={Bell}>
      {error && <InlineAlert message={error} />}
      {message && <InlineSuccess message={message} />}
      {loading ? <LoadingBlock /> : (
        <div className="notification-settings">
          <div className="settings-summary-grid">
            <MiniBlock label="Hub push" value={config?.enabled ? "configured" : "disabled"} />
            <MiniBlock label="Browser" value={supported ? "supported" : "unsupported"} />
            <MiniBlock label="Permission" value={permission} />
            <MiniBlock label="This browser" value={subscribed ? "subscribed" : "not subscribed"} />
          </div>
          {disabledReason && <p className="muted-line">{disabledReason}</p>}
          <div className="button-row">
            <button className="primary-button" type="button" disabled={saving || Boolean(disabledReason) || subscribed} onClick={() => void enablePush()}>
              {saving ? <Loader2 size={15} className="spin" /> : <Bell size={15} />}
              Enable
            </button>
            <button className="ghost-button" type="button" disabled={saving || !subscribed} onClick={() => void disablePush()}>
              Disable
            </button>
          </div>
        </div>
      )}
    </Panel>
  );
}

function browserPushSupported() {
  return typeof window !== "undefined" &&
    window.isSecureContext &&
    "Notification" in window &&
    "serviceWorker" in navigator &&
    "PushManager" in window;
}

function pushDisabledReason(config: PushNotificationConfig | null, supported: boolean, permission: NotificationPermission) {
  if (!config?.enabled) {
    return "Browser push is not configured on this Hub.";
  }
  if (!supported) {
    return "Browser push requires HTTPS or localhost and a browser with Service Worker support.";
  }
  if (permission === "denied") {
    return "Browser notifications are blocked for this site.";
  }
  return "";
}

function pushSubscriptionPayload(subscription: PushSubscription): PushSubscriptionJSON {
  const payload = subscription.toJSON();
  if (!payload.endpoint || !payload.keys?.p256dh || !payload.keys.auth) {
    throw new Error("Browser returned an incomplete push subscription");
  }
  return payload;
}

function urlBase64ToUint8Array(value: string) {
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = window.atob(base64);
  const output = new Uint8Array(raw.length);
  for (let index = 0; index < raw.length; index += 1) {
    output[index] = raw.charCodeAt(index);
  }
  return output;
}

function CompaniesSettings({ instances, inventory, onRefresh, scope }: { instances: InstanceModel[]; inventory: InventoryOrganization[]; onRefresh: () => void; scope: ApiScope }) {
  return (
    <div className="page-stack">
      <CompanyProvisioner onRefresh={onRefresh} scope={scope} />
      <CompaniesOverview instances={instances} inventory={inventory} onRefresh={onRefresh} scope={scope} />
    </div>
  );
}

function SitesSettings({ inventory, onRefresh, scope, sites }: { inventory: InventoryOrganization[]; onRefresh: () => void; scope: ApiScope; sites: SiteRow[] }) {
  return (
    <div className="page-stack">
      <SiteProvisioner onRefresh={onRefresh} scope={scope} />
      <SitesOverview inventory={inventory} onRefresh={onRefresh} scope={scope} sites={sites} />
    </div>
  );
}

function NodesSettings({ instances, inventory, onRefresh, scope }: { instances: InstanceModel[]; inventory: InventoryOrganization[]; onRefresh: () => void; scope: ApiScope }) {
  return (
    <div className="page-stack">
      <NodeProvisioner onRefresh={onRefresh} scope={scope} />
      <NodesInventoryEditor inventory={inventory} onRefresh={onRefresh} scope={scope} />
      <NodesOverview instances={instances} />
    </div>
  );
}

function CompanyProvisioner({ onRefresh, scope }: { onRefresh: () => void; scope: ApiScope }) {
  const [form, setForm] = useState({ name: "", slug: "" });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const organization = await createInventoryCompany(scope, form);
      setMessage(`Company created: ${organization.name}`);
      setForm({ name: "", slug: "" });
      onRefresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Panel title="Create company" icon={Building2}>
      {error && <InlineAlert message={error} />}
      {message && <InlineSuccess message={message} />}
      <form className="form-grid compact" onSubmit={submit}>
        <TextInput label="Company slug" value={form.slug} onChange={(slug) => setForm((current) => ({ ...current, slug }))} />
        <TextInput label="Display name" value={form.name} onChange={(name) => setForm((current) => ({ ...current, name }))} />
        <button className="primary-button" type="submit" disabled={saving}>{saving ? <Loader2 size={15} className="spin" /> : <Save size={15} />} Create</button>
      </form>
    </Panel>
  );
}

function SiteProvisioner({ onRefresh, scope }: { onRefresh: () => void; scope: ApiScope }) {
  const [form, setForm] = useState({
    app: scope.app || scope.project || "frontend",
    app_name: "",
    environment: scope.environment || "production",
    kind: "wordpress",
    org: scope.org,
    project: scope.project,
    project_name: "",
    service: "frontend"
  });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const result = await createInventorySite(scope, form);
      setMessage(`Site created: ${result.project.name} / ${result.environment.slug} / ${result.app.slug}`);
      onRefresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Panel title="Create site" icon={Building2}>
      {error && <InlineAlert message={error} />}
      {message && <InlineSuccess message={message} />}
      <form className="form-grid compact" onSubmit={submit}>
        <TextInput label="Company slug" value={form.org} onChange={(org) => setForm((current) => ({ ...current, org }))} />
        <TextInput label="Site slug" value={form.project} onChange={(project) => setForm((current) => ({ ...current, project }))} />
        <TextInput label="Site name" value={form.project_name} onChange={(project_name) => setForm((current) => ({ ...current, project_name }))} />
        <TextInput label="Environment" value={form.environment} onChange={(environment) => setForm((current) => ({ ...current, environment }))} />
        <TextInput label="App slug" value={form.app} onChange={(app) => setForm((current) => ({ ...current, app }))} />
        <label>Kind<select value={form.kind} onChange={(event) => setForm((current) => ({ ...current, kind: event.target.value }))}>
          {appKindOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select></label>
        <TextInput label="Service" value={form.service} onChange={(service) => setForm((current) => ({ ...current, service }))} />
        <button className="primary-button" type="submit" disabled={saving}>{saving ? <Loader2 size={15} className="spin" /> : <Save size={15} />} Create</button>
      </form>
    </Panel>
  );
}

function NodeProvisioner({ onRefresh, scope }: { onRefresh: () => void; scope: ApiScope }) {
  const [form, setForm] = useState({
    agent_id: "",
    app: scope.app || scope.project || "frontend",
    environment: scope.environment || "production",
    host: "",
    hostname: "",
    interval: "30s",
    org: scope.org,
    project: scope.project,
    queue_dir: "/var/lib/aegrail/queue",
    region: "",
    service: "frontend",
    state_dir: "/var/lib/aegrail/state"
  });
  const [provisioning, setProvisioning] = useState<NodeProvisioning | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setCopied(false);
    try {
      const result = await createInventoryNode(scope, form);
      setProvisioning(result);
      onRefresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  async function copyConfig() {
    if (!provisioning) {
      return;
    }
    await navigator.clipboard.writeText(provisioning.sample_config);
    setCopied(true);
  }

  return (
    <Panel title="Create node" icon={MonitorCog}>
      {error && <InlineAlert message={error} />}
      <form className="form-grid compact" onSubmit={submit}>
        <TextInput label="Company slug" value={form.org} onChange={(org) => setForm((current) => ({ ...current, org }))} />
        <TextInput label="Site slug" value={form.project} onChange={(project) => setForm((current) => ({ ...current, project }))} />
        <TextInput label="Environment" value={form.environment} onChange={(environment) => setForm((current) => ({ ...current, environment }))} />
        <TextInput label="App" value={form.app} onChange={(app) => setForm((current) => ({ ...current, app }))} />
        <TextInput label="Service" value={form.service} onChange={(service) => setForm((current) => ({ ...current, service }))} />
        <TextInput label="Node slug" value={form.host} onChange={(host) => setForm((current) => ({ ...current, host }))} />
        <TextInput label="Hostname" value={form.hostname} onChange={(hostname) => setForm((current) => ({ ...current, hostname }))} />
        <TextInput label="Node ID" value={form.agent_id} placeholder="Generated when empty" onChange={(agent_id) => setForm((current) => ({ ...current, agent_id }))} />
        <TextInput label="Queue dir" value={form.queue_dir} onChange={(queue_dir) => setForm((current) => ({ ...current, queue_dir }))} />
        <TextInput label="State dir" value={form.state_dir} onChange={(state_dir) => setForm((current) => ({ ...current, state_dir }))} />
        <TextInput label="Interval" value={form.interval} onChange={(interval) => setForm((current) => ({ ...current, interval }))} />
        <button className="primary-button" type="submit" disabled={saving}>{saving ? <Loader2 size={15} className="spin" /> : <KeyRound size={15} />} Create & generate config</button>
      </form>
      {provisioning && (
        <div className="provisioning-box">
          <div className="settings-summary-grid">
            <MiniBlock label="Node ID" value={provisioning.node_id} />
            <MiniBlock label="Protocol" value={provisioning.agent.wire_protocol || "aegrail-wire-v1"} />
            <MiniBlock label="Fingerprint" value={provisioning.agent.fingerprint} />
          </div>
          <div className="button-row">
            <button className="ghost-button" type="button" onClick={copyConfig}><Copy size={15} /> Copy config</button>
            {copied && <InlineSuccess message="Config copied." />}
          </div>
          <pre className="config-sample">{provisioning.sample_config}</pre>
        </div>
      )}
    </Panel>
  );
}

function CompaniesOverview({ instances, inventory, onRefresh, scope }: { instances: InstanceModel[]; inventory: InventoryOrganization[]; onRefresh: () => void; scope: ApiScope }) {
  const groups = inventory.map((organization) => {
    const companyInstances = instances.filter((instance) => instance.companySlug === organization.slug);
    return {
      activeAgents: companyInstances.reduce((sum, instance) => sum + instance.activeAgentCount, 0),
      agents: companyInstances.reduce((sum, instance) => sum + instance.agentCount, 0),
      issues: companyInstances.reduce((sum, instance) => sum + instance.openFindings, 0),
      nodes: companyInstances.length,
      organization,
      sites: organization.projects.length,
      status: companyInstances.some((instance) => instance.status === "critical")
        ? "critical"
        : companyInstances.some((instance) => instance.status === "warning")
          ? "warning"
          : "healthy"
    };
  });

  return (
    <Panel title="Companies" icon={Building2}>
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Company</th>
            <th>Status</th>
            <th>Sites</th>
            <th>Nodes</th>
            <th>Agents</th>
            <th>Open issues</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((row) => (
            <EditableCompanyRow key={row.organization.id} onRefresh={onRefresh} row={row} scope={scope} />
          ))}
          {groups.length === 0 && (
            <tr><td colSpan={7}><EmptyState title="No companies registered" /></td></tr>
          )}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}

function EditableCompanyRow({
  onRefresh,
  row,
  scope
}: {
  onRefresh: () => void;
  row: {
    activeAgents: number;
    agents: number;
    issues: number;
    nodes: number;
    organization: InventoryOrganization;
    sites: number;
    status: string;
  };
  scope: ApiScope;
}) {
  const [form, setForm] = useState({ name: row.organization.name, slug: row.organization.slug });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setForm({ name: row.organization.name, slug: row.organization.slug });
  }, [row.organization.name, row.organization.slug]);

  async function save() {
    setSaving(true);
    setError("");
    try {
      await updateInventoryCompany(scope, row.organization, form);
      onRefresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <tr>
      <td>
        <div className="table-edit-stack">
          <TextInput label="Display name" value={form.name} onChange={(name) => setForm((current) => ({ ...current, name }))} />
          <TextInput label="Slug" value={form.slug} onChange={(slug) => setForm((current) => ({ ...current, slug }))} />
          {error && <InlineAlert message={error} />}
        </div>
      </td>
      <td><StatusPill value={row.status} /></td>
      <td>{row.sites}</td>
      <td>{row.nodes}</td>
      <td>{row.activeAgents}/{row.agents}</td>
      <td>{row.issues}</td>
      <td>
        <div className="inline-row-actions">
          <small>{formatRelative(row.organization.updated_at)}</small>
          <button className="ghost-button compact" type="button" disabled={saving} onClick={() => void save()}>
            {saving ? <Loader2 size={14} className="spin" /> : <Save size={14} />}
            Save
          </button>
        </div>
      </td>
    </tr>
  );
}

function SitesOverview({ inventory, onRefresh, scope, sites }: { inventory: InventoryOrganization[]; onRefresh: () => void; scope: ApiScope; sites: SiteRow[] }) {
  const rows = inventory.flatMap((organization) =>
    organization.projects.flatMap((project) =>
      project.environments.flatMap((environment) =>
        environment.apps.map((app) => ({
          app,
          environment,
          organization,
          project,
          services: app.services ?? []
        }))
      )
    )
  );

  return (
    <Panel title="Sites" icon={Building2}>
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Company / Site</th>
            <th>Environment</th>
            <th>App</th>
            <th>Service</th>
            <th>State</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <EditableSiteRow
              key={`${row.organization.id}:${row.project.id}:${row.environment.id}:${row.app.id}`}
              onRefresh={onRefresh}
              row={row}
              scope={scope}
              state={sites.find((site) => site.companySlug === row.organization.slug && site.projectSlug === row.project.slug)}
            />
          ))}
          {rows.length === 0 && (
            <tr><td colSpan={6}><EmptyState title="No sites registered" /></td></tr>
          )}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}

function EditableSiteRow({
  onRefresh,
  row,
  scope,
  state
}: {
  onRefresh: () => void;
  row: {
    app: MonitoredApp;
    environment: InventoryEnvironment;
    organization: InventoryOrganization;
    project: InventoryProject;
    services: Service[];
  };
  scope: ApiScope;
  state?: SiteRow;
}) {
  const firstService = row.services[0];
  const [projectForm, setProjectForm] = useState({ name: row.project.name, slug: row.project.slug });
  const [environmentForm, setEnvironmentForm] = useState({ name: row.environment.name, slug: row.environment.slug });
  const [appForm, setAppForm] = useState({ kind: row.app.kind, name: row.app.name, slug: row.app.slug });
  const [serviceForm, setServiceForm] = useState({
    name: firstService?.name ?? "",
    role: firstService?.role ?? "",
    slug: firstService?.slug ?? ""
  });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setProjectForm({ name: row.project.name, slug: row.project.slug });
    setEnvironmentForm({ name: row.environment.name, slug: row.environment.slug });
    setAppForm({ kind: row.app.kind, name: row.app.name, slug: row.app.slug });
    setServiceForm({
      name: firstService?.name ?? "",
      role: firstService?.role ?? "",
      slug: firstService?.slug ?? ""
    });
  }, [firstService?.name, firstService?.role, firstService?.slug, row.app.kind, row.app.name, row.app.slug, row.environment.name, row.environment.slug, row.project.name, row.project.slug]);

  async function save() {
    setSaving(true);
    setError("");
    try {
      await updateInventoryProject(scope, row.project, projectForm);
      await updateInventoryEnvironment(scope, row.environment, environmentForm);
      await updateInventoryApp(scope, row.app, appForm);
      if (firstService) {
        await updateInventoryService(scope, firstService, serviceForm);
      }
      onRefresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <tr>
      <td>
        <strong>{row.organization.name}</strong>
        <small>{row.organization.slug}</small>
        <div className="table-edit-stack">
          <TextInput label="Site name" value={projectForm.name} onChange={(name) => setProjectForm((current) => ({ ...current, name }))} />
          <TextInput label="Site slug" value={projectForm.slug} onChange={(slug) => setProjectForm((current) => ({ ...current, slug }))} />
        </div>
      </td>
      <td>
        <div className="table-edit-stack">
          <TextInput label="Environment name" value={environmentForm.name} onChange={(name) => setEnvironmentForm((current) => ({ ...current, name }))} />
          <TextInput label="Environment slug" value={environmentForm.slug} onChange={(slug) => setEnvironmentForm((current) => ({ ...current, slug }))} />
        </div>
      </td>
      <td>
        <div className="table-edit-stack">
          <TextInput label="App name" value={appForm.name} onChange={(name) => setAppForm((current) => ({ ...current, name }))} />
          <TextInput label="App slug" value={appForm.slug} onChange={(slug) => setAppForm((current) => ({ ...current, slug }))} />
          <label>Kind<select value={appForm.kind} onChange={(event) => setAppForm((current) => ({ ...current, kind: event.target.value }))}>
            {appKindOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select></label>
        </div>
      </td>
      <td>
        {firstService ? (
          <div className="table-edit-stack">
            <TextInput label="Service name" value={serviceForm.name} onChange={(name) => setServiceForm((current) => ({ ...current, name }))} />
            <TextInput label="Service slug" value={serviceForm.slug} onChange={(slug) => setServiceForm((current) => ({ ...current, slug }))} />
            <TextInput label="Role" value={serviceForm.role} onChange={(role) => setServiceForm((current) => ({ ...current, role }))} />
          </div>
        ) : (
          <small>No service registered</small>
        )}
      </td>
      <td>
        {state ? (
          <>
            <StatusPill value={state.status} />
            <small>{state.openIssues} open / {state.instances.length} nodes</small>
            <small>Last signal {formatRelative(state.lastSignalAt)}</small>
          </>
        ) : (
          <StatusPill value="no signals" tone="neutral" />
        )}
        {error && <InlineAlert message={error} />}
      </td>
      <td>
        <button className="ghost-button compact" type="button" disabled={saving} onClick={() => void save()}>
          {saving ? <Loader2 size={14} className="spin" /> : <Save size={14} />}
          Save
        </button>
      </td>
    </tr>
  );
}

function NodesInventoryEditor({ inventory, onRefresh, scope }: { inventory: InventoryOrganization[]; onRefresh: () => void; scope: ApiScope }) {
  const rows = inventory.flatMap((organization) =>
    organization.projects.flatMap((project) =>
      project.environments.flatMap((environment) =>
        (environment.hosts ?? []).map((host) => ({
          environment,
          host,
          organization,
          project
        }))
      )
    )
  );

  return (
    <Panel title="Editable nodes" icon={MonitorCog}>
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Company / Site</th>
            <th>Node</th>
            <th>Agent</th>
            <th>Updated</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <EditableNodeRow key={row.host.id} onRefresh={onRefresh} row={row} scope={scope} />
          ))}
          {rows.length === 0 && (
            <tr><td colSpan={5}><EmptyState title="No nodes registered" /></td></tr>
          )}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}

function EditableNodeRow({
  onRefresh,
  row,
  scope
}: {
  onRefresh: () => void;
  row: {
    environment: InventoryEnvironment;
    host: Host;
    organization: InventoryOrganization;
    project: InventoryProject;
  };
  scope: ApiScope;
}) {
  const firstAgent = row.host.agents?.[0];
  const [hostForm, setHostForm] = useState({
    hostname: row.host.hostname,
    region: row.host.region ?? "",
    slug: row.host.slug
  });
  const [agentForm, setAgentForm] = useState({
    agent_id: firstAgent?.agent_id ?? "",
    version: firstAgent?.version ?? ""
  });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setHostForm({
      hostname: row.host.hostname,
      region: row.host.region ?? "",
      slug: row.host.slug
    });
    setAgentForm({
      agent_id: firstAgent?.agent_id ?? "",
      version: firstAgent?.version ?? ""
    });
  }, [firstAgent?.agent_id, firstAgent?.version, row.host.hostname, row.host.region, row.host.slug]);

  async function save() {
    setSaving(true);
    setError("");
    try {
      await updateInventoryHost(scope, row.host, {
        ...hostForm,
        labels: row.host.labels ?? {}
      });
      if (firstAgent) {
        await updateInventoryAgent(scope, firstAgent, agentForm);
      }
      onRefresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <tr>
      <td>
        <strong>{row.organization.name}</strong>
        <small>{row.project.name} / {row.environment.slug}</small>
      </td>
      <td>
        <div className="table-edit-stack">
          <TextInput label="Node slug" value={hostForm.slug} onChange={(slug) => setHostForm((current) => ({ ...current, slug }))} />
          <TextInput label="Hostname" value={hostForm.hostname} onChange={(hostname) => setHostForm((current) => ({ ...current, hostname }))} />
          <TextInput label="Region" value={hostForm.region} onChange={(region) => setHostForm((current) => ({ ...current, region }))} />
          {row.host.labels && Object.keys(row.host.labels).length > 0 && <small>Labels: {Object.entries(row.host.labels).map(([key, value]) => `${key}=${value}`).join(", ")}</small>}
        </div>
      </td>
      <td>
        {firstAgent ? (
          <div className="table-edit-stack">
            <TextInput label="Node ID" value={agentForm.agent_id} onChange={(agent_id) => setAgentForm((current) => ({ ...current, agent_id }))} />
            <TextInput label="Version" value={agentForm.version} onChange={(version) => setAgentForm((current) => ({ ...current, version }))} />
            <small>{firstAgent.fingerprint}</small>
          </div>
        ) : (
          <small>No agent attached</small>
        )}
      </td>
      <td><small>{formatRelative(row.host.updated_at)}</small></td>
      <td>
        <div className="inline-row-actions">
          {error && <InlineAlert message={error} />}
          <button className="ghost-button compact" type="button" disabled={saving} onClick={() => void save()}>
            {saving ? <Loader2 size={14} className="spin" /> : <Save size={14} />}
            Save
          </button>
        </div>
      </td>
    </tr>
  );
}

function NodesOverview({ instances }: { instances: InstanceModel[] }) {
  return (
    <Panel title="Nodes" icon={MonitorCog}>
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Company / Site</th>
            <th>Environment / App</th>
            <th>Status</th>
            <th>Agents online</th>
            <th>Coverage warnings</th>
            <th>Open issues</th>
            <th>Last signal</th>
          </tr>
        </thead>
        <tbody>
          {instances.map((instance) => (
            <tr key={instance.key}>
              <td>{instance.companyName}<small>{instance.projectName}</small></td>
              <td>{instance.environmentName}<small>{instance.appName}</small></td>
              <td><StatusPill value={instance.status} /></td>
              <td>{instance.activeAgentCount}/{instance.agentCount}</td>
              <td>{instance.coverageWarnings}</td>
              <td>{instance.openFindings}</td>
              <td>{formatRelative(instance.lastSignalAt)}</td>
            </tr>
          ))}
          {instances.length === 0 && (
            <tr><td colSpan={7}><EmptyState title="No nodes registered" /></td></tr>
          )}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}

function InventoryTree({ organizations }: { organizations: InventoryOrganization[] }) {
  if (organizations.length === 0) {
    return <EmptyState title="Inventory will appear once agents report" />;
  }
  return (
    <div className="inventory-tree">
      {organizations.map((organization) => (
        <details key={organization.id} open>
          <summary><strong>{organization.name}</strong> <small>{organization.slug}</small></summary>
          <ul>
            {organization.projects.map((project) => (
              <li key={project.id}>
                <strong>{project.name}</strong> <small>{project.slug}</small>
                <ul>
                  {project.environments.map((environment) => (
                    <li key={environment.id}>
                      <small>{environment.name}</small>: {environment.apps.map((app) => app.slug).join(", ") || "no apps"}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </details>
      ))}
    </div>
  );
}

function UserAccessManager({ currentUser, scope }: { currentUser?: HubUser; scope: ApiScope }) {
  const [users, setUsers] = useState<HubUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [savingID, setSavingID] = useState("");
  const [error, setError] = useState("");
  const [enrollment, setEnrollment] = useState<{ enrollment: HubUserTOTPEnrollment; user: HubUser } | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [verifyMessage, setVerifyMessage] = useState("");
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
  }, [canManage, scope.baseUrl, scope.org, scope.project, scope.environment, scope.app]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSavingID("new");
    setError("");
    try {
      const created = await createHubUser(scope, form);
      setUsers((current) => upsertUser(current, created));
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

  async function startEnroll(user: HubUser) {
    setSavingID(user.id);
    setError("");
    setVerifyMessage("");
    setVerifyCode("");
    try {
      const result = await startHubUserTOTP(scope, user);
      setEnrollment(result);
      setUsers((current) => upsertUser(current, result.user));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSavingID("");
    }
  }

  async function finishEnroll() {
    if (!enrollment) {
      return;
    }
    setSavingID(enrollment.user.id);
    setError("");
    try {
      const verified = await verifyHubUserTOTP(scope, enrollment.user, verifyCode);
      setUsers((current) => upsertUser(current, verified));
      setEnrollment(null);
      setVerifyCode("");
      setVerifyMessage(`2FA is now active for ${verified.email}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSavingID("");
    }
  }

  async function disableEnroll(user: HubUser) {
    if (!window.confirm(`Disable 2FA for ${user.email}? They will be blocked from dashboard access until they re-enroll.`)) {
      return;
    }
    setSavingID(user.id);
    setError("");
    try {
      const disabled = await disableHubUserTOTP(scope, user);
      setUsers((current) => upsertUser(current, disabled));
      setVerifyMessage(`2FA disabled for ${disabled.email}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setSavingID("");
    }
  }

  if (!canManage) {
    return <Panel title="Users" icon={Users}><EmptyState title="Admin access required" /></Panel>;
  }

  return (
    <div className="page-stack">
      <Panel title="Add user" icon={UserPlus}>
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
          <label className="check-row"><input checked readOnly type="checkbox" />Require 2FA</label>
          <button className="primary-button" type="submit" disabled={savingID === "new"}>{savingID === "new" ? <Loader2 size={15} className="spin" /> : <UserPlus size={15} />} Add</button>
        </form>
      </Panel>

      <Panel title="Users" icon={ShieldCheck}>
        {error && <InlineAlert message={error} />}
        {verifyMessage && <InlineSuccess message={verifyMessage} />}
        {loading ? <LoadingBlock /> : (
          <ResponsiveTable>
            <thead>
              <tr><th>User</th><th>Access</th><th>Status</th><th>2FA</th><th>Last sign-in</th><th /></tr>
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
                  <td>
                    {user.two_factor_enabled
                      ? <StatusPill value="enabled" />
                      : user.two_factor_pending
                        ? <StatusPill value="pending" />
                        : user.two_factor_required
                          ? <StatusPill value="required" />
                          : <StatusPill value="optional" />}
                    {user.pending_totp_started_at && <small>Started {formatRelative(user.pending_totp_started_at)}</small>}
                    {user.totp_enrolled_at && <small>Enrolled {formatDate(user.totp_enrolled_at)}</small>}
                  </td>
                  <td><small>{user.last_login_at ? formatDate(user.last_login_at) : "never"}</small></td>
                  <td>
                    <div className="inline-row-actions">
                      <button
                        className="ghost-button compact"
                        type="button"
                        disabled={savingID === user.id}
                        onClick={() => void startEnroll(user)}
                      >
                        <QrCode size={14} />
                        {user.two_factor_enabled ? "Re-enroll" : "Enroll"}
                      </button>
                      {(user.two_factor_enabled || user.two_factor_pending) && (
                        <button
                          className="ghost-button compact"
                          type="button"
                          disabled={savingID === user.id}
                          onClick={() => void disableEnroll(user)}
                        >
                          <ShieldOff size={14} />
                          Disable
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr><td colSpan={6}><EmptyState title="No users yet" /></td></tr>
              )}
            </tbody>
          </ResponsiveTable>
        )}
        {enrollment && (
          <div className="totp-box">
            <strong>{enrollment.user.email}</strong>
            <p>Scan the QR code in an authenticator app, then enter the 6-digit code to activate 2FA.</p>
            <img src={enrollment.enrollment.qr_code_data_url} alt="2FA QR code" />
            <details>
              <summary>Cannot scan? Show secret</summary>
              <code>{enrollment.enrollment.secret}</code>
              <small>{enrollment.enrollment.otpauth_url}</small>
            </details>
            <div className="totp-verify">
              <TextInput label="Verification code" value={verifyCode} onChange={setVerifyCode} placeholder="123456" />
              <div className="button-row">
                <button
                  className="primary-button"
                  type="button"
                  disabled={savingID !== "" || verifyCode.trim().length < 6}
                  onClick={() => void finishEnroll()}
                >
                  {savingID !== "" ? <Loader2 size={15} className="spin" /> : <ShieldCheck size={15} />}
                  Verify and activate
                </button>
                <button
                  className="ghost-button"
                  type="button"
                  onClick={() => { setEnrollment(null); setVerifyCode(""); }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
