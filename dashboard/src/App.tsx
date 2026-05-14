import {
  Activity,
  AlertTriangle,
  Bell,
  Boxes,
  Bug,
  Building2,
  Calendar,
  CheckCircle2,
  Clock3,
  Code2,
  Columns3,
  DatabaseZap,
  Download,
  Eye,
  FileText,
  Filter,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  Layers3,
  ListChecks,
  Loader2,
  MonitorCog,
  MoreHorizontal,
  RefreshCw,
  Save,
  ScrollText,
  Search,
  Server,
  Settings,
  ShieldCheck,
  ShieldHalf,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  UserPlus,
  UserCircle,
  XCircle
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis
} from "recharts";
import {
  allowBrowserScriptFromFinding,
  createHubUser,
  createBrowserScriptAllowlistEntry,
  defaultScope,
  enrollHubUserTOTP,
  loadAuthMe,
  loadDashboard,
  loadEstateDashboard,
  loadHubUsers,
  loadScope,
  loginHubUser,
  logoutHubUser,
  MFARequiredError,
  saveScope,
  updateHubUser,
  updateFindingStatus
} from "./api";
import {
  buildEstateModel,
  instanceScopeKey,
  type CompanyModel,
  type EstateModel,
  type InstanceModel
} from "./estate";
import type {
  Agent,
  ApiScope,
  BrowserAllowlistEntry,
  BrowserScript,
  CoverageRecord,
  DashboardData,
  Deployment,
  Host,
  HubAuthMe,
  HubFinding,
  HubUser,
  HubUserTOTPEnrollment,
  InventoryEnvironment,
  InventoryOrganization,
  InventoryProject,
  MonitoredApp,
  ModelAnalysisReport,
  RuleDefinition,
  Service,
  TimelineEvent
} from "./types";

type ViewKey =
  | "overview"
  | "companies"
  | "company"
  | "site"
  | "instance"
  | "findings"
  | "timeline"
  | "inventory"
  | "coverage"
  | "agents"
  | "browser"
  | "deployments"
  | "reports"
  | "settings";

type ActionState = {
  actor: string;
  reason: string;
  note: string;
};

type BreadcrumbItem = {
  label: string;
  view?: ViewKey;
};

type FindingFilters = {
  query: string;
  severity: string;
  status: string;
};

type DashboardFilters = {
  platform: string;
  status: string;
};

type PlatformFilterOption = {
  count: number;
  label: string;
  value: string;
};

const emptyDashboard: DashboardData = {
  health: { data: null },
  findings: { data: [] },
  timeline: { data: [] },
  coverage: { data: [] },
  scopes: { data: [] },
  topology: { data: { counts: {}, apps: [], services: [], hosts: [], agents: [] } },
  deployments: { data: [] },
  browserScripts: { data: [] },
  allowlist: { data: [] },
  reports: { data: [] },
  rules: { data: [] }
};

const navItems: Array<{ key: ViewKey; label: string; icon: typeof LayoutDashboard }> = [
  { key: "overview", label: "Overview", icon: LayoutDashboard },
  { key: "companies", label: "Companies", icon: Boxes },
  { key: "instance", label: "Instance", icon: MonitorCog },
  { key: "findings", label: "Findings", icon: AlertTriangle },
  { key: "timeline", label: "Timeline", icon: Clock3 },
  { key: "coverage", label: "Coverage", icon: ListChecks },
  { key: "agents", label: "Agents", icon: TerminalSquare },
  { key: "browser", label: "Browser Scripts", icon: Bug },
  { key: "deployments", label: "Deployments", icon: GitBranch },
  { key: "reports", label: "Reports", icon: FileText },
  { key: "settings", label: "Settings", icon: Settings }
];

const viewKeys = new Set<ViewKey>([...navItems.map((item) => item.key), "company", "site", "inventory"]);
const basePath = import.meta.env.BASE_URL.replace(/\/$/, "") || "/dashboard";
const autoRefreshIntervalMs = 30_000;

const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const statusColors: Record<string, string> = {
  healthy: "#16a34a",
  warning: "#f59e0b",
  critical: "#dc2626",
  stale: "#64748b",
  unknown: "#94a3b8"
};

const severityColors: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#2563eb",
  info: "#64748b"
};

export default function App() {
  const [scope, setScope] = useState<ApiScope>(() => loadScope());
  const [draftScope, setDraftScope] = useState<ApiScope>(scope);
  const [auth, setAuth] = useState<HubAuthMe | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authError, setAuthError] = useState("");
  const [data, setData] = useState<DashboardData>(emptyDashboard);
  const [estate, setEstate] = useState<EstateModel>(() => buildEstateModel([]));
  const [selectedView, setSelectedView] = useState<ViewKey>(() => viewFromLocation());
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [lastLoadedAt, setLastLoadedAt] = useState<Date | null>(null);
  const [actionState, setActionState] = useState<ActionState>(() => loadActionDefaults());
  const [actionError, setActionError] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const [findingFilters, setFindingFilters] = useState<FindingFilters>({
    query: "",
    severity: "all",
    status: "all"
  });
  const [dashboardFilters, setDashboardFilters] = useState<DashboardFilters>({
    platform: "all",
    status: "all"
  });
  const refreshToken = useRef(0);

  async function refreshAuth(activeScope = scope) {
    setAuthLoading(true);
    setAuthError("");
    try {
      const nextAuth = await loadAuthMe(activeScope);
      setAuth(nextAuth);
      return nextAuth;
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : String(error));
      const fallback = { authenticated: false, auth_configured: true, requires_bootstrap: false };
      setAuth(fallback);
      return fallback;
    } finally {
      setAuthLoading(false);
    }
  }

  async function refresh(activeScope = scope) {
    const token = ++refreshToken.current;
    setLoading(true);
    try {
      const nextEstateData = await loadEstateDashboard(activeScope);
      const nextEstate = buildEstateModel(nextEstateData.instances);
      const activeInstance =
        nextEstate.instances.find((instance) => instanceScopeKey(instance.scope) === instanceScopeKey(activeScope)) ??
        nextEstate.instances[0];
      const nextData = activeInstance?.data ?? await loadDashboard(activeScope);
      if (token === refreshToken.current) {
        setEstate(nextEstate);
        setData(nextData);
        setLastLoadedAt(new Date());
      }
    } finally {
      if (token === refreshToken.current) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    void refreshAuth(scope);
  }, [scope.baseUrl]);

  useEffect(() => {
    if (authLoading || !auth?.authenticated) {
      return;
    }
    void refresh(scope);
    const interval = window.setInterval(() => void refresh(scope), autoRefreshIntervalMs);
    return () => window.clearInterval(interval);
  }, [auth?.authenticated, authLoading, scope]);

  useEffect(() => {
    const handlePopState = () => setSelectedView(viewFromLocation());
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    saveActionDefaults(actionState);
  }, [actionState]);

  useEffect(() => {
    if (!selectedFindingId && data.findings.data.length > 0) {
      setSelectedFindingId(data.findings.data[0].id);
    }
  }, [data.findings.data, selectedFindingId]);

  const sortedFindings = useMemo(() => {
    return [...data.findings.data].sort((left, right) => {
      const severityDiff = (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0);
      if (severityDiff !== 0) {
        return severityDiff;
      }
      return new Date(right.last_event_at).getTime() - new Date(left.last_event_at).getTime();
    });
  }, [data.findings.data]);

  const filteredFindings = useMemo(() => filterFindings(sortedFindings, findingFilters), [findingFilters, sortedFindings]);
  const selectedFinding = filteredFindings.find((finding) => finding.id === selectedFindingId) ?? filteredFindings[0];
  const summary = summarize(data);
  const ruleById = useMemo(() => new Map(data.rules.data.map((rule) => [rule.id, rule])), [data.rules.data]);
  const filteredEstate = useMemo(() => filterEstate(estate, dashboardFilters), [dashboardFilters, estate]);
  const platformOptions = useMemo(() => platformFilterOptions(estate.instances), [estate.instances]);
  const estateErrors = useMemo(() => collectEstateErrors(estate.instances), [estate.instances]);
  const hasGlobalEndpointErrors = hasEndpointErrors(data) || estateErrors.length > 0;
  const activeFilterCount = Number(dashboardFilters.platform !== "all") + Number(dashboardFilters.status !== "all");
  const selectedCompany = useMemo(() => {
    return estate.companies.find((company) => company.companySlug === scope.org) ?? estate.companies[0];
  }, [estate.companies, scope.org]);
  const selectedCompanyForView = useMemo(() => {
    return filteredEstate.companies.find((company) => company.companySlug === scope.org) ?? selectedCompany;
  }, [filteredEstate.companies, scope.org, selectedCompany]);
  const selectedInstance = useMemo(() => {
    return estate.instances.find((instance) => instanceScopeKey(instance.scope) === instanceScopeKey(scope)) ??
      selectedCompany?.instances[0] ??
      estate.instances[0];
  }, [estate.instances, scope, selectedCompany]);
  const selectedSiteInstances = useMemo(() => {
    const companySlug = selectedInstance?.companySlug ?? selectedCompany?.companySlug ?? scope.org;
    const projectSlug = selectedInstance?.projectSlug ?? scope.project;
    const instances = estate.instances.filter((instance) =>
      instance.companySlug === companySlug && instance.projectSlug === projectSlug
    );
    if (instances.length > 0) {
      return instances;
    }
    return selectedInstance ? [selectedInstance] : [];
  }, [estate.instances, scope.project, scope.org, selectedCompany, selectedInstance]);

  function applyScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalized = {
      ...draftScope,
      baseUrl: draftScope.baseUrl.trim().replace(/\/+$/, "")
    };
    setScope(normalized);
    saveScope(normalized);
  }

  function selectInventoryScope(nextScope: ApiScope) {
    const normalized = {
      ...nextScope,
      baseUrl: nextScope.baseUrl.trim().replace(/\/+$/, "")
    };
    setDraftScope(normalized);
    setScope(normalized);
    saveScope(normalized);
    const instance = estate.instances.find((item) => instanceScopeKey(item.scope) === instanceScopeKey(normalized));
    if (instance) {
      setData(instance.data);
    }
  }

  function selectView(view: ViewKey) {
    setSelectedView(view);
    const nextPath = viewPath(view);
    if (window.location.pathname !== nextPath) {
      window.history.pushState({}, "", nextPath);
    }
  }

  function openCompany(company: CompanyModel) {
    const firstInstance = company.instances[0];
    if (firstInstance) {
      selectInventoryScope(firstInstance.scope);
    }
    selectView("company");
  }

  function openSite(instance: InstanceModel) {
    selectInventoryScope(instance.scope);
    selectView("site");
  }

  function openInstance(instance: InstanceModel) {
    selectInventoryScope(instance.scope);
    selectView("instance");
  }

  function openFinding(findingID: string, instance?: InstanceModel) {
    if (instance) {
      selectInventoryScope(instance.scope);
    }
    setSelectedFindingId(findingID);
    selectView("findings");
  }

  async function setFindingStatus(finding: HubFinding, status: string) {
    setActionError("");
    setActionLoading(true);
    try {
      await updateFindingStatus(scope, finding, status, actionState.actor, actionState.reason, actionState.note);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setActionLoading(false);
    }
  }

  async function allowScript(finding: HubFinding) {
    setActionError("");
    setActionLoading(true);
    try {
      await allowBrowserScriptFromFinding(scope, finding, actionState.actor, actionState.reason);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setActionLoading(false);
    }
  }

  async function handleAuthenticated() {
    const nextAuth = await refreshAuth(scope);
    if (nextAuth.authenticated) {
      await refresh(scope);
    }
  }

  async function signOut() {
    setAuthError("");
    try {
      await logoutHubUser(scope);
      setData(emptyDashboard);
      setEstate(buildEstateModel([]));
      await refreshAuth(scope);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : String(error));
    }
  }

  if (authLoading || !auth?.authenticated) {
    return (
      <AuthGate
        auth={auth}
        error={authError}
        loading={authLoading}
        onAuthenticated={handleAuthenticated}
        scope={scope}
      />
    );
  }

  const activeNavKey = selectedView === "company" || selectedView === "site" ? "companies" : selectedView;
  const ActiveIcon = navItems.find((item) => item.key === activeNavKey)?.icon ?? LayoutDashboard;
  const pageTitle = pageTitleForView(selectedView, selectedCompanyForView, selectedInstance);
  const pageEyebrow = pageEyebrowForView(selectedView, scope, selectedCompanyForView, selectedInstance);

  return (
    <div className="dashboard-shell">
      <aside className="sidebar">
        <a className="brand" href="/dashboard/" aria-label="Aegrail dashboard">
          <img src={`${import.meta.env.BASE_URL}aegrail-horizontal-white.svg`} alt="Aegrail" />
        </a>
        <nav className="nav-list" aria-label="Dashboard views">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={`nav-item ${activeNavKey === item.key ? "active" : ""}`}
                key={item.key}
                onClick={() => selectView(item.key)}
                type="button"
                title={item.label}
              >
                <Icon size={18} aria-hidden="true" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <button className="sidebar-collapse" type="button" title="Collapse sidebar">
          <MoreHorizontal size={18} aria-hidden="true" />
          <span>Collapse</span>
        </button>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="topbar-title">
            <p className="eyebrow">{pageEyebrow}</p>
            <h1>
              <ActiveIcon size={24} aria-hidden="true" />
              {pageTitle}
            </h1>
            <Breadcrumbs
              items={breadcrumbItemsForView(selectedView, selectedCompanyForView, selectedInstance)}
              onView={selectView}
            />
          </div>
          <div className="utility-cluster" aria-label="Dashboard utilities">
            <button className={`utility-button alert ${estate.totals.highFindings + estate.totals.criticalFindings > 0 ? "" : "empty"}`} type="button" title="Open high-risk findings" onClick={() => selectView("findings")}>
              <Bell size={18} aria-hidden="true" />
              <span>{estate.totals.highFindings + estate.totals.criticalFindings}</span>
            </button>
            <button className="utility-button" type="button" title="Open settings" onClick={() => selectView("settings")}>
              <Settings size={18} aria-hidden="true" />
            </button>
            <button className="avatar-button" type="button" title="Sign out" onClick={() => void signOut()}>
              <UserCircle size={18} aria-hidden="true" />
              <span>{userInitials(auth.user)}</span>
            </button>
          </div>
        </header>

        <div className="filter-strip">
          <ScopeSwitcher
            loading={loading}
            organizations={data.scopes.data}
            scope={scope}
            onSelect={selectInventoryScope}
          />
          <select
            className="form-select filter-select"
            aria-label="Platform filter"
            value={dashboardFilters.platform}
            onChange={(event) => setDashboardFilters((current) => ({ ...current, platform: event.target.value }))}
          >
            <option value="all">All Platforms</option>
            {platformOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label} ({option.count})
              </option>
            ))}
          </select>
          <select
            className="form-select filter-select"
            aria-label="Status filter"
            value={dashboardFilters.status}
            onChange={(event) => setDashboardFilters((current) => ({ ...current, status: event.target.value }))}
          >
            <option value="all">All Statuses</option>
            <option value="healthy">Healthy</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
          <button className="btn btn-primary filter-button" type="button" onClick={() => setDashboardFilters({ platform: "all", status: "all" })}>
            <SlidersHorizontal size={16} aria-hidden="true" />
            {activeFilterCount > 0 ? `Clear Filters (${activeFilterCount})` : "Filters"}
          </button>
          <div className="topbar-actions">
            <span className="time-range-pill" title={lastLoadedAt ? `Last refresh ${formatDate(lastLoadedAt.toISOString())}` : "No refresh yet"}>
              <Calendar size={16} aria-hidden="true" />
              24h / {lastLoadedAt ? formatRelative(lastLoadedAt.toISOString()) : "not loaded"}
            </span>
            <span className={`api-state ${loading ? "loading" : !data.health.data ? "offline" : hasGlobalEndpointErrors ? "warn" : "ok"}`}>
              {loading ? <Loader2 size={16} className="spin" /> : !data.health.data ? <XCircle size={16} /> : hasGlobalEndpointErrors ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
              {loading ? "Loading" : !data.health.data ? "Offline" : hasGlobalEndpointErrors ? "Partial" : "Live"}
            </span>
            <button className="icon-button" type="button" disabled={loading} onClick={() => void refresh()} title="Refresh dashboard">
              {loading ? <Loader2 size={18} className="spin" aria-hidden="true" /> : <RefreshCw size={18} aria-hidden="true" />}
            </button>
          </div>
        </div>

        {activeFilterCount > 0 && (
          <ActiveFilterChips
            filters={dashboardFilters}
            onClear={(filter) => setDashboardFilters((current) => ({ ...current, [filter]: "all" }))}
            onClearAll={() => setDashboardFilters({ platform: "all", status: "all" })}
          />
        )}

        {(hasErrors(data) || estateErrors.length > 0) && <ApiErrors data={data} estateErrors={estateErrors} />}

        {selectedView === "overview" && (
          <OperationsOverview
            estate={filteredEstate}
            ruleById={ruleById}
            lastLoadedAt={lastLoadedAt}
            onCompany={openCompany}
            onFinding={openFinding}
            onView={selectView}
          />
        )}
        {selectedView === "companies" && (
          <CompaniesDirectory
            estate={filteredEstate}
            onCompany={openCompany}
          />
        )}
        {selectedView === "company" && (
          <CompanyPage
            company={selectedCompanyForView}
            onFinding={openFinding}
            onInstance={openInstance}
            onSite={openSite}
            ruleById={ruleById}
          />
        )}
        {selectedView === "site" && (
          <SiteProjectPage
            instances={selectedSiteInstances}
            onFinding={openFinding}
            onInstance={openInstance}
            onOpenBrowser={() => selectView("browser")}
            onOpenCoverage={() => selectView("coverage")}
            onOpenTimeline={() => selectView("timeline")}
            ruleById={ruleById}
          />
        )}
        {selectedView === "instance" && selectedInstance && (
          <InstancePage
            actionError={actionError}
            actionLoading={actionLoading}
            instance={selectedInstance}
            onAllowScript={allowScript}
            onFinding={(id) => openFinding(id, selectedInstance)}
            onStatus={setFindingStatus}
            ruleById={ruleById}
          />
        )}
        {selectedView === "findings" && (
          <IncidentInbox
            actionError={actionError}
            actionLoading={actionLoading}
            estate={filteredEstate}
            onAllowScript={allowScript}
            onFinding={openFinding}
            onStatus={setFindingStatus}
            ruleById={ruleById}
          />
        )}
        {selectedView === "timeline" && <ActivityTimelinePage estate={filteredEstate} />}
        {selectedView === "inventory" && <InventoryView data={data} />}
        {selectedView === "coverage" && <CoverageCommandCenter estate={filteredEstate} onInstance={openInstance} />}
        {selectedView === "agents" && <AgentsCollectorHealthPage estate={filteredEstate} />}
        {selectedView === "browser" && (
          <BrowserScriptsPage
            actionState={actionState}
            allowlist={filteredEstate.instances.flatMap((instance) => instance.data.allowlist.data)}
            findings={filteredEstate.instances.flatMap((instance) => instance.data.findings.data)}
            onAllowlistCreated={() => void refresh()}
            scope={scope}
            scripts={filteredEstate.instances.flatMap((instance) => instance.data.browserScripts.data)}
          />
        )}
        {selectedView === "deployments" && <DeploymentsView estate={filteredEstate} />}
        {selectedView === "reports" && <ReportsView estate={filteredEstate} ruleById={ruleById} />}
        {selectedView === "settings" && (
          <SettingsView
            actionState={actionState}
            defaultScope={defaultScope}
            draftScope={draftScope}
            inventoryScopes={data.scopes.data}
            loading={loading}
            onActionChange={setActionState}
            onScopeChange={setDraftScope}
            onScopeSelect={selectInventoryScope}
            onSubmit={applyScope}
            scope={scope}
            user={auth.user}
          />
        )}
      </main>
    </div>
  );
}

function AuthGate({
  auth,
  error,
  loading,
  onAuthenticated,
  scope
}: {
  auth: HubAuthMe | null;
  error: string;
  loading: boolean;
  onAuthenticated: () => Promise<void>;
  scope: ApiScope;
}) {
  const requiresBootstrap = Boolean(auth?.requires_bootstrap);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [mfaRequired, setMFARequired] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setFormError("");
    try {
      if (requiresBootstrap) {
        await createHubUser(scope, {
          access_level: "owner",
          display_name: displayName,
          email,
          password,
          status: "active",
          two_factor_required: true
        });
      }
      await loginHubUser(scope, {
        email,
        password,
        totp_code: totpCode
      });
      setMFARequired(false);
      await onAuthenticated();
    } catch (caught) {
      if (caught instanceof MFARequiredError) {
        setMFARequired(true);
        setFormError("Enter your 2FA code to finish signing in.");
      } else {
        setFormError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-panel">
        <a className="auth-brand" href="/dashboard/" aria-label="Aegrail dashboard">
          <img src={`${import.meta.env.BASE_URL}aegrail-horizontal-white.svg`} alt="Aegrail" />
        </a>
        <div className="auth-card">
          <div className="auth-heading">
            <span className="auth-icon">{requiresBootstrap ? <UserPlus size={22} /> : <KeyRound size={22} />}</span>
            <div>
              <p className="eyebrow">{requiresBootstrap ? "First user setup" : "Protected dashboard"}</p>
              <h1>{requiresBootstrap ? "Create owner access" : "Sign in"}</h1>
            </div>
          </div>
          <form className="auth-form" onSubmit={submit}>
            {requiresBootstrap && (
              <TextInput
                label="Name"
                value={displayName}
                placeholder="Display name"
                onChange={setDisplayName}
              />
            )}
            <TextInput
              label="Email"
              value={email}
              placeholder="person@example.com"
              onChange={(value) => {
                setEmail(value);
                setMFARequired(false);
              }}
            />
            <label className="form-label" htmlFor="hub-password">Password</label>
            <input
              autoComplete={requiresBootstrap ? "new-password" : "current-password"}
              className="form-control"
              id="hub-password"
              minLength={12}
              required
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                setMFARequired(false);
              }}
            />
            {(mfaRequired || !requiresBootstrap) && (
              <>
                <label className="form-label" htmlFor="hub-totp">2FA code</label>
                <input
                  autoComplete="one-time-code"
                  className="form-control"
                  id="hub-totp"
                  inputMode="numeric"
                  maxLength={8}
                  placeholder={mfaRequired ? "123456" : "Optional until 2FA is enabled"}
                  type="text"
                  value={totpCode}
                  onChange={(event) => setTotpCode(event.target.value)}
                />
              </>
            )}
            {(error || formError) && (
              <div className="alert alert-warning compact-alert" role="status">
                <AlertTriangle size={16} />
                {formError || error}
              </div>
            )}
            <button className="btn btn-primary auth-submit" type="submit" disabled={loading || submitting}>
              {loading || submitting ? <Loader2 size={16} className="spin" /> : <ShieldCheck size={16} aria-hidden="true" />}
              {requiresBootstrap ? "Create and sign in" : "Sign in"}
            </button>
          </form>
        </div>
      </section>
    </main>
  );
}

type ScopeInstanceChoice = {
  environment: InventoryEnvironment;
  app?: MonitoredApp;
};

type ScopeChoice = {
  app?: MonitoredApp;
  environment: InventoryEnvironment;
  organization: InventoryOrganization;
  project: InventoryProject;
};

function ScopeSwitcher({
  loading,
  onSelect,
  organizations,
  scope
}: {
  loading: boolean;
  onSelect: (scope: ApiScope) => void;
  organizations: InventoryOrganization[];
  scope: ApiScope;
}) {
  const selectedOrganization = organizations.find((organization) => organization.slug === scope.org) ?? organizations[0];
  const projects = selectedOrganization?.projects ?? [];
  const selectedProject = projects.find((project) => project.slug === scope.project) ?? projects[0];
  const instances = selectedProject ? scopeInstances(selectedProject) : [];
  const selectedInstance =
    instances.find(({ app, environment }) => environment.slug === scope.environment && (app?.slug ?? "") === scope.app) ??
    instances[0];

  function selectOrganization(slug: string) {
    const organization = organizations.find((item) => item.slug === slug);
    const project = organization?.projects[0];
    const instance = project ? scopeInstances(project)[0] : undefined;
    if (organization && project && instance) {
      onSelect(scopeFromParts(scope.baseUrl, organization, project, instance));
    }
  }

  function selectProject(slug: string) {
    const project = projects.find((item) => item.slug === slug);
    const instance = project ? scopeInstances(project)[0] : undefined;
    if (selectedOrganization && project && instance) {
      onSelect(scopeFromParts(scope.baseUrl, selectedOrganization, project, instance));
    }
  }

  function selectInstance(key: string) {
    const instance = instances.find((item) => scopeInstanceKey(item) === key);
    if (selectedOrganization && selectedProject && instance) {
      onSelect(scopeFromParts(scope.baseUrl, selectedOrganization, selectedProject, instance));
    }
  }

  if (organizations.length === 0) {
    return null;
  }

  return (
    <div className="scope-switcher" aria-label="Dashboard scope">
      <label>
        <span>Company</span>
        <select
          aria-label="Company"
          className="form-select scope-select"
          disabled={loading}
          value={selectedOrganization?.slug ?? ""}
          onChange={(event) => selectOrganization(event.target.value)}
        >
          {organizations.map((organization) => (
            <option key={organization.slug} value={organization.slug}>
              {organization.name || organization.slug}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Site</span>
        <select
          aria-label="Site"
          className="form-select scope-select"
          disabled={loading || projects.length === 0}
          value={selectedProject?.slug ?? ""}
          onChange={(event) => selectProject(event.target.value)}
        >
          {projects.map((project) => (
            <option key={project.slug} value={project.slug}>
              {project.name || project.slug}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Instance</span>
        <select
          aria-label="Instance"
          className="form-select scope-select"
          disabled={loading || instances.length === 0}
          value={selectedInstance ? scopeInstanceKey(selectedInstance) : ""}
          onChange={(event) => selectInstance(event.target.value)}
        >
          {instances.map((instance) => (
            <option key={scopeInstanceKey(instance)} value={scopeInstanceKey(instance)}>
              {scopeInstanceLabel(instance)}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

function scopeInstances(project: InventoryProject): ScopeInstanceChoice[] {
  return project.environments.flatMap((environment) => {
    if (environment.apps.length === 0) {
      return [{ environment }];
    }
    return environment.apps.map((app) => ({ environment, app }));
  });
}

function scopeFromParts(
  baseUrl: string,
  organization: InventoryOrganization,
  project: InventoryProject,
  instance: ScopeInstanceChoice
): ApiScope {
  return {
    app: instance.app?.slug ?? "",
    baseUrl,
    environment: instance.environment.slug,
    org: organization.slug,
    project: project.slug
  };
}

function scopeInstanceKey(instance: ScopeInstanceChoice) {
  return `${instance.environment.slug}:${instance.app?.slug ?? ""}`;
}

function scopeInstanceLabel(instance: ScopeInstanceChoice) {
  const appLabel = instance.app?.name || instance.app?.slug || "All apps";
  const kind = instance.app?.kind ? ` / ${appKindLabel(instance.app.kind)}` : "";
  return `${instance.environment.name || instance.environment.slug} / ${appLabel}${kind}`;
}

function appKindLabel(kind: string) {
  switch (kind) {
    case "wordpress-multisite":
      return "WordPress Network";
    case "wordpress":
      return "WordPress";
    case "prestashop":
      return "PrestaShop";
    default:
      return kind;
  }
}

function platformLabel(kind: string) {
  return appKindLabel(kind);
}

function statusLabel(status: string) {
  if (status === "all") {
    return "All statuses";
  }
  return titleCase(status.replace(/[_-]/g, " "));
}

function titleCase(value: string) {
  return value
    .split(" ")
    .filter(Boolean)
    .map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}

type FindingWithInstance = {
  finding: HubFinding;
  instance: InstanceModel;
};

type SiteGroup = {
  companySlug: string;
  iconUrls: string[];
  instances: InstanceModel[];
  openFindings: number;
  platforms: string[];
  projectName: string;
  projectSlug: string;
};

function OperationsOverview({
  estate,
  lastLoadedAt,
  onCompany,
  onFinding,
  onView,
  ruleById
}: {
  estate: EstateModel;
  lastLoadedAt: Date | null;
  onCompany: (company: CompanyModel) => void;
  onFinding: (id: string, instance?: InstanceModel) => void;
  onView: (view: ViewKey) => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  const attention = priorityFindings(estate.instances).slice(0, 5);
  const recentFindings = priorityFindings(estate.instances).slice(0, 6);
  const estateStatus = estate.companies.some((company) => company.status === "critical")
    ? "critical"
    : estate.companies.some((company) => company.status === "warning")
      ? "warning"
      : "healthy";
  const coveragePercent = estateCoveragePercent(estate);

  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip">
        <KpiCard icon={Building2} label="Monitored Companies" value={estate.totals.companies} tone="blue" trend="0% vs yesterday" />
        <KpiCard icon={Layers3} label="Sites" value={estate.totals.sites} tone="blue" trend="derived from scopes" />
        <KpiCard icon={Server} label="Instances" value={estate.totals.instances} tone="purple" trend="derived from apps" />
        <KpiCard icon={AlertTriangle} label="Open Critical Findings" value={estate.totals.criticalFindings} tone="red" trend="live grouped count" />
        <KpiCard icon={ShieldHalf} label="Open High Findings" value={estate.totals.highFindings} tone="orange" trend="live grouped count" />
        <KpiCard icon={TerminalSquare} label="Stale Agents" value={estate.totals.staleAgents} tone="gray" trend="fresh signal aware" />
      </section>

      <section className="operations-grid">
        <div className="operations-main">
          <section className="panel spec-panel">
            <PanelTitle icon={AlertTriangle} title="Needs attention" action="View all findings" onAction={() => recentFindings[0] && onFinding(recentFindings[0].finding.id, recentFindings[0].instance)} />
            <AttentionList items={attention} onFinding={onFinding} ruleById={ruleById} />
            <div className="panel-foot">{attention.length} total item{attention.length === 1 ? "" : "s"}</div>
          </section>

          <section className="section-block">
            <div className="section-heading-row">
              <h2>Companies</h2>
              <button className="btn btn-outline-secondary" type="button" onClick={() => onView("companies")}>Open Directory</button>
            </div>
            <div className="company-grid" aria-label="Companies">
              {estate.companies.map((company) => (
                <CompanyCard company={company} key={company.companySlug} onOpen={onCompany} />
              ))}
            </div>
          </section>
        </div>

        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={AlertTriangle} title="Recent findings" />
            <AttentionList items={recentFindings.slice(0, 5)} onFinding={onFinding} ruleById={ruleById} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={ListChecks} title="Coverage summary" />
            <DonutChart
              centerLabel="Overall coverage"
              centerValue={`${coveragePercent}%`}
              data={statusChartData(estate.instances)}
            />
            <LegendList data={statusChartData(estate.instances)} />
            <div className="summary-row">
              <span>Total instances</span>
              <strong>{estate.totals.instances}</strong>
            </div>
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Activity} title="Console status" />
            <div className="trust-grid">
              <InfoTile label="Estate state" value={estateStatus} tone={estateStatus === "critical" ? "danger" : estateStatus === "warning" ? "warning" : "ok"} />
              <InfoTile label="Active agents" value={String(estate.totals.activeAgents)} tone="ok" />
              <InfoTile label="Open issues" value={String(estate.totals.openFindings)} tone={estate.totals.openFindings > 0 ? "warning" : "ok"} />
              <InfoTile label="Last refresh" value={lastLoadedAt ? formatRelative(lastLoadedAt.toISOString()) : "not yet"} tone="muted" />
            </div>
          </section>
        </aside>
      </section>
      {estate.companies.length === 0 && (
        <EmptyState icon={Boxes} title="No companies" detail="No inventory scopes were returned by the Hub." />
      )}

      <footer className="dashboard-foot">
        <span>{lastLoadedAt ? `Refreshed ${formatRelative(lastLoadedAt.toISOString())}` : "Not refreshed yet"}</span>
        <span>Auto-refresh every {Math.round(autoRefreshIntervalMs / 1000)}s</span>
        <span>{estate.totals.instances} monitored instance{estate.totals.instances === 1 ? "" : "s"}</span>
      </footer>
    </div>
  );
}

function CompaniesDirectory({ estate, onCompany }: { estate: EstateModel; onCompany: (company: CompanyModel) => void }) {
  const [query, setQuery] = useState("");
  const [sortMode, setSortMode] = useState("health");
  const [view, setView] = useState<"grid" | "list">("grid");
  const normalizedQuery = query.trim().toLowerCase();
  const matchingCompanies = normalizedQuery
    ? estate.companies.filter((company) =>
        [company.companyName, company.companySlug, company.statusReason, platformSummary(company)]
          .some((value) => value.toLowerCase().includes(normalizedQuery))
      )
    : estate.companies;
  const companies = sortCompanies(matchingCompanies, sortMode);
  const healthy = estate.companies.filter((company) => company.status === "healthy").length;
  const warning = estate.companies.filter((company) => company.status === "warning").length;
  const critical = estate.companies.filter((company) => company.status === "critical").length;

  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip five">
        <KpiCard icon={ShieldCheck} label="Healthy Companies" value={healthy} tone="green" trend={`${percentOf(healthy, estate.totals.companies)}% of total`} />
        <KpiCard icon={AlertTriangle} label="Warning Companies" value={warning} tone="orange" trend={`${percentOf(warning, estate.totals.companies)}% of total`} />
        <KpiCard icon={AlertTriangle} label="Critical Companies" value={critical} tone="red" trend={`${percentOf(critical, estate.totals.companies)}% of total`} />
        <KpiCard icon={Building2} label="Total Sites" value={estate.totals.sites} tone="blue" trend="scope inventory" />
        <KpiCard icon={Server} label="Total Instances" value={estate.totals.instances} tone="purple" trend="derived targets" />
      </section>

      <div className="directory-toolbar">
        <div className="segmented-control" aria-label="View mode">
          <button className={view === "grid" ? "active" : ""} type="button" onClick={() => setView("grid")}>Grid</button>
          <button className={view === "list" ? "active" : ""} type="button" onClick={() => setView("list")}>List</button>
        </div>
        <select className="form-select filter-select" value={sortMode} onChange={(event) => setSortMode(event.target.value)} aria-label="Sort companies">
          <option value="health">Overall health</option>
          <option value="risk">Risk score</option>
          <option value="findings">Open findings</option>
          <option value="signal">Last signal</option>
          <option value="name">Company name</option>
        </select>
        <div className="search-field directory-search">
          <Search size={16} aria-hidden="true" />
          <input className="form-control" placeholder="Search companies..." value={query} onChange={(event) => setQuery(event.target.value)} />
        </div>
      </div>

      <section className="operations-grid">
        <div className="operations-main">
          {view === "grid" ? (
            <div className="company-grid directory-grid">
              {companies.map((company) => <CompanyCard company={company} key={company.companySlug} onOpen={onCompany} />)}
            </div>
          ) : (
            <section className="panel table-panel">
              <div className="table-responsive">
                <table className="table align-middle data-table">
                  <thead>
                    <tr>
                      <th>Company</th>
                      <th>Health</th>
                      <th>Risk score</th>
                      <th>Sites</th>
                      <th>Instances</th>
                      <th>Worst issue</th>
                      <th>Last signal</th>
                      <th>Open issues</th>
                    </tr>
                  </thead>
                  <tbody>
                    {companies.map((company) => (
                      <tr key={company.companySlug} onClick={() => onCompany(company)}>
                        <td><AvatarLabel iconUrls={company.iconUrls} name={company.companyName} /><div className="muted-line">{platformSummary(company)}</div></td>
                        <td><HealthBadge status={company.status} /></td>
                        <td>{riskScore(company)}</td>
                        <td>{company.siteCount}</td>
                        <td>{company.instances.length}</td>
                        <td>{company.statusReason}</td>
                        <td>{formatRelative(company.lastSignalAt)}</td>
                        <td>{company.openFindings}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
          {companies.length === 0 && <EmptyState icon={Search} title="No companies match" detail="No monitored companies match the current search." />}
        </div>

        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={ShieldCheck} title="Company health distribution" />
            <DonutChart centerLabel="Total" centerValue={String(estate.totals.companies)} data={companyHealthChartData(estate)} />
            <LegendList data={companyHealthChartData(estate)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={AlertTriangle} title="Top company risks" />
            <RankedCompanyList companies={[...estate.companies].sort((a, b) => riskScore(b) - riskScore(a)).slice(0, 5)} onCompany={onCompany} />
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function CompanyCard({ company, onOpen }: { company: CompanyModel; onOpen: (company: CompanyModel) => void }) {
  const score = riskScore(company);
  return (
    <button className={`company-card ${company.status}`} type="button" onClick={() => onOpen(company)}>
      <div className="company-card-top">
        <AvatarLabel iconUrls={company.iconUrls} name={company.companyName} />
        <span className="company-card-identity">
          <strong>{company.companyName}</strong>
          <small>{platformSummary(company)}</small>
        </span>
        <HealthBadge status={company.status} />
      </div>
      <div className="platform-badges">
        {platformBadges(company).map((platform) => <span key={platform}>{platform}</span>)}
      </div>
      <div className="risk-row">
        <RiskGauge value={score} />
        <span>
          <strong>Risk score</strong>
          <small>{riskBand(score)}</small>
        </span>
      </div>
      <div className="company-card-metrics">
        <InfoTile label="Sites" value={String(company.siteCount)} tone="muted" />
        <InfoTile label="Instances" value={String(company.instances.length)} tone="muted" />
        <InfoTile label="Open" value={String(company.openFindings)} tone={company.openFindings > 0 ? "warning" : "ok"} />
      </div>
      <div className="company-card-issue">
        <span>Worst issue</span>
        <strong>{company.statusReason}</strong>
      </div>
      <div className="company-card-foot">
        <span>Last signal {formatRelative(company.lastSignalAt)}</span>
        <span>View company</span>
      </div>
    </button>
  );
}

function CompanyPage({
  company,
  onFinding,
  onInstance,
  onSite,
  ruleById
}: {
  company?: CompanyModel;
  onFinding: (id: string, instance?: InstanceModel) => void;
  onInstance: (instance: InstanceModel) => void;
  onSite: (instance: InstanceModel) => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  if (!company) {
    return <EmptyState icon={Boxes} title="No company selected" detail="Select a company from the overview." />;
  }

  const attention = priorityFindings(company.instances).slice(0, 4);
  const allFindings = company.instances.flatMap((instance) => instance.data.findings.data);
  const healthScore = Math.max(0, 100 - riskScore(company));

  return (
    <div className="view-stack spec-page">
      <section className={`entity-header company-summary ${company.status}`}>
        <div className="entity-identity">
          <AvatarLabel iconUrls={company.iconUrls} name={company.companyName} />
          <span>
          <p className="eyebrow">Company</p>
          <h2>{company.companyName}</h2>
            <p>{platformSummary(company)} / last signal {formatRelative(company.lastSignalAt)}</p>
          </span>
        </div>
        <div className="summary-metrics">
          <RiskGauge value={100 - healthScore} />
          <InfoTile label="Overall health" value={`${healthScore}%`} tone={company.status === "critical" ? "danger" : company.status === "warning" ? "warning" : "ok"} />
          <InfoTile label="Risk score" value={`${riskScore(company)}/100`} tone={riskScore(company) >= 70 ? "danger" : riskScore(company) >= 35 ? "warning" : "ok"} />
          <InfoTile label="Total sites" value={String(company.siteCount)} tone="muted" />
          <InfoTile label="Platforms" value={String(platformBadges(company).length)} tone="muted" />
          <InfoTile label="Open issues" value={String(company.openFindings)} tone={company.openFindings > 0 ? "warning" : "ok"} />
        </div>
      </section>

      <section className="company-detail-grid">
        <div className="panel">
          <PanelTitle icon={AlertTriangle} title="Needs Attention" />
          <AttentionList items={attention} onFinding={onFinding} ruleById={ruleById} />
        </div>
        <div className="panel">
          <PanelTitle icon={MonitorCog} title="Sites and instances" />
          <CompactSiteList instances={company.instances} onSite={onSite} />
        </div>
        <div className="panel">
          <PanelTitle icon={ShieldHalf} title="Top risks" />
          <AttentionList items={priorityFindings(company.instances).slice(0, 5)} onFinding={onFinding} ruleById={ruleById} />
        </div>
      </section>

      <section className="panel table-panel">
        <div className="table-toolbar">
          <PanelHeading icon={MonitorCog} title="Sites And Instances" />
          <span className="count-pill">{company.instances.length}</span>
        </div>
        <div className="table-responsive">
          <table className="table align-middle data-table instance-table">
            <thead>
              <tr>
                <th>Site</th>
                <th>Type</th>
                <th>Instance</th>
                <th>Health</th>
                <th>Collectors</th>
                <th>Last signal</th>
                <th>Open</th>
              </tr>
            </thead>
            <tbody>
              {company.instances.map((instance) => (
                <tr key={instance.key} onClick={() => onInstance(instance)}>
                  <td>
                    <button className="table-link" type="button" onClick={(event) => {
                      event.stopPropagation();
                      onSite(instance);
                    }}>
                      {instance.projectName}
                    </button>
                    <div className="muted-line">{instance.projectSlug}</div>
                  </td>
                  <td>{appKindLabel(instance.appKind)}</td>
                  <td>{instance.environmentName}<div className="muted-line">{instance.appName}</div></td>
                  <td><HealthBadge status={instance.status} /></td>
                  <td><CollectorPills collectors={instance.collectors} /></td>
                  <td>{formatRelative(instance.lastSignalAt)}</td>
                  <td>{instance.openFindings}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="content-grid three">
        <div className="panel">
          <PanelTitle icon={GitBranch} title="Recent deployments" />
          <DeploymentList deployments={company.instances.flatMap((instance) => instance.data.deployments.data).slice(0, 5)} />
        </div>
        <div className="panel">
          <PanelTitle icon={AlertTriangle} title="Recent findings" />
          <FindingList findings={allFindings.slice(0, 5)} ruleById={ruleById} onSelect={(id) => onFinding(id)} />
        </div>
        <div className="panel">
          <PanelTitle icon={Activity} title="Timeline snapshot" />
          <EventList events={company.instances.flatMap((instance) => instance.data.timeline.data).sort(sortEventsNewest).slice(0, 6)} />
        </div>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function SiteProjectPage({
  instances,
  onFinding,
  onInstance,
  onOpenBrowser,
  onOpenCoverage,
  onOpenTimeline,
  ruleById
}: {
  instances: InstanceModel[];
  onFinding: (id: string, instance?: InstanceModel) => void;
  onInstance: (instance: InstanceModel) => void;
  onOpenBrowser: () => void;
  onOpenCoverage: () => void;
  onOpenTimeline: () => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  if (instances.length === 0) {
    return <EmptyState icon={MonitorCog} title="No site selected" detail="Select a company site from the company page." />;
  }

  const primary = instances[0];
  const status = worstStatus(instances);
  const allFindings = instances.flatMap((instance) => instance.data.findings.data);
  const openFindings = allFindings.filter((finding) => finding.status === "open");
  const allEvents = instances.flatMap((instance) => instance.data.timeline.data).sort(sortEventsNewest);
  const deployments = instances.flatMap((instance) => instance.data.deployments.data).sort(sortDeploymentsNewest);
  const scripts = instances.flatMap((instance) => instance.data.browserScripts.data);
  const lastCrawl = newestISO(instances.flatMap((instance) =>
    instance.collectors.filter((collector) => collector.key === "browser").map((collector) => collector.lastSeenAt)
  ));
  const lastDbScan = newestISO(instances.flatMap((instance) =>
    instance.collectors.filter((collector) => collector.key === "database").map((collector) => collector.lastSeenAt)
  ));
  const platforms = Array.from(new Set(instances.map((instance) => appKindLabel(instance.appKind)))).join(", ") || "Web application";
  const environments = Array.from(new Set(instances.map((instance) => instance.environmentName))).join(", ") || "Unknown";

  return (
    <div className="view-stack spec-page">
      <section className={`entity-header site-header ${status}`}>
        <div className="entity-identity">
          <AvatarLabel iconUrls={siteGroupIconCandidates(instances)} name={primary.projectName} />
          <span>
            <p className="eyebrow">{primary.companyName} / Site or project</p>
            <h2>{primary.projectName}</h2>
            <p>{platforms} / {instances.length} monitored instance{instances.length === 1 ? "" : "s"}</p>
          </span>
          <HealthBadge status={status} />
        </div>
        <div className="summary-metrics compact">
          <InfoTile label="Type" value="Web Application" tone="muted" />
          <InfoTile label="Environment" value={environments} tone="muted" />
          <InfoTile label="Platforms" value={platforms} tone="muted" />
          <InfoTile label="Total instances" value={String(instances.length)} tone="muted" />
          <InfoTile label="Last crawl" value={formatRelative(lastCrawl)} tone={lastCrawl ? "ok" : "warning"} />
          <InfoTile label="Last DB scan" value={formatRelative(lastDbScan)} tone={lastDbScan ? "ok" : "warning"} />
          <InfoTile label="Open findings" value={String(openFindings.length)} tone={openFindings.length > 0 ? "warning" : "ok"} />
        </div>
      </section>

      <section className="operations-grid">
        <div className="operations-main">
          <section className="panel table-panel">
            <div className="table-toolbar">
              <div>
                <PanelHeading icon={Server} title="Instances" />
                <p className="panel-subtitle">{instances.length} environment/app target{instances.length === 1 ? "" : "s"} under this site</p>
              </div>
              <span className="count-pill">{instances.length}</span>
            </div>
            <div className="table-responsive">
              <table className="table align-middle data-table coverage-table">
                <thead>
                  <tr>
                    <th>Instance</th>
                    <th>Files</th>
                    <th>Database</th>
                    <th>Browser</th>
                    <th>Config</th>
                    <th>Agent Status</th>
                    <th>Open Findings</th>
                    <th>Last Signal</th>
                  </tr>
                </thead>
                <tbody>
                  {instances.map((instance) => {
                    const collectors = new Map(instance.collectors.map((collector) => [collector.key, collector]));
                    return (
                      <tr key={instance.key} onClick={() => onInstance(instance)}>
                        <td>
                          <button className="table-link" type="button" onClick={(event) => {
                            event.stopPropagation();
                            onInstance(instance);
                          }}>
                            {instance.environmentName}
                          </button>
                          <div className="muted-line">{instance.appName} / {appKindLabel(instance.appKind)}</div>
                        </td>
                        <td><CollectorBadge collector={collectors.get("files")} /></td>
                        <td><CollectorBadge collector={collectors.get("database")} /></td>
                        <td><CollectorBadge collector={collectors.get("browser")} /></td>
                        <td><CollectorBadge collector={collectors.get("config")} /></td>
                        <td><HealthBadge status={instance.status} /><div className="muted-line">{instance.activeAgentCount}/{instance.agentCount} active</div></td>
                        <td>{instance.openFindings}</td>
                        <td>{formatRelative(instance.lastSignalAt)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={ShieldCheck} title="Site health" action="View details" onAction={onOpenCoverage} />
            <DonutChart centerLabel="Healthy" centerValue={`${Math.max(0, 100 - siteRiskScore(instances))}%`} data={statusChartData(instances)} />
            <LegendList data={statusChartData(instances)} />
            <dl className="detail-list compact">
              <div><dt>Total checks</dt><dd>{instances.length * 4}</dd></div>
            </dl>
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Activity} title="Recent changes" action="View all" onAction={onOpenTimeline} />
            <SiteChangeList deployments={deployments} events={allEvents} findings={priorityFindings(instances)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={GitBranch} title="Deployment context" />
            <DeploymentContext deployments={deployments} />
          </section>
        </aside>
      </section>

      <section className="content-grid two">
        <div className="panel spec-panel">
          <PanelTitle icon={Bug} title="Browser drift" action="View details" onAction={onOpenBrowser} />
          <DonutChart centerLabel="Instances" centerValue={String(instances.length)} data={browserDriftChartData(instances)} />
          <LegendList data={browserDriftChartData(instances)} />
          <ScriptList scripts={scripts.slice(0, 4)} />
        </div>
        <div className="panel spec-panel">
          <PanelTitle icon={AlertTriangle} title="Findings summary" action="View all findings" onAction={() => openFindings[0] && onFinding(openFindings[0].id, primary)} />
          <div className="severity-mini-grid">
            {severityChartData(openFindings).map((item) => (
              <div className="severity-mini-card" key={item.name}>
                <span style={{ background: item.color }} />
                <strong>{item.value}</strong>
                <small>{item.name}</small>
              </div>
            ))}
          </div>
          <MiniLineChart data={findingsTrendData(openFindings)} stroke="#dc2626" />
          <FindingList findings={openFindings.slice(0, 4)} ruleById={ruleById} onSelect={(id) => onFinding(id, primary)} />
        </div>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function InstancePage({
  actionError,
  actionLoading,
  instance,
  onAllowScript,
  onFinding,
  onStatus,
  ruleById
}: {
  actionError: string;
  actionLoading: boolean;
  instance: InstanceModel;
  onAllowScript: (finding: HubFinding) => void;
  onFinding: (id: string) => void;
  onStatus: (finding: HubFinding, status: string) => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  const attention = priorityFindings([instance]).slice(0, 4);
  const [activeTab, setActiveTab] = useState("findings");
  const [drawerFindingID, setDrawerFindingID] = useState<string>(attention[0]?.finding.id ?? "");
  const selectedFinding = instance.data.findings.data.find((finding) => finding.id === drawerFindingID) ?? instance.data.findings.data[0];

  return (
    <div className="view-stack spec-page">
      <section className={`entity-header instance-header ${instance.status}`}>
        <div className="entity-identity">
          <AvatarLabel iconUrls={instance.iconUrls} name={instance.projectName} />
          <span>
          <p className="eyebrow">{instance.companyName} / {instance.projectName} / {instance.environmentName}</p>
          <h2>{instance.projectName}</h2>
            <p>{appKindLabel(instance.appKind)} / {instance.appName}</p>
          </span>
        </div>
        <div className="summary-metrics compact">
          <HealthBadge status={instance.status} />
          <InfoTile label="Agent status" value={`${instance.activeAgentCount}/${instance.agentCount} active`} tone={instance.activeAgentCount > 0 ? "ok" : "danger"} />
          <InfoTile label="Last seen" value={formatRelative(instance.lastSignalAt)} tone="muted" />
          <InfoTile label="Risk score" value={`${instanceRiskScore(instance)}/100`} tone={instanceRiskScore(instance) >= 70 ? "danger" : instanceRiskScore(instance) >= 35 ? "warning" : "ok"} />
        </div>
      </section>

      <section className="panel spec-panel">
        <PanelTitle icon={AlertTriangle} title="Needs attention" />
        <AttentionList items={attention} onFinding={(id) => setDrawerFindingID(id)} ruleById={ruleById} />
      </section>
      <section className="collector-grid">
        {instance.collectors.map((collector) => (
          <button className={`collector-card ${collector.status}`} key={collector.key} type="button" onClick={() => setActiveTab(collector.key === "database" ? "database" : collector.key === "browser" ? "browser" : collector.key === "files" ? "files" : "agent")}>
            <span>{collector.label}</span>
            <strong>{collector.status}</strong>
            <small>{collector.lastSeenAt ? `${formatRelative(collector.lastSeenAt)} / ${collector.detail}` : collector.detail}</small>
          </button>
        ))}
      </section>

      <div className="tab-strip" role="tablist">
        {[
          ["findings", `Findings (${instance.data.findings.data.length})`],
          ["timeline", "Timeline"],
          ["database", "Database Changes"],
          ["files", "Files"],
          ["browser", "Browser / Scripts"],
          ["agent", "Agent / Config"]
        ].map(([key, label]) => (
          <button className={activeTab === key ? "active" : ""} key={key} type="button" onClick={() => setActiveTab(key)}>{label}</button>
        ))}
      </div>

      <section className="instance-workspace">
        <div className="panel table-panel">
          {activeTab === "findings" && (
            <InstanceFindingsTable
              findings={instance.data.findings.data}
              onSelect={(id) => setDrawerFindingID(id)}
              ruleById={ruleById}
              selectedFindingID={selectedFinding?.id}
            />
          )}
          {activeTab === "timeline" && <TimelineView events={instance.data.timeline.data} />}
          {activeTab === "database" && <TimelineView events={instance.data.timeline.data.filter((event) => event.type.startsWith("db."))} />}
          {activeTab === "files" && <TimelineView events={instance.data.timeline.data.filter((event) => event.type.startsWith("file."))} />}
          {activeTab === "browser" && <BrowserView scripts={instance.data.browserScripts.data} allowlist={instance.data.allowlist.data} />}
          {activeTab === "agent" && (
            <div className="panel embedded-panel">
              <PanelTitle icon={TerminalSquare} title="Agent / Config" />
              <CoverageMatrix coverage={instance.data.coverage.data} />
              <AgentRows agents={instance.data.topology.data.agents} hosts={instance.data.topology.data.hosts} />
            </div>
          )}
        </div>
        <FindingDrawer
          actionError={actionError}
          actionLoading={actionLoading}
          finding={selectedFinding}
          onAllowScript={() => selectedFinding && onAllowScript(selectedFinding)}
          onStatus={(status) => selectedFinding && onStatus(selectedFinding, status)}
          ruleById={ruleById}
        />
      </section>
      <ConsoleFooter />
    </div>
  );
}

function CoverageCommandCenter({ estate, onInstance }: { estate: EstateModel; onInstance: (instance: InstanceModel) => void }) {
  const [query, setQuery] = useState("");
  const [columnsOpen, setColumnsOpen] = useState(false);
  const [visibleColumns, setVisibleColumns] = useState({
    agent: true,
    browser: true,
    config: true,
    database: true,
    files: true,
    findings: true,
    lastSignal: true
  });
  const normalizedQuery = query.trim().toLowerCase();
  const instances = normalizedQuery
    ? estate.instances.filter((instance) =>
        [instance.companyName, instance.projectName, instance.environmentName, instance.appName, instance.appKind, instance.statusReason]
          .some((value) => value.toLowerCase().includes(normalizedQuery))
      )
    : estate.instances;
  const latest = [...estate.instances].sort((left, right) => new Date(right.lastSignalAt ?? 0).getTime() - new Date(left.lastSignalAt ?? 0).getTime())[0];
  const coveragePercent = estateCoveragePercent(estate);
  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip five">
        <KpiCard icon={Server} label="Total instances" value={estate.totals.instances} tone="blue" trend="current estate" />
        <KpiCard icon={ListChecks} label="Overall coverage" value={`${coveragePercent}%`} tone="green" trend="collector freshness" />
        <KpiCard icon={TerminalSquare} label="Stale agents" value={estate.totals.staleAgents} tone={estate.totals.staleAgents > 0 ? "orange" : "green"} trend="signal aware" />
        <KpiCard icon={AlertTriangle} label="Failed scans" value={estate.instances.reduce((sum, instance) => sum + instance.collectors.filter((collector) => collector.status === "missing").length, 0)} tone="red" trend="missing collectors" />
        <KpiCard icon={Activity} label="Last successful signal" value={formatRelative(latest?.lastSignalAt)} tone="purple" trend={latest ? `${latest.companyName} / ${latest.projectName}` : "no signal"} />
      </section>

      <section className="operations-grid">
        <div className="operations-main">
          <section className="panel table-panel">
            <div className="table-toolbar">
              <div>
                <PanelHeading icon={ListChecks} title="Coverage Matrix" />
                <p className="panel-subtitle">{instances.length}/{estate.instances.length} monitored instance{estate.instances.length === 1 ? "" : "s"}</p>
              </div>
              <div className="table-actions">
                <div className="search-field compact"><Search size={16} aria-hidden="true" /><input className="form-control" placeholder="Search instances..." value={query} onChange={(event) => setQuery(event.target.value)} /></div>
                <div className="menu-wrap">
                  <button className="icon-button" type="button" title="Columns" onClick={() => setColumnsOpen((open) => !open)}><Columns3 size={16} /></button>
                  {columnsOpen && (
                    <div className="floating-menu">
                      {Object.entries({
                        files: "Files",
                        database: "Database",
                        browser: "Browser",
                        config: "Config",
                        agent: "Agent status",
                        findings: "Open findings",
                        lastSignal: "Last signal"
                      }).map(([key, label]) => (
                        <label key={key}>
                          <input
                            checked={visibleColumns[key as keyof typeof visibleColumns]}
                            type="checkbox"
                            onChange={(event) => setVisibleColumns((current) => ({ ...current, [key]: event.target.checked }))}
                          />
                          {label}
                        </label>
                      ))}
                    </div>
                  )}
                </div>
                <button className="icon-button" type="button" title="Export" onClick={() => exportCoverage(instances, visibleColumns)}><Download size={16} /></button>
              </div>
            </div>
            <div className="table-responsive">
              <table className="table align-middle data-table coverage-table">
                <thead>
                  <tr>
                    <th>Company</th>
                    <th>Site</th>
                    <th>Instance</th>
                    {visibleColumns.files && <th>Files</th>}
                    {visibleColumns.database && <th>Database</th>}
                    {visibleColumns.browser && <th>Browser</th>}
                    {visibleColumns.config && <th>Config</th>}
                    {visibleColumns.agent && <th>Agent status</th>}
                    {visibleColumns.findings && <th>Open findings</th>}
                    {visibleColumns.lastSignal && <th>Last signal</th>}
                  </tr>
                </thead>
                <tbody>
                  {instances.map((instance) => {
                    const collectors = new Map(instance.collectors.map((collector) => [collector.key, collector]));
                    return (
                      <tr key={instance.key} onClick={() => onInstance(instance)}>
                        <td><AvatarLabel iconUrls={instance.iconUrls} name={instance.companyName} /><div className="muted-line">{instance.companyName}</div></td>
                        <td>
                          <button className="table-link" type="button" onClick={(event) => {
                            event.stopPropagation();
                            onInstance(instance);
                          }}>
                            {instance.projectName}
                          </button>
                        </td>
                        <td>{instance.environmentName}<div className="muted-line">{instance.appName}</div></td>
                        {visibleColumns.files && <td><CollectorBadge collector={collectors.get("files")} /></td>}
                        {visibleColumns.database && <td><CollectorBadge collector={collectors.get("database")} /></td>}
                        {visibleColumns.browser && <td><CollectorBadge collector={collectors.get("browser")} /></td>}
                        {visibleColumns.config && <td><CollectorBadge collector={collectors.get("config")} /></td>}
                        {visibleColumns.agent && <td><HealthBadge status={instance.status} /></td>}
                        {visibleColumns.findings && <td>{instance.openFindings}</td>}
                        {visibleColumns.lastSignal && <td>{formatRelative(instance.lastSignalAt)}</td>}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {instances.length === 0 && <EmptyState icon={ListChecks} title="No coverage" detail="No monitored instances match the current filters." />}
          </section>
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={TerminalSquare} title="Agent Health" />
            <DonutChart centerLabel="Total agents" centerValue={String(estate.totals.activeAgents)} data={statusChartData(estate.instances)} />
            <LegendList data={statusChartData(estate.instances)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Activity} title="Coverage Trend" />
            <MiniLineChart data={estate.instances.map((instance) => ({ label: instance.projectName, value: instanceCoveragePercent(instance) }))} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Building2} title="Environment Distribution" />
            <DonutChart centerLabel="Total instances" centerValue={String(estate.totals.instances)} data={environmentChartData(estate)} />
            <LegendList data={environmentChartData(estate)} />
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function AttentionList({
  items,
  onFinding,
  ruleById
}: {
  items: FindingWithInstance[];
  onFinding: (id: string, instance?: InstanceModel) => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  if (items.length === 0) {
    return <EmptyState icon={ShieldCheck} title="Nothing urgent" detail="No open high-priority findings are present in this scope." />;
  }

  return (
    <div className="stack-list">
      {items.map(({ finding, instance }) => (
        <button className="attention-row" key={`${instance.key}:${finding.id}`} type="button" onClick={() => onFinding(finding.id, instance)}>
          <SeverityBadge severity={finding.severity} />
          <span>
            <strong>{finding.title}</strong>
            <small>{instance.companyName} / {instance.projectName} / {instance.environmentName} / {ruleById.get(finding.rule_id)?.category ?? finding.rule_id}</small>
          </span>
          <span>{formatRelative(finding.last_event_at)}</span>
        </button>
      ))}
    </div>
  );
}

function ScriptList({ scripts }: { scripts: BrowserScript[] }) {
  if (scripts.length === 0) {
    return <EmptyState icon={Bug} title="No browser scripts" detail="No browser script observations were returned for this instance." />;
  }
  return (
    <div className="stack-list">
      {scripts.map((script) => (
        <div className="stack-row passive" key={script.event_id}>
          <StatusBadge status={script.source_type || script.type} />
          <span>
            <strong>{script.domain || "inline"}</strong>
            <small>{script.url_redacted || script.path || script.sha256 || script.target}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function InstanceFindingsTable({
  findings,
  onSelect,
  ruleById,
  selectedFindingID
}: {
  findings: HubFinding[];
  onSelect: (id: string) => void;
  ruleById: Map<string, RuleDefinition>;
  selectedFindingID?: string;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const normalizedQuery = query.trim().toLowerCase();
  const filteredFindings = findings.filter((finding) => {
    const queryMatch = !normalizedQuery ||
      [finding.title, finding.rule_id, finding.summary, finding.description, ruleById.get(finding.rule_id)?.category]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(normalizedQuery));
    const severityMatch = severity === "all" || finding.severity === severity;
    const statusMatch = status === "all" || finding.status === status;
    return queryMatch && severityMatch && statusMatch;
  });

  if (findings.length === 0) {
    return <EmptyState icon={ShieldCheck} title="No findings" detail="No findings were returned for this instance." />;
  }
  return (
    <>
      <div className="table-toolbar">
        <PanelHeading icon={AlertTriangle} title={`Findings (${filteredFindings.length}/${findings.length})`} />
        <div className="table-actions">
          <div className="search-field compact">
            <Search size={16} aria-hidden="true" />
            <input className="form-control" placeholder="Search findings..." value={query} onChange={(event) => setQuery(event.target.value)} />
          </div>
          <select className="form-select filter-select" value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Severity">
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select className="form-select filter-select" value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Finding status">
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False positive</option>
          </select>
        </div>
      </div>
      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Severity</th>
              <th>First seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredFindings.map((finding) => (
              <tr className={selectedFindingID === finding.id ? "selected-row" : ""} key={finding.id} onClick={() => onSelect(finding.id)}>
                <td>
                  <button className="table-link" type="button" onClick={() => onSelect(finding.id)}>{finding.title}</button>
                  <div className="muted-line">{ruleById.get(finding.rule_id)?.category ?? finding.rule_id}</div>
                </td>
                <td><SeverityBadge severity={finding.severity} /></td>
                <td>{formatRelative(finding.first_event_at)}</td>
                <td><StatusBadge status={finding.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filteredFindings.length === 0 && <EmptyState icon={Search} title="No findings match" detail="No instance findings match the current search and filters." />}
    </>
  );
}

function FindingDrawer({
  actionError,
  actionLoading,
  finding,
  onAllowScript,
  onStatus,
  ruleById
}: {
  actionError: string;
  actionLoading: boolean;
  finding?: HubFinding;
  onAllowScript: () => void;
  onStatus: (status: string) => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  const [activeTab, setActiveTab] = useState<"details" | "evidence" | "response" | "history">("details");
  if (!finding) {
    return (
      <aside className="finding-drawer">
        <EmptyState icon={Search} title="No finding selected" detail="Select a finding to inspect details and evidence." />
      </aside>
    );
  }
  const risk = metadataRecord(finding.metadata.risk);
  return (
    <aside className="finding-drawer">
      <div className="drawer-heading">
        <SeverityBadge severity={finding.severity} />
        <h2>{finding.title}</h2>
        <small>{finding.id}</small>
      </div>
      <div className="drawer-metrics">
        <InfoTile label="Risk score" value={valueText(risk.score) || riskLabel(finding)} tone={finding.severity === "critical" || finding.severity === "high" ? "danger" : "warning"} />
        <InfoTile label="Confidence" value={finding.confidence} tone="muted" />
        <InfoTile label="Status" value={finding.status} tone={finding.status === "open" ? "warning" : "ok"} />
        <InfoTile label="Evidence" value={String(finding.event_ids.length)} tone="muted" />
      </div>
      <div className="drawer-tabs">
        <button className={activeTab === "details" ? "active" : ""} type="button" onClick={() => setActiveTab("details")}>Details</button>
        <button className={activeTab === "evidence" ? "active" : ""} type="button" onClick={() => setActiveTab("evidence")}>Evidence</button>
        <button className={activeTab === "response" ? "active" : ""} type="button" onClick={() => setActiveTab("response")}>Response</button>
        <button className={activeTab === "history" ? "active" : ""} type="button" onClick={() => setActiveTab("history")}>History</button>
      </div>
      {activeTab === "details" && (
        <>
          <div className="drawer-section">
            <h3>What happened</h3>
            <p>{finding.summary || finding.description || ruleById.get(finding.rule_id)?.title || "No summary was returned."}</p>
          </div>
          <dl className="detail-list compact">
            <div><dt>Rule</dt><dd>{finding.rule_id} / {finding.rule_version}</dd></div>
            <div><dt>First seen</dt><dd>{formatDate(finding.first_event_at)}</dd></div>
            <div><dt>Last seen</dt><dd>{formatDate(finding.last_event_at)}</dd></div>
            <div><dt>Fingerprint</dt><dd>{finding.dedupe_key}</dd></div>
          </dl>
          <FindingMetadata finding={finding} />
        </>
      )}
      {activeTab === "evidence" && (
        <div className="drawer-section">
          <h3>Evidence references</h3>
          <div className="stack-list compact-stack">
            {finding.event_ids.map((eventID) => (
              <div className="stack-row passive" key={eventID}>
                <StatusBadge status="evidence" />
                <span>
                  <strong>Event reference</strong>
                  <small className="mono-cell">{eventID}</small>
                </span>
              </div>
            ))}
          </div>
          {finding.event_ids.length === 0 && <EmptyState icon={Search} title="No evidence IDs" detail="This finding did not include event references." />}
        </div>
      )}
      {activeTab === "response" && (
        <div className="drawer-section">
          <h3>Response state</h3>
          <dl className="detail-list compact">
            <div><dt>Status</dt><dd>{finding.status}</dd></div>
            <div><dt>Reason</dt><dd>{finding.status_reason || "none"}</dd></div>
            <div><dt>Actor</dt><dd>{finding.status_actor || "none"}</dd></div>
            <div><dt>Note</dt><dd>{finding.status_note || "none"}</dd></div>
          </dl>
        </div>
      )}
      {activeTab === "history" && (
        <div className="drawer-section">
          <h3>History</h3>
          <dl className="detail-list compact">
            <div><dt>Created</dt><dd>{formatDate(finding.created_at)}</dd></div>
            <div><dt>Updated</dt><dd>{formatDate(finding.updated_at)}</dd></div>
            <div><dt>Status updated</dt><dd>{formatDate(finding.status_updated_at)}</dd></div>
            <div><dt>First observed</dt><dd>{formatDate(finding.first_event_at)}</dd></div>
            <div><dt>Last observed</dt><dd>{formatDate(finding.last_event_at)}</dd></div>
          </dl>
        </div>
      )}
      {actionError && <div className="alert alert-danger compact-alert">{actionError}</div>}
      <div className="button-row drawer-actions">
        <ActionButton icon={Eye} label="Acknowledge" loading={actionLoading} onClick={() => onStatus("acknowledged")} />
        <ActionButton icon={CheckCircle2} label="Resolve" loading={actionLoading} onClick={() => onStatus("resolved")} />
        <ActionButton icon={XCircle} label="False positive" loading={actionLoading} onClick={() => onStatus("false_positive")} />
        {isBrowserDriftFinding(finding) && <ActionButton icon={ShieldCheck} label="Allow script" loading={actionLoading} onClick={onAllowScript} />}
      </div>
    </aside>
  );
}

function IncidentInbox({
  actionError,
  actionLoading,
  estate,
  onAllowScript,
  onFinding,
  onStatus,
  ruleById
}: {
  actionError: string;
  actionLoading: boolean;
  estate: EstateModel;
  onAllowScript: (finding: HubFinding) => void;
  onFinding: (id: string, instance?: InstanceModel) => void;
  onStatus: (finding: HubFinding, status: string) => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  const [density, setDensity] = useState<"dense" | "comfort">("dense");
  const [groupBy, setGroupBy] = useState<"company" | "site">("company");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selected, setSelected] = useState<FindingWithInstance | undefined>();
  const [sortBy, setSortBy] = useState("risk");
  const allItems = estate.instances.flatMap((instance) =>
    instance.data.findings.data
      .filter((finding) => finding.status === "open")
      .map((finding) => ({ finding, instance }))
  );
  const allFindings = allItems.map((item) => item.finding);
  const normalizedQuery = query.trim().toLowerCase();
  const filteredItems = allItems.filter((item) => {
    const queryMatch = !normalizedQuery ||
      [
        item.finding.title,
        item.finding.rule_id,
        item.finding.summary,
        item.finding.description,
        item.instance.companyName,
        item.instance.projectName,
        item.instance.environmentName,
        ruleById.get(item.finding.rule_id)?.category
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(normalizedQuery));
    const severityMatch = severity === "all" || item.finding.severity === severity;
    return queryMatch && severityMatch;
  });
  const sortedItems = sortFindingItems(filteredItems, sortBy);
  const groups = groupIncidentItems(sortedItems, groupBy);
  const first = sortedItems[0];
  const selectedItem = selected && sortedItems.some((item) => item.finding.id === selected.finding.id && item.instance.key === selected.instance.key)
    ? selected
    : first;
  const visibleRowsPerGroup = density === "dense" ? 10 : 5;
  const filteredFindings = sortedItems.map((item) => item.finding);

  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip five">
        <KpiCard icon={AlertTriangle} label="Critical" value={allFindings.filter((finding) => finding.severity === "critical").length} tone="red" trend="open findings" />
        <KpiCard icon={ShieldHalf} label="High" value={allFindings.filter((finding) => finding.severity === "high").length} tone="orange" trend="open findings" />
        <KpiCard icon={AlertTriangle} label="Medium" value={allFindings.filter((finding) => finding.severity === "medium").length} tone="yellow" trend="open findings" />
        <KpiCard icon={TerminalSquare} label="Stale agents" value={estate.totals.staleAgents} tone="purple" trend="coverage trust" />
        <KpiCard icon={Sparkles} label="New findings today" value={allFindings.length} tone="blue" trend="current API window" />
      </section>

      <section className="incident-layout">
        <div className="operations-main">
          <div className="directory-toolbar">
            <select className="form-select filter-select" value={groupBy} onChange={(event) => setGroupBy(event.target.value as "company" | "site")} aria-label="Group by">
              <option value="company">Group by: Company</option>
              <option value="site">Group by: Site</option>
            </select>
            <select className="form-select filter-select" value={sortBy} onChange={(event) => setSortBy(event.target.value)} aria-label="Sort by">
              <option value="risk">Sort by: Risk score</option>
              <option value="time">Sort by: Last seen</option>
              <option value="company">Sort by: Company</option>
            </select>
            <select className="form-select filter-select" value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Severity filter">
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <div className="search-field directory-search">
              <Search size={16} aria-hidden="true" />
              <input className="form-control" placeholder="Search findings..." value={query} onChange={(event) => setQuery(event.target.value)} />
            </div>
            <div className="segmented-control">
              <button className={density === "dense" ? "active" : ""} type="button" onClick={() => setDensity("dense")}>Dense</button>
              <button className={density === "comfort" ? "active" : ""} type="button" onClick={() => setDensity("comfort")}>Comfort</button>
            </div>
          </div>
          <div className="grouped-findings">
            {groups.map((group) => (
              <section className="finding-group" key={group.key}>
                <header>
                  <AvatarLabel iconUrls={siteGroupIconCandidates(group.instances)} name={group.label} />
                  <span>
                    <strong>{group.label}</strong>
                    <small>{group.subLabel} / risk score {group.risk} / {group.findings.length} finding{group.findings.length === 1 ? "" : "s"}</small>
                  </span>
                  <HealthBadge status={group.status} />
                </header>
                <div className="table-responsive">
                  <table className="table align-middle data-table compact-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Site / Project</th>
                        <th>Environment</th>
                        <th>Finding Summary</th>
                        <th>Risk</th>
                        <th>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.findings.slice(0, visibleRowsPerGroup).map((item) => (
                        <tr key={`${item.instance.key}:${item.finding.id}`} onClick={() => setSelected(item)}>
                          <td><SeverityBadge severity={item.finding.severity} /></td>
                          <td>{item.instance.projectName}</td>
                          <td><StatusBadge status={item.instance.environmentName} /></td>
                          <td>
                            <button className="table-link" type="button" onClick={(event) => {
                              event.stopPropagation();
                              setSelected(item);
                            }}>{item.finding.title}</button>
                            <div className="muted-line">{ruleById.get(item.finding.rule_id)?.category ?? item.finding.rule_id}</div>
                          </td>
                          <td>{riskLabel(item.finding)}</td>
                          <td>{item.finding.event_ids.length}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            ))}
            {groups.length === 0 && <EmptyState icon={ShieldCheck} title="No findings" detail="No open findings match the current search and filters." />}
          </div>
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={ShieldCheck} title="Company health" />
            <DonutChart centerLabel="Companies" centerValue={String(estate.totals.companies)} data={companyHealthChartData(estate)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Activity} title="Findings over time" />
            <MiniLineChart data={findingsTrendData(filteredFindings)} stroke="#dc2626" />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={AlertTriangle} title="Top finding types" />
            <BarRows rows={topFindingTypeRows(filteredFindings, ruleById)} />
          </section>
        </aside>
        <FindingDrawer
          actionError={actionError}
          actionLoading={actionLoading}
          finding={selectedItem?.finding}
          onAllowScript={() => selectedItem && onAllowScript(selectedItem.finding)}
          onStatus={(status) => selectedItem && onStatus(selectedItem.finding, status)}
          ruleById={ruleById}
        />
      </section>
    </div>
  );
}

function InfoTile({ label, tone, value }: { label: string; tone: string; value: string }) {
  return (
    <div className={`info-tile ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function KpiCard({
  icon: Icon,
  label,
  onClick,
  tone,
  trend,
  value
}: {
  icon: typeof AlertTriangle;
  label: string;
  onClick?: () => void;
  tone: string;
  trend: string;
  value: number | string;
}) {
  const content = (
    <>
      <span className={`kpi-icon ${tone}`}><Icon size={20} aria-hidden="true" /></span>
      <span>
        <strong>{value}</strong>
        <small>{label}</small>
        <em>{trend}</em>
      </span>
    </>
  );
  if (onClick) {
    return <button className="kpi-card interactive" type="button" onClick={onClick}>{content}</button>;
  }
  return <div className="kpi-card">{content}</div>;
}

type ChartDatum = {
  color: string;
  name: string;
  value: number;
};

function DonutChart({ centerLabel, centerValue, data }: { centerLabel: string; centerValue: string; data: ChartDatum[] }) {
  const total = data.reduce((sumValue, item) => sumValue + item.value, 0);
  return (
    <div className="donut-wrap">
      <ResponsiveContainer width="100%" height={180}>
        <PieChart>
          <Pie data={data} dataKey="value" innerRadius={56} outerRadius={78} paddingAngle={2}>
            {data.map((entry) => <Cell fill={entry.color} key={entry.name} />)}
          </Pie>
          <RechartsTooltip
            formatter={(value, name) => {
              const numericValue = typeof value === "number" ? value : Number(value ?? 0);
              return [`${numericValue} (${percentOf(numericValue, total)}%)`, String(name)];
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="donut-center">
        <strong>{centerValue}</strong>
        <span>{centerLabel}</span>
      </div>
    </div>
  );
}

function MiniLineChart({ data, lineKey = "value", stroke = "#126dff" }: { data: Array<Record<string, number | string>>; lineKey?: string; stroke?: string }) {
  return (
    <div className="mini-chart">
      <ResponsiveContainer width="100%" height={180}>
        <LineChart data={data}>
          <XAxis dataKey="label" tickLine={false} axisLine={false} fontSize={11} />
          <YAxis tickLine={false} axisLine={false} fontSize={11} width={28} />
          <RechartsTooltip />
          <Line type="monotone" dataKey={lineKey} stroke={stroke} strokeWidth={3} dot={{ r: 3 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function MiniBarChart({ data }: { data: Array<Record<string, number | string>> }) {
  return (
    <div className="mini-chart">
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={data}>
          <XAxis dataKey="label" tickLine={false} axisLine={false} fontSize={11} />
          <YAxis tickLine={false} axisLine={false} fontSize={11} width={28} />
          <RechartsTooltip />
          <Bar dataKey="value" radius={[5, 5, 0, 0]} fill="#126dff" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function LegendList({ data }: { data: ChartDatum[] }) {
  const total = data.reduce((sumValue, item) => sumValue + item.value, 0);
  return (
    <div className="legend-list">
      {data.map((item) => (
        <div className="legend-row" key={item.name}>
          <span><i style={{ background: item.color }} />{item.name}</span>
          <strong>{item.value}</strong>
          <em>{percentOf(item.value, total)}%</em>
        </div>
      ))}
    </div>
  );
}

function RankedCompanyList({ companies, onCompany }: { companies: CompanyModel[]; onCompany: (company: CompanyModel) => void }) {
  if (companies.length === 0) {
    return <EmptyState icon={ShieldCheck} title="No company risk" detail="No monitored companies were returned." />;
  }
  return (
    <div className="ranked-list">
      {companies.map((company) => (
        <button className="ranked-row" key={company.companySlug} type="button" onClick={() => onCompany(company)}>
          <span className={`status-dot ${company.status}`} />
          <span>
            <strong>{company.companyName}</strong>
            <small>{platformSummary(company)}</small>
          </span>
          <strong>{riskScore(company)}</strong>
        </button>
      ))}
    </div>
  );
}

function BarRows({ rows }: { rows: Array<{ label: string; value: number }> }) {
  const max = Math.max(...rows.map((row) => row.value), 1);
  if (rows.length === 0) {
    return <EmptyState icon={AlertTriangle} title="No types" detail="No finding categories are available." />;
  }
  return (
    <div className="bar-row-list">
      {rows.map((row) => (
        <div className="bar-row" key={row.label}>
          <span>{row.label}</span>
          <div><i style={{ width: `${Math.max(6, (row.value / max) * 100)}%` }} /></div>
          <strong>{row.value}</strong>
        </div>
      ))}
    </div>
  );
}

function CompactInstanceList({ instances, onInstance }: { instances: InstanceModel[]; onInstance: (instance: InstanceModel) => void }) {
  if (instances.length === 0) {
    return <EmptyState icon={Server} title="No instances" detail="No derived instances were returned for this company." />;
  }
  return (
    <div className="stack-list">
      {instances.map((instance) => (
        <button className="stack-row" key={instance.key} type="button" onClick={() => onInstance(instance)}>
          <HealthBadge status={instance.status} />
          <span>
            <strong>{instance.projectName}</strong>
            <small>{appKindLabel(instance.appKind)} / {instance.environmentName} / coverage {instanceCoveragePercent(instance)}%</small>
          </span>
          <strong>{instance.openFindings}</strong>
        </button>
      ))}
    </div>
  );
}

function CompactSiteList({ instances, onSite }: { instances: InstanceModel[]; onSite: (instance: InstanceModel) => void }) {
  const groups = siteGroups(instances);
  if (groups.length === 0) {
    return <EmptyState icon={MonitorCog} title="No sites" detail="No monitored sites were returned for this company." />;
  }
  return (
    <div className="stack-list">
      {groups.map((group) => (
        <button className="stack-row site-stack-row" key={`${group.companySlug}:${group.projectSlug}`} type="button" onClick={() => onSite(group.instances[0])}>
          <AvatarLabel iconUrls={group.iconUrls} name={group.projectName} />
          <span>
            <strong>{group.projectName}</strong>
            <small>{group.instances.length} instance{group.instances.length === 1 ? "" : "s"} / {group.platforms.join(", ") || "Web app"}</small>
          </span>
          <HealthBadge status={worstStatus(group.instances)} />
          <strong>{group.openFindings}</strong>
        </button>
      ))}
    </div>
  );
}

function SiteChangeList({
  deployments,
  events,
  findings
}: {
  deployments: Deployment[];
  events: TimelineEvent[];
  findings: FindingWithInstance[];
}) {
  const rows = [
    ...deployments.map((deployment) => ({
      key: `deployment:${deployment.id}`,
      label: `Deployment ${deployment.version}`,
      meta: deployment.actor || deployment.commit_sha || "deployment marker",
      status: deployment.finished_at ? "completed" : "active",
      time: deployment.started_at
    })),
    ...findings.slice(0, 4).map(({ finding, instance }) => ({
      key: `finding:${finding.id}:${instance.key}`,
      label: finding.title,
      meta: `${instance.environmentName} / ${finding.rule_id}`,
      status: finding.severity,
      time: finding.last_event_at
    })),
    ...events.slice(0, 8).map((event) => ({
      key: `event:${event.id}`,
      label: event.message || event.type,
      meta: `${eventSourceLabel(event.type)} / ${event.host || event.hostname || "target"}`,
      status: event.severity || "info",
      time: event.event_time
    }))
  ]
    .sort((left, right) => new Date(right.time).getTime() - new Date(left.time).getTime())
    .slice(0, 6);

  if (rows.length === 0) {
    return <EmptyState icon={Activity} title="No changes" detail="No site changes were returned for this time range." />;
  }

  return (
    <div className="stack-list">
      {rows.map((row) => (
        <div className="stack-row passive" key={row.key}>
          <StatusBadge status={row.status} />
          <span>
            <strong>{row.label}</strong>
            <small>{row.meta} / {formatRelative(row.time)}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function DeploymentContext({ deployments }: { deployments: Deployment[] }) {
  const latest = deployments[0];
  if (!latest) {
    return <EmptyState icon={GitBranch} title="No deployment context" detail="No deployment markers were returned for this site." />;
  }
  return (
    <dl className="detail-list compact">
      <div><dt>Version</dt><dd>{latest.version}</dd></div>
      <div><dt>Commit</dt><dd className="mono-cell">{shortSha(latest.commit_sha)}</dd></div>
      <div><dt>Actor</dt><dd>{latest.actor || "unknown"}</dd></div>
      <div><dt>Last deployment</dt><dd>{formatRelative(latest.started_at)}</dd></div>
      <div><dt>Status</dt><dd>{latest.finished_at ? "Completed" : "Active"}</dd></div>
    </dl>
  );
}

function DeploymentList({ deployments }: { deployments: Deployment[] }) {
  if (deployments.length === 0) {
    return <EmptyState icon={GitBranch} title="No deployments" detail="No deployment markers were returned for this scope." />;
  }
  return (
    <div className="stack-list">
      {deployments.map((deployment) => (
        <div className="stack-row passive" key={deployment.id}>
          <StatusBadge status={deployment.finished_at ? "completed" : "active"} />
          <span>
            <strong>{deployment.version}</strong>
            <small>{deployment.actor || "unknown actor"} / {formatRelative(deployment.started_at)}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function AvatarLabel({ iconUrls = [], name }: { iconUrls?: string[]; name: string }) {
  const candidates = useMemo(() => uniqueStrings(iconUrls).slice(0, 8), [iconUrls]);
  const iconKey = candidates.join("|");
  const [failedIconCount, setFailedIconCount] = useState(0);
  useEffect(() => {
    setFailedIconCount(0);
  }, [iconKey]);
  const src = candidates[failedIconCount];
  return (
    <span className={`company-avatar ${src ? "has-icon" : ""}`} title={name}>
      {src ? (
        <img
          alt=""
          loading="lazy"
          referrerPolicy="no-referrer"
          src={src}
          onError={() => setFailedIconCount((count) => count + 1)}
        />
      ) : initials(name)}
    </span>
  );
}

function RiskGauge({ value }: { value: number }) {
  const color = value >= 70 ? statusColors.critical : value >= 35 ? statusColors.warning : statusColors.healthy;
  return (
    <span className="risk-gauge" style={{ ["--risk" as string]: `${value * 3.6}deg`, ["--risk-color" as string]: color }}>
      <strong>{value}</strong>
    </span>
  );
}

function ConsoleFooter() {
  return (
    <footer className="console-footer">
      <span>Copyright 2025 Aegrail Inc. All rights reserved.</span>
      <span>Version 1.0.0</span>
      <span><i /> Status</span>
    </footer>
  );
}

function Breadcrumbs({ items, onView }: { items: BreadcrumbItem[]; onView: (view: ViewKey) => void }) {
  if (items.length <= 1) {
    return null;
  }
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      {items.map((item, index) => {
        const isCurrent = index === items.length - 1;
        const key = `${item.label}:${index}`;
        return (
          <span className="dashboard-breadcrumb-item" key={key}>
            {item.view && !isCurrent ? (
              <button type="button" onClick={() => item.view && onView(item.view)}>
                {item.label}
              </button>
            ) : (
              <span aria-current={isCurrent ? "page" : undefined}>{item.label}</span>
            )}
          </span>
        );
      })}
    </nav>
  );
}

function ActiveFilterChips({
  filters,
  onClear,
  onClearAll
}: {
  filters: DashboardFilters;
  onClear: (filter: keyof DashboardFilters) => void;
  onClearAll: () => void;
}) {
  const chips = [
    filters.platform !== "all" ? { key: "platform" as const, label: `Platform: ${platformLabel(filters.platform)}` } : null,
    filters.status !== "all" ? { key: "status" as const, label: `Status: ${statusLabel(filters.status)}` } : null
  ].filter(Boolean) as Array<{ key: keyof DashboardFilters; label: string }>;

  if (chips.length === 0) {
    return null;
  }

  return (
    <div className="active-filter-chips" aria-label="Active dashboard filters">
      {chips.map((chip) => (
        <button className="filter-chip" key={chip.key} type="button" onClick={() => onClear(chip.key)}>
          {chip.label}
          <XCircle size={14} aria-hidden="true" />
        </button>
      ))}
      <button className="filter-chip clear" type="button" onClick={onClearAll}>Clear all</button>
    </div>
  );
}

function HealthBadge({ status }: { status: "critical" | "warning" | "healthy" }) {
  return <span className={`health-badge ${status}`}>{status}</span>;
}

function CollectorPills({ collectors }: { collectors: InstanceModel["collectors"] }) {
  return (
    <div className="collector-pills">
      {collectors.map((collector) => (
        <CollectorBadge collector={collector} key={collector.key} />
      ))}
    </div>
  );
}

function CollectorBadge({ collector }: { collector?: InstanceModel["collectors"][number] }) {
  if (!collector) {
    return <span className="collector-badge missing">n/a</span>;
  }
  return <span className={`collector-badge ${collector.status}`} title={collector.detail}>{collector.label}</span>;
}

function priorityFindings(instances: InstanceModel[]): FindingWithInstance[] {
  const sorted = instances
    .flatMap((instance) =>
      instance.data.findings.data
        .filter((finding) => finding.status === "open")
        .map((finding) => ({ finding, instance }))
    )
    .sort((left, right) => {
      const severityDiff = (severityRank[right.finding.severity] ?? 0) - (severityRank[left.finding.severity] ?? 0);
      if (severityDiff !== 0) {
        return severityDiff;
      }
      return new Date(right.finding.last_event_at).getTime() - new Date(left.finding.last_event_at).getTime();
    });
  const seen = new Set<string>();
  const grouped: FindingWithInstance[] = [];
  for (const item of sorted) {
    const key = `${item.instance.key}:${item.finding.title || item.finding.dedupe_key || item.finding.rule_id}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    grouped.push(item);
  }
  return grouped;
}

function sortFindingItems(items: FindingWithInstance[], sortBy: string) {
  return [...items].sort((left, right) => {
    switch (sortBy) {
      case "time":
        return new Date(right.finding.last_event_at).getTime() - new Date(left.finding.last_event_at).getTime();
      case "company":
        return left.instance.companyName.localeCompare(right.instance.companyName) ||
          left.instance.projectName.localeCompare(right.instance.projectName) ||
          (severityRank[right.finding.severity] ?? 0) - (severityRank[left.finding.severity] ?? 0);
      case "risk":
      default:
        return (severityRank[right.finding.severity] ?? 0) - (severityRank[left.finding.severity] ?? 0) ||
          new Date(right.finding.last_event_at).getTime() - new Date(left.finding.last_event_at).getTime();
    }
  });
}

function groupIncidentItems(items: FindingWithInstance[], groupBy: "company" | "site") {
  const groups = new Map<string, FindingWithInstance[]>();
  for (const item of items) {
    const key = groupBy === "company"
      ? item.instance.companySlug
      : `${item.instance.companySlug}:${item.instance.projectSlug}`;
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  return Array.from(groups.entries()).map(([key, findings]) => {
    const first = findings[0].instance;
    const instances = Array.from(new Map(findings.map((item) => [item.instance.key, item.instance])).values());
    const status = worstStatus(instances);
    const label = groupBy === "company" ? first.companyName : first.projectName;
    const siteCount = new Set(instances.map((instance) => instance.projectSlug)).size;
    const subLabel = groupBy === "company"
      ? `${siteCount} site${siteCount === 1 ? "" : "s"}`
      : `${first.companyName} / ${instances.length} instance${instances.length === 1 ? "" : "s"}`;
    return {
      findings,
      instances,
      key,
      label,
      risk: Math.max(...instances.map(instanceRiskScore), 0),
      status,
      subLabel
    };
  });
}

function filterEstate(estate: EstateModel, filters: DashboardFilters): EstateModel {
  if (filters.platform === "all" && filters.status === "all") {
    return estate;
  }
  const instances = estate.instances.filter((instance) => {
    const platformMatch = filters.platform === "all" || instance.appKind === filters.platform;
    const statusMatch = filters.status === "all" || instance.status === filters.status;
    return platformMatch && statusMatch;
  });
  const companyMap = new Map<string, InstanceModel[]>();
  for (const instance of instances) {
    companyMap.set(instance.companySlug, [...(companyMap.get(instance.companySlug) ?? []), instance]);
  }
  const companies = Array.from(companyMap.values())
    .map(companyFromInstances)
    .sort((left, right) => statusWeight(right.status) - statusWeight(left.status) || left.companyName.localeCompare(right.companyName));
  const siteKeys = new Set(instances.map((instance) => `${instance.companySlug}:${instance.projectSlug}`));

  return {
    companies,
    instances,
    totals: {
      activeAgents: instances.reduce((total, instance) => total + instance.activeAgentCount, 0),
      companies: companies.length,
      criticalFindings: instances.reduce((total, instance) => total + instance.criticalFindings, 0),
      highFindings: instances.reduce((total, instance) => total + instance.highFindings, 0),
      instances: instances.length,
      openFindings: instances.reduce((total, instance) => total + instance.openFindings, 0),
      sites: siteKeys.size,
      staleAgents: instances.reduce((total, instance) => total + instance.staleAgents, 0),
      warningInstances: instances.filter((instance) => instance.status !== "healthy").length
    }
  };
}

function companyFromInstances(instances: InstanceModel[]): CompanyModel {
  const first = instances[0];
  const priority = priorityFindings(instances)[0]?.finding;
  const status = worstStatus(instances);
  const projectKeys = new Set(instances.map((instance) => instance.projectSlug));
  const reason = priority?.title ||
    instances.find((instance) => instance.status !== "healthy")?.statusReason ||
    "No open high-risk signals";

  return {
    companyName: first?.companyName ?? "Unknown company",
    companySlug: first?.companySlug ?? "",
    coverageWarnings: instances.reduce((total, instance) => total + instance.coverageWarnings, 0),
    criticalFindings: instances.reduce((total, instance) => total + instance.criticalFindings, 0),
    highFindings: instances.reduce((total, instance) => total + instance.highFindings, 0),
    iconUrls: uniqueStrings(instances.flatMap((instance) => instance.iconUrls)),
    instances,
    lastSignalAt: newestISO(instances.map((instance) => instance.lastSignalAt)),
    mediumFindings: instances.reduce((total, instance) => total + instance.mediumFindings, 0),
    openFindings: instances.reduce((total, instance) => total + instance.openFindings, 0),
    siteCount: projectKeys.size,
    staleAgents: instances.reduce((total, instance) => total + instance.staleAgents, 0),
    status,
    statusReason: reason,
    totalFindings: instances.reduce((total, instance) => total + instance.totalFindings, 0),
    worstFinding: priority
  };
}

function sortCompanies(companies: CompanyModel[], sortMode: string) {
  return [...companies].sort((left, right) => {
    switch (sortMode) {
      case "risk":
        return riskScore(right) - riskScore(left) || left.companyName.localeCompare(right.companyName);
      case "findings":
        return right.openFindings - left.openFindings || left.companyName.localeCompare(right.companyName);
      case "signal":
        return new Date(right.lastSignalAt ?? 0).getTime() - new Date(left.lastSignalAt ?? 0).getTime() || left.companyName.localeCompare(right.companyName);
      case "name":
        return left.companyName.localeCompare(right.companyName);
      case "health":
      default:
        return statusWeight(right.status) - statusWeight(left.status) || riskScore(right) - riskScore(left) || left.companyName.localeCompare(right.companyName);
    }
  });
}

function siteGroups(instances: InstanceModel[]): SiteGroup[] {
  const grouped = new Map<string, InstanceModel[]>();
  for (const instance of instances) {
    const key = `${instance.companySlug}:${instance.projectSlug}`;
    grouped.set(key, [...(grouped.get(key) ?? []), instance]);
  }
  return Array.from(grouped.values())
    .map((groupInstances) => {
      const first = groupInstances[0];
      return {
        companySlug: first.companySlug,
        iconUrls: uniqueStrings(groupInstances.flatMap((instance) => instance.iconUrls)),
        instances: groupInstances,
        openFindings: groupInstances.reduce((total, instance) => total + instance.openFindings, 0),
        platforms: Array.from(new Set(groupInstances.map((instance) => appKindLabel(instance.appKind)))),
        projectName: first.projectName,
        projectSlug: first.projectSlug
      };
    })
    .sort((left, right) => statusWeight(worstStatus(right.instances)) - statusWeight(worstStatus(left.instances)) || left.projectName.localeCompare(right.projectName));
}

function worstStatus(instances: InstanceModel[]): "critical" | "warning" | "healthy" {
  if (instances.some((instance) => instance.status === "critical")) {
    return "critical";
  }
  if (instances.some((instance) => instance.status === "warning")) {
    return "warning";
  }
  return "healthy";
}

function statusWeight(status: "critical" | "warning" | "healthy") {
  switch (status) {
    case "critical":
      return 3;
    case "warning":
      return 2;
    case "healthy":
      return 1;
  }
}

function siteRiskScore(instances: InstanceModel[]) {
  return Math.min(100, instances.reduce((total, instance) => total + instanceRiskScore(instance), 0));
}

function browserDriftChartData(instances: InstanceModel[]): ChartDatum[] {
  const browserCollectors = instances.map((instance) => instance.collectors.find((collector) => collector.key === "browser"));
  const upToDate = browserCollectors.filter((collector) => collector?.status === "fresh").length;
  const minor = browserCollectors.filter((collector) => collector?.status === "warning" || collector?.status === "stale").length;
  const unknown = browserCollectors.filter((collector) => !collector || collector.status === "missing").length;
  return [
    { color: statusColors.healthy, name: "Up to date", value: upToDate },
    { color: statusColors.warning, name: "Minor drift", value: minor },
    { color: statusColors.critical, name: "Major drift", value: 0 },
    { color: statusColors.unknown, name: "Unknown", value: unknown }
  ];
}

function newestISO(values: Array<string | undefined>) {
  const latest = values.reduce((max, value) => Math.max(max, value ? new Date(value).getTime() : 0), 0);
  return latest > 0 ? new Date(latest).toISOString() : undefined;
}

function sortEventsNewest(left: TimelineEvent, right: TimelineEvent) {
  return new Date(right.event_time).getTime() - new Date(left.event_time).getTime();
}

function sortDeploymentsNewest(left: Deployment, right: Deployment) {
  return new Date(right.started_at).getTime() - new Date(left.started_at).getTime();
}

function shortSha(value?: string) {
  return value ? value.slice(0, 10) : "none";
}

function coverageTone(level: string) {
  if (["complete", "full", "strong"].includes(level)) {
    return "ok";
  }
  if (level === "unknown") {
    return "muted";
  }
  return "warning";
}

function statusChartData(instances: InstanceModel[]): ChartDatum[] {
  return ["healthy", "warning", "critical"].map((status) => ({
    color: statusColors[status],
    name: capitalize(status),
    value: instances.filter((instance) => instance.status === status).length
  }));
}

function companyHealthChartData(estate: EstateModel): ChartDatum[] {
  return ["healthy", "warning", "critical"].map((status) => ({
    color: statusColors[status],
    name: capitalize(status),
    value: estate.companies.filter((company) => company.status === status).length
  }));
}

function environmentChartData(estate: EstateModel): ChartDatum[] {
  const colors = ["#126dff", "#7c3aed", "#00a491", "#64748b"];
  const counts = new Map<string, number>();
  for (const instance of estate.instances) {
    counts.set(instance.environmentName, (counts.get(instance.environmentName) ?? 0) + 1);
  }
  return Array.from(counts.entries()).map(([name, value], index) => ({ color: colors[index % colors.length], name, value }));
}

function versionChartData(estate: EstateModel): ChartDatum[] {
  const colors = ["#126dff", "#00a491", "#f59e0b", "#64748b"];
  const counts = new Map<string, number>();
  for (const instance of estate.instances) {
    const version = instance.data.topology.data.agents[0]?.version || "unknown";
    counts.set(version, (counts.get(version) ?? 0) + 1);
  }
  return Array.from(counts.entries()).map(([name, value], index) => ({ color: colors[index % colors.length], name, value }));
}

function severityChartData(findings: Array<{ severity: string }>): ChartDatum[] {
  return ["critical", "high", "medium", "low", "info"].map((severity) => ({
    color: severityColors[severity],
    name: capitalize(severity),
    value: findings.filter((finding) => finding.severity === severity).length
  }));
}

function estateCoveragePercent(estate: EstateModel) {
  const expectedSignals = estate.instances.length * 4;
  if (expectedSignals === 0) {
    return 0;
  }
  const freshSignals = estate.instances.reduce(
    (total, instance) => total + instance.collectors.filter((collector) => collector.status === "fresh").length,
    0
  );
  return Math.round((freshSignals / expectedSignals) * 100);
}

function instanceCoveragePercent(instance: InstanceModel) {
  const freshSignals = instance.collectors.filter((collector) => collector.status === "fresh").length;
  return Math.round((freshSignals / Math.max(instance.collectors.length, 1)) * 100);
}

function riskScore(company: CompanyModel) {
  return Math.min(100, company.criticalFindings * 30 + company.highFindings * 18 + company.mediumFindings * 7 + company.staleAgents * 18 + company.coverageWarnings * 8);
}

function instanceRiskScore(instance: InstanceModel) {
  return Math.min(100, instance.criticalFindings * 30 + instance.highFindings * 18 + instance.mediumFindings * 7 + instance.staleAgents * 18 + instance.coverageWarnings * 8);
}

function riskBand(score: number) {
  if (score >= 70) {
    return "High";
  }
  if (score >= 35) {
    return "Medium";
  }
  return "Low";
}

function percentOf(value: number, total: number) {
  if (total <= 0) {
    return 0;
  }
  return Math.round((value / total) * 100);
}

function platformSummary(company: CompanyModel) {
  const platforms = platformBadges(company);
  return platforms.length > 0 ? platforms.join(", ") : "Web estate";
}

function platformBadges(company: CompanyModel) {
  return Array.from(new Set(company.instances.map((instance) => appKindLabel(instance.appKind)))).slice(0, 3);
}

function platformFilterOptions(instances: InstanceModel[]): PlatformFilterOption[] {
  const counts = new Map<string, number>();
  for (const instance of instances) {
    const kind = instance.appKind || "app";
    counts.set(kind, (counts.get(kind) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([value, count]) => ({ count, label: appKindLabel(value), value }))
    .sort((left, right) => left.label.localeCompare(right.label));
}

function siteGroupIconCandidates(instances: InstanceModel[]) {
  return uniqueStrings(instances.flatMap((instance) => instance.iconUrls));
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

function initials(name: string) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) {
    return "AG";
  }
  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase();
  }
  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
}

function userInitials(user?: HubUser) {
  return initials(user?.display_name || user?.email || "Aegrail");
}

function timelineVolumeData(events: TimelineEvent[]) {
  const buckets = new Map<string, number>();
  for (const event of events) {
    const date = new Date(event.event_time);
    if (Number.isNaN(date.getTime())) {
      continue;
    }
    const label = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(date);
    buckets.set(label, (buckets.get(label) ?? 0) + 1);
  }
  return Array.from(buckets.entries()).slice(-12).map(([label, value]) => ({ label, value }));
}

function findingsTrendData(findings: HubFinding[]) {
  const buckets = new Map<string, number>();
  for (const finding of findings) {
    const date = new Date(finding.last_event_at);
    if (Number.isNaN(date.getTime())) {
      continue;
    }
    const label = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(date);
    buckets.set(label, (buckets.get(label) ?? 0) + 1);
  }
  return Array.from(buckets.entries()).slice(-7).map(([label, value]) => ({ label, value }));
}

function eventSourceRows(events: TimelineEvent[]) {
  const counts = new Map<string, number>();
  for (const event of events) {
    const source = eventSourceLabel(event.type);
    counts.set(source, (counts.get(source) ?? 0) + 1);
  }
  const total = events.length || 1;
  return Array.from(counts.entries())
    .map(([name, value]) => ({ name, percent: percentOf(value, total), value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 7);
}

function topFindingTypeRows(findings: HubFinding[], ruleById: Map<string, RuleDefinition>) {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const label = ruleById.get(finding.rule_id)?.category || finding.rule_id || "Unknown";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 6);
}

function topDomainRows(scripts: BrowserScript[]) {
  const counts = new Map<string, number>();
  for (const script of scripts) {
    const domain = script.domain || "inline";
    counts.set(domain, (counts.get(domain) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 6);
}

function deploymentTrendData(deployments: Deployment[]) {
  const buckets = new Map<string, number>();
  for (const deployment of deployments) {
    const date = new Date(deployment.started_at);
    if (Number.isNaN(date.getTime())) {
      continue;
    }
    const label = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(date);
    buckets.set(label, (buckets.get(label) ?? 0) + 1);
  }
  return Array.from(buckets.entries()).slice(-7).map(([label, value]) => ({ label, value }));
}

function deploymentSiteRows(rows: Array<{ deployment: Deployment; instance: InstanceModel }>) {
  const counts = new Map<string, number>();
  for (const { instance } of rows) {
    counts.set(instance.projectName, (counts.get(instance.projectName) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 6);
}

function reportModelRows(reports: ModelAnalysisReport[]) {
  const counts = new Map<string, number>();
  for (const report of reports) {
    const label = report.model_name || report.model_provider || "unknown";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 6);
}

function averageReportDuration(reports: ModelAnalysisReport[]) {
  const durations = reports.map((report) => report.total_duration_millis ?? 0).filter((value) => value > 0);
  if (durations.length === 0) {
    return "unknown";
  }
  const average = durations.reduce((total, value) => total + value, 0) / durations.length;
  if (average >= 1000) {
    return `${(average / 1000).toFixed(1)}s`;
  }
  return `${Math.round(average)}ms`;
}

function exportDeployments(rows: Array<{ deployment: Deployment; instance: InstanceModel }>) {
  downloadCsv(
    "aegrail-deployments.csv",
    ["Company", "Site", "Instance", "Version", "Commit", "Actor", "Started", "Status", "Open Findings"],
    rows.map(({ deployment, instance }) => [
      instance.companyName,
      instance.projectName,
      instance.environmentName,
      deployment.version,
      shortSha(deployment.commit_sha),
      deployment.actor || "unknown",
      formatDate(deployment.started_at),
      deployment.finished_at ? "completed" : "active",
      instance.openFindings
    ])
  );
}

function exportReports(rows: Array<{ report: ModelAnalysisReport; instance: InstanceModel }>, findingTitleById: Map<string, string>) {
  downloadCsv(
    "aegrail-reports.csv",
    ["Company", "Site", "Instance", "Status", "Model", "Template", "Linked Findings", "Evidence Bundle", "Generated"],
    rows.map(({ instance, report }) => [
      instance.companyName,
      instance.projectName,
      instance.environmentName,
      report.status,
      report.model_name || report.model_provider || "unknown",
      `${report.prompt_template_id} ${report.prompt_template_version}`,
      report.source_finding_ids.map((id) => findingTitleById.get(id) ?? id).join("; "),
      shortSha(report.evidence_bundle_sha256),
      formatDate(report.generated_at)
    ])
  );
}

function exportCoverage(
  instances: InstanceModel[],
  columns: {
    agent: boolean;
    browser: boolean;
    config: boolean;
    database: boolean;
    files: boolean;
    findings: boolean;
    lastSignal: boolean;
  }
) {
  const headers = ["Company", "Site", "Instance"];
  if (columns.files) headers.push("Files");
  if (columns.database) headers.push("Database");
  if (columns.browser) headers.push("Browser");
  if (columns.config) headers.push("Config");
  if (columns.agent) headers.push("Agent status");
  if (columns.findings) headers.push("Open findings");
  if (columns.lastSignal) headers.push("Last signal");

  downloadCsv(
    "aegrail-coverage.csv",
    headers,
    instances.map((instance) => {
      const collectors = new Map(instance.collectors.map((collector) => [collector.key, collector]));
      const row: Array<number | string> = [instance.companyName, instance.projectName, `${instance.environmentName} / ${instance.appName}`];
      if (columns.files) row.push(collectorExportText(collectors.get("files")));
      if (columns.database) row.push(collectorExportText(collectors.get("database")));
      if (columns.browser) row.push(collectorExportText(collectors.get("browser")));
      if (columns.config) row.push(collectorExportText(collectors.get("config")));
      if (columns.agent) row.push(instance.status);
      if (columns.findings) row.push(instance.openFindings);
      if (columns.lastSignal) row.push(formatDate(instance.lastSignalAt));
      return row;
    })
  );
}

function exportAgents(instances: InstanceModel[]) {
  downloadCsv(
    "aegrail-agents.csv",
    ["Agent ID", "Company", "Site", "Instance", "Host", "App kind", "Status", "Collectors", "Queue state", "Last signal", "Open findings"],
    instances.map((instance) => [
      instance.data.topology.data.agents[0]?.agent_id || `agt_${instance.projectSlug}`,
      instance.companyName,
      instance.projectName,
      instance.environmentName,
      instance.data.topology.data.hosts[0]?.hostname || instance.projectSlug,
      appKindLabel(instance.appKind),
      instance.status,
      instance.collectors.map((collector) => `${collector.label}:${collector.status}`).join("; "),
      instance.collectors.some((collector) => collector.status === "missing") ? "backing_up" : "normal",
      formatDate(instance.lastSignalAt),
      instance.openFindings
    ])
  );
}

function collectorExportText(collector?: InstanceModel["collectors"][number]) {
  if (!collector) {
    return "n/a";
  }
  return `${collector.status}${collector.lastSeenAt ? ` / ${formatDate(collector.lastSeenAt)}` : ""}`;
}

function downloadCsv(filename: string, headers: string[], rows: Array<Array<number | string>>) {
  const csv = [headers, ...rows]
    .map((row) => row.map((value) => csvValue(String(value))).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function csvValue(value: string) {
  return /[",\n]/.test(value) ? `"${value.replaceAll("\"", "\"\"")}"` : value;
}

function averageLastSignal(instances: InstanceModel[]) {
  const ages = instances
    .map((instance) => instance.lastSignalAt ? Date.now() - new Date(instance.lastSignalAt).getTime() : 0)
    .filter((age) => age > 0);
  if (ages.length === 0) {
    return "unknown";
  }
  const averageMs = ages.reduce((total, age) => total + age, 0) / ages.length;
  const minutes = Math.max(1, Math.round(averageMs / 60000));
  if (minutes >= 60) {
    return `${Math.round(minutes / 60)}h`;
  }
  return `${minutes}m`;
}

function eventSourceLabel(type: string) {
  if (type.startsWith("db.")) {
    return "Database";
  }
  if (type.startsWith("file.")) {
    return "Files";
  }
  if (type.startsWith("browser.")) {
    return "Browser Script";
  }
  if (type.startsWith("agent.")) {
    return "Agent";
  }
  if (type.startsWith("deploy")) {
    return "Deployment";
  }
  return "Web App";
}

function capitalize(value: string) {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

function Overview({
  data,
  findings,
  lastLoadedAt,
  onSelectFinding,
  onView,
  ruleById,
  summary
}: {
  data: DashboardData;
  findings: HubFinding[];
  lastLoadedAt: Date | null;
  onSelectFinding: (id: string) => void;
  onView: (view: ViewKey) => void;
  ruleById: Map<string, RuleDefinition>;
  summary: ReturnType<typeof summarize>;
}) {
  const urgentFinding = findings.find((finding) => finding.status === "open" && ["critical", "high"].includes(finding.severity));

  return (
    <div className="view-stack">
      {urgentFinding && <IncidentBanner finding={urgentFinding} onSelect={onSelectFinding} ruleById={ruleById} />}
      <section className="metric-grid">
        <Metric label="Open findings" value={summary.openFindings} tone={summary.openFindings > 0 ? "danger" : "ok"} icon={AlertTriangle} />
        <Metric label="High risk" value={summary.highRiskFindings} tone={summary.highRiskFindings > 0 ? "warning" : "muted"} icon={ShieldHalf} />
        <Metric label="Covered sites" value={summary.coveredSites} tone="ok" icon={MonitorCog} />
        <Metric label="Active agents" value={summary.activeAgents} tone="accent" icon={TerminalSquare} />
        <Metric label="Script domains" value={summary.scriptDomains} tone="teal" icon={Bug} />
        <Metric label="Reports" value={data.reports.data.length} tone="muted" icon={FileText} />
      </section>

      <section className="content-grid overview-grid">
        <div className="panel">
          <PanelTitle icon={ListChecks} title="Finding Queue" action="View all" onAction={() => onView("findings")} />
          <FindingList findings={findings.slice(0, 5)} ruleById={ruleById} onSelect={onSelectFinding} />
        </div>
        <div className="panel">
          <PanelTitle icon={Activity} title="Recent Timeline" action="Open timeline" onAction={() => onView("timeline")} />
          <EventList events={data.timeline.data.slice(0, 7)} />
        </div>
        <div className="panel">
          <PanelTitle icon={Server} title="Estate Coverage" action="Open coverage" onAction={() => onView("coverage")} />
          <CoverageMatrix coverage={data.coverage.data} />
        </div>
        <div className="panel">
          <PanelTitle icon={Sparkles} title="Reports" action="Open reports" onAction={() => onView("reports")} />
          <ReportList reports={data.reports.data.slice(0, 5)} />
        </div>
      </section>

      <footer className="dashboard-foot">
        <span>{lastLoadedAt ? `Refreshed ${formatRelative(lastLoadedAt.toISOString())}` : "Not refreshed yet"}</span>
        <span>Auto-refresh every {Math.round(autoRefreshIntervalMs / 1000)}s</span>
        <span>{summary.totalEvents} timeline events in the last 24 hours</span>
      </footer>
    </div>
  );
}

function IncidentBanner({
  finding,
  onSelect,
  ruleById
}: {
  finding: HubFinding;
  onSelect: (id: string) => void;
  ruleById: Map<string, RuleDefinition>;
}) {
  return (
    <section className={`incident-banner ${finding.severity}`} aria-live="polite">
      <div className="incident-icon">
        <AlertTriangle size={22} aria-hidden="true" />
      </div>
      <div className="incident-copy">
        <span>{finding.severity} / {formatDate(finding.last_event_at)} / risk {riskLabel(finding)}</span>
        <strong>{finding.title}</strong>
        <p>{finding.summary || ruleById.get(finding.rule_id)?.title || finding.rule_id}</p>
      </div>
      <button className="btn btn-danger" type="button" onClick={() => onSelect(finding.id)}>
        <Eye size={16} aria-hidden="true" />
        Open finding
      </button>
    </section>
  );
}

function FindingsView({
  actionError,
  actionLoading,
  actionState,
  filters,
  findings,
  onActionChange,
  onAllowScript,
  onFiltersChange,
  onSelect,
  onStatus,
  ruleById,
  selectedFinding,
  totalFindings
}: {
  actionError: string;
  actionLoading: boolean;
  actionState: ActionState;
  filters: FindingFilters;
  findings: HubFinding[];
  totalFindings: number;
  onActionChange: (state: ActionState) => void;
  onAllowScript: (finding: HubFinding) => void;
  onFiltersChange: (filters: FindingFilters) => void;
  onSelect: (id: string) => void;
  onStatus: (finding: HubFinding, status: string) => void;
  ruleById: Map<string, RuleDefinition>;
  selectedFinding?: HubFinding;
}) {
  return (
    <section className="split-view">
      <div className="panel table-panel">
        <div className="table-toolbar">
          <PanelHeading icon={AlertTriangle} title="Findings" />
          <span className="count-pill">{findings.length}/{totalFindings}</span>
        </div>
        <div className="filter-bar">
          <div className="search-field">
            <Search size={16} aria-hidden="true" />
            <input
              aria-label="Search findings"
              className="form-control"
              placeholder="Search title, rule, summary"
              value={filters.query}
              onChange={(event) => onFiltersChange({ ...filters, query: event.target.value })}
            />
          </div>
          <select
            aria-label="Filter severity"
            className="form-select"
            value={filters.severity}
            onChange={(event) => onFiltersChange({ ...filters, severity: event.target.value })}
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select
            aria-label="Filter status"
            className="form-select"
            value={filters.status}
            onChange={(event) => onFiltersChange({ ...filters, status: event.target.value })}
          >
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False positive</option>
          </select>
        </div>
        <div className="table-responsive">
          <table className="table align-middle data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Status</th>
                <th>Last event</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr
                  className={selectedFinding?.id === finding.id ? "selected-row" : ""}
                  key={finding.id}
                  onClick={() => onSelect(finding.id)}
                >
                  <td><SeverityBadge severity={finding.severity} /></td>
                  <td>
                    <button className="table-link" type="button" onClick={() => onSelect(finding.id)}>
                      {finding.title}
                    </button>
                    <div className="muted-line">{ruleById.get(finding.rule_id)?.category ?? finding.rule_id}</div>
                  </td>
                  <td><StatusBadge status={finding.status} /></td>
                  <td>{formatRelative(finding.last_event_at)}</td>
                  <td>{riskLabel(finding)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {findings.length === 0 && <EmptyState icon={ShieldCheck} title="No matching findings" detail="The current filters did not match any returned findings." />}
      </div>

      <aside className="detail-panel">
        {selectedFinding ? (
          <>
            <div className="detail-heading">
              <SeverityBadge severity={selectedFinding.severity} />
              <h2>{selectedFinding.title}</h2>
              <StatusBadge status={selectedFinding.status} />
            </div>
            <p className="detail-summary">{selectedFinding.summary || selectedFinding.description || "No finding summary was returned."}</p>
            <dl className="detail-list">
              <dt>Rule</dt>
              <dd>{selectedFinding.rule_id} / {selectedFinding.rule_version}</dd>
              <dt>Confidence</dt>
              <dd>{selectedFinding.confidence}</dd>
              <dt>Window</dt>
              <dd>{formatDate(selectedFinding.first_event_at)} to {formatDate(selectedFinding.last_event_at)}</dd>
              <dt>Evidence</dt>
              <dd>{selectedFinding.event_ids.length} event{selectedFinding.event_ids.length === 1 ? "" : "s"}</dd>
            </dl>
            <FindingMetadata finding={selectedFinding} />
            <div className="action-box">
              <label className="form-label" htmlFor="finding-actor">Actor</label>
              <input
                className="form-control"
                id="finding-actor"
                value={actionState.actor}
                onChange={(event) => onActionChange({ ...actionState, actor: event.target.value })}
              />
              <label className="form-label" htmlFor="finding-reason">Reason</label>
              <input
                className="form-control"
                id="finding-reason"
                value={actionState.reason}
                onChange={(event) => onActionChange({ ...actionState, reason: event.target.value })}
              />
              <label className="form-label" htmlFor="finding-note">Note</label>
              <textarea
                className="form-control"
                id="finding-note"
                rows={3}
                value={actionState.note}
                onChange={(event) => onActionChange({ ...actionState, note: event.target.value })}
              />
              {actionError && <div className="alert alert-danger compact-alert">{actionError}</div>}
              <div className="button-row">
                <ActionButton icon={Eye} label="Acknowledge" loading={actionLoading} onClick={() => onStatus(selectedFinding, "acknowledged")} />
                <ActionButton icon={CheckCircle2} label="Resolve" loading={actionLoading} onClick={() => onStatus(selectedFinding, "resolved")} />
                <ActionButton icon={XCircle} label="False positive" loading={actionLoading} onClick={() => onStatus(selectedFinding, "false_positive")} />
                {isBrowserDriftFinding(selectedFinding) && (
                  <ActionButton icon={ShieldCheck} label="Allow script" loading={actionLoading} onClick={() => onAllowScript(selectedFinding)} />
                )}
              </div>
            </div>
          </>
        ) : (
          <EmptyState icon={Search} title="No selection" detail="Select a finding to inspect it." />
        )}
      </aside>
    </section>
  );
}

function ActivityTimelinePage({ estate }: { estate: EstateModel }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const events = estate.instances.flatMap((instance) => instance.data.timeline.data).sort(sortEventsNewest);
  const normalizedQuery = query.trim().toLowerCase();
  const filteredEvents = events.filter((event) => {
    const queryMatch = !normalizedQuery ||
      [event.type, event.message, event.host, event.hostname, event.target, event.agent, eventSourceLabel(event.type)]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(normalizedQuery));
    const severityMatch = severity === "all" || event.severity === severity;
    const sourceMatch = source === "all" || eventSourceLabel(event.type) === source;
    return queryMatch && severityMatch && sourceMatch;
  });
  const sourceRows = eventSourceRows(filteredEvents);
  return (
    <div className="view-stack spec-page">
      <section className="panel spec-panel event-volume-card">
        <div>
          <p className="eyebrow">Event volume</p>
          <h2>{filteredEvents.length}</h2>
          <span>{events.length} events in current window</span>
        </div>
        <MiniBarChart data={timelineVolumeData(filteredEvents)} />
      </section>
      <div className="directory-toolbar">
        <div className="search-field directory-search">
          <Search size={16} aria-hidden="true" />
          <input className="form-control" placeholder="Search events..." value={query} onChange={(event) => setQuery(event.target.value)} />
        </div>
        <select className="form-select filter-select" value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Timeline severity">
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select className="form-select filter-select" value={source} onChange={(event) => setSource(event.target.value)} aria-label="Timeline source">
          <option value="all">All sources</option>
          {eventSourceRows(events).map((row) => <option key={row.name} value={row.name}>{row.name}</option>)}
        </select>
      </div>
      <section className="operations-grid">
        <div className="operations-main">
          <TimelineView events={filteredEvents} />
          {filteredEvents.length >= 3 && (
            <section className="panel spec-panel incident-chain">
              <PanelTitle icon={GitBranch} title="Correlated incident chain" />
              <div className="chain-steps">
                {filteredEvents.slice(0, 5).map((event) => (
                  <div className="chain-step" key={event.id}>
                    <SeverityBadge severity={event.severity} />
                    <strong>{event.type}</strong>
                    <small>{eventSourceLabel(event.type)} / {event.target}</small>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={Activity} title="Signal volume" />
            <LegendList data={severityChartData(filteredEvents)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Boxes} title="Activity by source" />
            <BarRows rows={sourceRows.map((row) => ({ label: row.name, value: row.value }))} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={AlertTriangle} title="Recent correlated incidents" />
            <EventList events={filteredEvents.filter((event) => ["critical", "high"].includes(event.severity)).slice(0, 4)} />
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function TimelineView({ events }: { events: TimelineEvent[] }) {
  return (
    <section className="panel table-panel">
      <PanelTitle icon={Clock3} title="Timeline" />
      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Severity</th>
              <th>Event</th>
              <th>Host</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id}>
                <td>{formatDate(event.event_time)}</td>
                <td><SeverityBadge severity={event.severity} /></td>
                <td>
                  <div className="strong-line">{event.type}</div>
                  <div className="muted-line">{event.message}</div>
                </td>
                <td>{event.host}<div className="muted-line">{event.agent}</div></td>
                <td className="wrap-cell">{event.target}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {events.length === 0 && <EmptyState icon={Clock3} title="No timeline events" detail="The Hub returned no events for the current window." />}
    </section>
  );
}

function InventoryView({ data }: { data: DashboardData }) {
  const topology = data.topology.data;
  return (
    <div className="view-stack">
      <section className="metric-grid four">
        <Metric label="Apps" value={topology.apps.length} tone="accent" icon={Boxes} />
        <Metric label="Services" value={topology.services.length} tone="teal" icon={DatabaseZap} />
        <Metric label="Hosts" value={topology.hosts.length} tone="muted" icon={Server} />
        <Metric label="Agents" value={topology.agents.length} tone="ok" icon={TerminalSquare} />
      </section>
      <section className="content-grid two">
        <div className="panel">
          <PanelTitle icon={Boxes} title="Apps" />
          <SimpleRows rows={topology.apps.map((app) => [app.name || app.slug, app.kind, app.slug])} />
        </div>
        <div className="panel">
          <PanelTitle icon={DatabaseZap} title="Services" />
          <SimpleRows rows={topology.services.map((service) => [service.name || service.slug, service.role, service.slug])} />
        </div>
        <div className="panel">
          <PanelTitle icon={Server} title="Hosts" />
          <HostRows hosts={topology.hosts} />
        </div>
        <div className="panel">
          <PanelTitle icon={TerminalSquare} title="Agents" />
          <AgentRows agents={topology.agents} hosts={topology.hosts} />
        </div>
      </section>
    </div>
  );
}

function SitesView({ coverage }: { coverage: CoverageRecord[] }) {
  return (
    <section className="panel table-panel">
      <PanelTitle icon={MonitorCog} title="Site Coverage" />
      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>Site</th>
              <th>Kind</th>
              <th>Coverage</th>
              <th>Host</th>
              <th>Reported</th>
            </tr>
          </thead>
          <tbody>
            {coverage.map((record) => (
              <tr key={record.event_id}>
                <td>{record.site}</td>
                <td>{record.site_kind}</td>
                <td><CoverageBadge level={record.coverage_level} /></td>
                <td>{record.host}<div className="muted-line">{record.agent}</div></td>
                <td>{formatRelative(record.reported_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {coverage.length === 0 && <EmptyState icon={MonitorCog} title="No coverage records" detail="No site coverage events were returned for the current window." />}
    </section>
  );
}

function AgentsCollectorHealthPage({ estate }: { estate: EstateModel }) {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const instances = normalizedQuery
    ? estate.instances.filter((instance) =>
        [
          instance.companyName,
          instance.projectName,
          instance.environmentName,
          instance.appName,
          instance.data.topology.data.agents[0]?.agent_id,
          instance.data.topology.data.hosts[0]?.hostname
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery))
      )
    : estate.instances;
  const healthy = estate.instances.filter((instance) => instance.activeAgentCount > 0 && instance.status !== "critical").length;
  const stale = estate.instances.filter((instance) => instance.staleAgents > 0).length;
  const failed = estate.instances.filter((instance) => instance.activeAgentCount === 0 && instance.agentCount > 0).length;
  const missingCollectors = estate.instances.reduce((sum, instance) => sum + instance.collectors.filter((collector) => collector.status === "missing").length, 0);
  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip">
        <KpiCard icon={TerminalSquare} label="Total Agents" value={estate.totals.activeAgents} tone="blue" trend="derived active signals" />
        <KpiCard icon={ShieldCheck} label="Healthy" value={healthy} tone="green" trend={`${percentOf(healthy, estate.totals.instances)}% of instances`} />
        <KpiCard icon={Clock3} label="Stale" value={stale} tone="orange" trend="no fresh signal" />
        <KpiCard icon={AlertTriangle} label="Failed" value={failed} tone="red" trend="no active signal" />
        <KpiCard icon={DatabaseZap} label="Queue Lag" value={missingCollectors} tone="purple" trend="missing collectors" />
        <KpiCard icon={Clock3} label="Avg Last Signal" value={averageLastSignal(estate.instances)} tone="blue" trend="current window" />
      </section>
      <section className="operations-grid">
        <div className="operations-main">
          <section className="panel table-panel">
            <div className="table-toolbar">
              <PanelHeading icon={TerminalSquare} title="Agents & Collector Health" />
              <div className="table-actions">
                <div className="search-field compact"><Search size={16} /><input className="form-control" placeholder="Search agents..." value={query} onChange={(event) => setQuery(event.target.value)} /></div>
                <button className="btn btn-outline-secondary" type="button" onClick={() => exportAgents(instances)}><Download size={16} /> Export</button>
              </div>
            </div>
            <div className="table-responsive">
              <table className="table align-middle data-table">
                <thead>
                  <tr>
                    <th>Agent ID</th>
                    <th>Company</th>
                    <th>Host</th>
                    <th>Coverage Scope</th>
                    <th>Agent Status</th>
                    <th>Collectors Enabled</th>
                    <th>Queue State</th>
                    <th>Last Signal</th>
                    <th>Open Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {instances.map((instance) => (
                    <tr key={instance.key}>
                      <td>{instance.data.topology.data.agents[0]?.agent_id || `agt_${instance.projectSlug}`}</td>
                      <td><AvatarLabel iconUrls={instance.iconUrls} name={instance.companyName} /><div className="muted-line">{instance.companyName}</div></td>
                      <td>{instance.data.topology.data.hosts[0]?.hostname || instance.projectSlug}</td>
                      <td>{appKindLabel(instance.appKind)}</td>
                      <td><HealthBadge status={instance.status} /></td>
                      <td><CollectorPills collectors={instance.collectors} /></td>
                      <td><StatusBadge status={instance.collectors.some((collector) => collector.status === "missing") ? "backing_up" : "normal"} /></td>
                      <td>{formatRelative(instance.lastSignalAt)}</td>
                      <td>{instance.openFindings}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {instances.length === 0 && <EmptyState icon={TerminalSquare} title="No agents match" detail="No collector agents match the current search and top filters." />}
          </section>
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={TerminalSquare} title="Agent health distribution" />
            <DonutChart centerLabel="Total" centerValue={String(estate.totals.instances)} data={statusChartData(estate.instances)} />
            <LegendList data={statusChartData(estate.instances)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={GitBranch} title="Version rollout" />
            <DonutChart centerLabel="Total" centerValue={String(estate.totals.instances)} data={versionChartData(estate)} />
            <LegendList data={versionChartData(estate)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Clock3} title="Stale agents needing attention" />
            <CompactInstanceList instances={estate.instances.filter((instance) => instance.status !== "healthy").slice(0, 5)} onInstance={() => undefined} />
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function AgentsView({ agents, hosts }: { agents: Agent[]; hosts: Host[] }) {
  return (
    <section className="panel table-panel">
      <PanelTitle icon={TerminalSquare} title="Agents" />
      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Host</th>
              <th>Version</th>
              <th>Last seen</th>
              <th>Fingerprint</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id}>
                <td>{agent.agent_id}</td>
                <td>{hostLabel(hosts, agent.host_id)}</td>
                <td>{agent.version || "unknown"}</td>
                <td>{agent.last_seen_at ? formatRelative(agent.last_seen_at) : "never"}</td>
                <td className="mono-cell">{agent.fingerprint}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {agents.length === 0 && <EmptyState icon={TerminalSquare} title="No agents" detail="No agents were returned for the selected environment." />}
    </section>
  );
}

function BrowserScriptsPage({
  actionState,
  allowlist,
  findings,
  onAllowlistCreated,
  scope,
  scripts
}: {
  actionState: ActionState;
  allowlist: BrowserAllowlistEntry[];
  findings: HubFinding[];
  onAllowlistCreated: () => void;
  scope: ApiScope;
  scripts: BrowserScript[];
}) {
  const [activeTab, setActiveTab] = useState<"scripts" | "drift" | "allowlist">("scripts");
  const [allowlistKind, setAllowlistKind] = useState("domain");
  const [allowlistPage, setAllowlistPage] = useState("");
  const [allowlistValue, setAllowlistValue] = useState("");
  const [quickAllowError, setQuickAllowError] = useState("");
  const [quickAllowLoading, setQuickAllowLoading] = useState(false);
  const [quickAllowMessage, setQuickAllowMessage] = useState("");
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const domains = topDomainRows(scripts);
  const driftFindings = findings.filter(isBrowserDriftFinding);
  const filteredScripts = normalizedQuery
    ? scripts.filter((script) =>
        [script.domain, script.url_redacted, script.path, script.sha256, script.target, script.host, script.source_type]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery))
      )
    : scripts;
  const filteredAllowlist = normalizedQuery
    ? allowlist.filter((entry) =>
        [entry.kind, entry.value, entry.page_url, entry.status, entry.approved_by]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery))
      )
    : allowlist;
  const filteredDriftFindings = normalizedQuery
    ? driftFindings.filter((finding) =>
        [finding.title, finding.rule_id, finding.summary, finding.description]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery))
      )
    : driftFindings;
  const newDomains = new Set(scripts.map((script) => script.domain).filter(Boolean)).size;

  async function createQuickAllowlistEntry() {
    setQuickAllowError("");
    setQuickAllowMessage("");
    setQuickAllowLoading(true);
    try {
      await createBrowserScriptAllowlistEntry(scope, {
        approved_by: actionState.actor,
        kind: allowlistKind,
        page_url: allowlistPage,
        reason: actionState.reason || "dashboard quick allowlist",
        value: allowlistValue
      });
      setAllowlistValue("");
      setAllowlistPage("");
      setActiveTab("allowlist");
      setQuickAllowMessage("Allowlist entry created.");
      onAllowlistCreated();
    } catch (error) {
      setQuickAllowError(error instanceof Error ? error.message : String(error));
    } finally {
      setQuickAllowLoading(false);
    }
  }

  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip four">
        <KpiCard icon={Code2} label="Observed Scripts" value={scripts.length} tone="blue" trend="current window" />
        <KpiCard icon={Building2} label="New Domains" value={newDomains} tone="purple" trend="unique domains" />
        <KpiCard icon={ShieldCheck} label="Allowlisted Items" value={allowlist.length} tone="green" trend="active policy" />
        <KpiCard icon={AlertTriangle} label="Drift Findings" value={driftFindings.length} tone="orange" trend="linked findings" />
      </section>
      <div className="tab-strip">
        <button className={activeTab === "scripts" ? "active" : ""} type="button" onClick={() => setActiveTab("scripts")}>Observed Scripts <span>{scripts.length}</span></button>
        <button className={activeTab === "drift" ? "active" : ""} type="button" onClick={() => setActiveTab("drift")}>Drift Findings <span>{driftFindings.length}</span></button>
        <button className={activeTab === "allowlist" ? "active" : ""} type="button" onClick={() => setActiveTab("allowlist")}>Allowlist <span>{allowlist.length}</span></button>
      </div>
      <section className="operations-grid">
        <div className="operations-main">
          <div className="panel table-panel">
            <div className="table-toolbar">
              <PanelHeading icon={activeTab === "allowlist" ? ShieldCheck : activeTab === "drift" ? AlertTriangle : Bug} title={activeTab === "allowlist" ? "Allowlist" : activeTab === "drift" ? "Drift Findings" : "Observed Scripts"} />
              <div className="search-field compact">
                <Search size={16} aria-hidden="true" />
                <input className="form-control" placeholder="Search scripts, domains, findings..." value={query} onChange={(event) => setQuery(event.target.value)} />
              </div>
            </div>
            {activeTab === "scripts" && <BrowserScriptsTable scripts={filteredScripts} />}
            {activeTab === "drift" && <BrowserDriftFindingsTable findings={filteredDriftFindings} />}
            {activeTab === "allowlist" && <AllowlistTable allowlist={filteredAllowlist} />}
          </div>
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={Activity} title="Script drift trends" />
            <MiniLineChart data={findingsTrendData(driftFindings)} stroke="#f97316" />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Building2} title="Top external domains" />
            <BarRows rows={domains} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={ShieldCheck} title="Quick allowlist" />
            <div className="quick-form">
              <div className="segmented-control">
                <button className={allowlistKind === "domain" ? "active" : ""} type="button" onClick={() => setAllowlistKind("domain")}>By domain</button>
                <button className={allowlistKind === "tag_manager_id" ? "active" : ""} type="button" onClick={() => setAllowlistKind("tag_manager_id")}>By tag</button>
                <button className={allowlistKind === "inline_hash" ? "active" : ""} type="button" onClick={() => setAllowlistKind("inline_hash")}>By hash</button>
              </div>
              <input className="form-control" placeholder={allowlistKind === "domain" ? "e.g. cdn.example.com" : allowlistKind === "tag_manager_id" ? "e.g. GTM-XXXX" : "e.g. sha256..."} value={allowlistValue} onChange={(event) => setAllowlistValue(event.target.value)} />
              <input className="form-control" placeholder="Optional page URL scope" value={allowlistPage} onChange={(event) => setAllowlistPage(event.target.value)} />
              {quickAllowError && <div className="alert alert-danger compact-alert">{quickAllowError}</div>}
              {quickAllowMessage && <div className="alert alert-success compact-alert">{quickAllowMessage}</div>}
              <button className="btn btn-primary" type="button" disabled={quickAllowLoading || allowlistValue.trim() === ""} onClick={() => void createQuickAllowlistEntry()}>
                {quickAllowLoading ? <Loader2 size={16} className="spin" /> : <ShieldCheck size={16} aria-hidden="true" />}
                Allowlist {allowlistKind === "domain" ? "domain" : allowlistKind === "tag_manager_id" ? "tag" : "hash"}
              </button>
            </div>
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function BrowserView({ allowlist, scripts }: { allowlist: BrowserAllowlistEntry[]; scripts: BrowserScript[] }) {
  return (
    <div className="content-grid two">
      <section className="panel table-panel">
        <PanelTitle icon={Bug} title="Observed Scripts" />
        <BrowserScriptsTable scripts={scripts} />
      </section>
      <section className="panel table-panel">
        <PanelTitle icon={ShieldCheck} title="Allowlist" />
        <AllowlistTable allowlist={allowlist} />
      </section>
    </div>
  );
}

function BrowserScriptsTable({ scripts }: { scripts: BrowserScript[] }) {
  return (
    <>
      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Source</th>
              <th>Host</th>
              <th>Observed</th>
            </tr>
          </thead>
          <tbody>
            {scripts.map((script) => (
              <tr key={script.event_id}>
                <td>{script.domain || "inline"}<div className="muted-line">{script.source_type || script.type}</div></td>
                <td className="wrap-cell">{script.url_redacted || script.path || script.sha256 || script.target}</td>
                <td>{script.host}</td>
                <td>{formatRelative(script.event_time)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {scripts.length === 0 && <EmptyState icon={Bug} title="No browser scripts" detail="No browser script observations were returned." />}
    </>
  );
}

function BrowserDriftFindingsTable({ findings }: { findings: HubFinding[] }) {
  return (
    <>
      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.id}>
                <td>{finding.title}<div className="muted-line">{finding.rule_id}</div></td>
                <td><SeverityBadge severity={finding.severity} /></td>
                <td><StatusBadge status={finding.status} /></td>
                <td>{formatRelative(finding.last_event_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {findings.length === 0 && <EmptyState icon={ShieldCheck} title="No script drift findings" detail="No browser-script drift findings match this view." />}
    </>
  );
}

function AllowlistTable({ allowlist }: { allowlist: BrowserAllowlistEntry[] }) {
  return (
    <>
      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>Kind</th>
              <th>Value</th>
              <th>Status</th>
              <th>Approved</th>
            </tr>
          </thead>
          <tbody>
            {allowlist.map((entry) => (
              <tr key={entry.id}>
                <td>{entry.kind}</td>
                <td className="wrap-cell">{entry.value}<div className="muted-line">{entry.page_url}</div></td>
                <td><StatusBadge status={entry.status} /></td>
                <td>{entry.approved_by || "unknown"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {allowlist.length === 0 && <EmptyState icon={ShieldCheck} title="No allowlist entries" detail="No browser script allowlist entries were returned." />}
    </>
  );
}

function DeploymentsView({ estate }: { estate: EstateModel }) {
  const [query, setQuery] = useState("");
  const rows = estate.instances
    .flatMap((instance) => instance.data.deployments.data.map((deployment) => ({ deployment, instance })))
    .sort((left, right) => sortDeploymentsNewest(left.deployment, right.deployment));
  const normalizedQuery = query.trim().toLowerCase();
  const filteredRows = normalizedQuery
    ? rows.filter(({ deployment, instance }) =>
        [
          instance.companyName,
          instance.projectName,
          instance.environmentName,
          instance.appName,
          deployment.version,
          deployment.commit_sha,
          deployment.actor,
          deployment.finished_at ? "completed" : "active"
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery))
      )
    : rows;
  const completed = rows.filter((row) => row.deployment.finished_at).length;
  const active = rows.length - completed;
  const impactedSites = new Set(rows.map((row) => `${row.instance.companySlug}:${row.instance.projectSlug}`)).size;
  const postDeploymentFindings = rows.reduce((total, row) =>
    total + row.instance.data.findings.data.filter((finding) =>
      new Date(finding.first_event_at).getTime() >= new Date(row.deployment.started_at).getTime()
    ).length,
    0
  );
  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip five">
        <KpiCard icon={GitBranch} label="Deployments" value={rows.length} tone="blue" trend="current estate window" />
        <KpiCard icon={Activity} label="Active" value={active} tone={active > 0 ? "orange" : "green"} trend="unfinished markers" />
        <KpiCard icon={CheckCircle2} label="Completed" value={completed} tone="green" trend={`${percentOf(completed, rows.length)}% complete`} />
        <KpiCard icon={MonitorCog} label="Impacted sites" value={impactedSites} tone="purple" trend="unique projects" />
        <KpiCard icon={AlertTriangle} label="Post-deploy findings" value={postDeploymentFindings} tone={postDeploymentFindings > 0 ? "orange" : "green"} trend="first seen after deploy" />
      </section>
      <section className="operations-grid">
        <div className="operations-main">
          <section className="panel table-panel">
            <div className="table-toolbar">
              <PanelHeading icon={GitBranch} title="Deployment Ledger" />
              <div className="table-actions">
                <div className="search-field compact"><Search size={16} aria-hidden="true" /><input className="form-control" placeholder="Search deployments..." value={query} onChange={(event) => setQuery(event.target.value)} /></div>
                <button className="btn btn-outline-secondary" type="button" onClick={() => exportDeployments(filteredRows)}><Download size={16} /> Export</button>
              </div>
            </div>
            <div className="table-responsive">
              <table className="table align-middle data-table">
                <thead>
                  <tr>
                    <th>Company / Site</th>
                    <th>Instance</th>
                    <th>Version</th>
                    <th>Commit</th>
                    <th>Actor</th>
                    <th>Started</th>
                    <th>Status</th>
                    <th>Open Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRows.map(({ deployment, instance }) => (
                    <tr key={`${instance.key}:${deployment.id}`}>
                      <td><AvatarLabel iconUrls={instance.iconUrls} name={instance.companyName} /><div className="muted-line">{instance.projectName}</div></td>
                      <td>{instance.environmentName}<div className="muted-line">{instance.appName}</div></td>
                      <td>{deployment.version}</td>
                      <td className="mono-cell">{shortSha(deployment.commit_sha)}</td>
                      <td>{deployment.actor || "unknown"}</td>
                      <td>{formatRelative(deployment.started_at)}</td>
                      <td><StatusBadge status={deployment.finished_at ? "completed" : "active"} /></td>
                      <td>{instance.openFindings}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filteredRows.length === 0 && <EmptyState icon={GitBranch} title="No deployments" detail="No deployment markers match the current search and filters." />}
          </section>
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={Activity} title="Deployment volume" />
            <MiniLineChart data={deploymentTrendData(rows.map((row) => row.deployment))} stroke="#126dff" />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Building2} title="Impacted sites" />
            <BarRows rows={deploymentSiteRows(rows)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={AlertTriangle} title="Sites with findings" />
            <CompactInstanceList instances={estate.instances.filter((instance) => instance.openFindings > 0).slice(0, 5)} onInstance={() => undefined} />
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function ReportsView({ estate, ruleById }: { estate: EstateModel; ruleById: Map<string, RuleDefinition> }) {
  const [query, setQuery] = useState("");
  const reports = estate.instances.flatMap((instance) => instance.data.reports.data.map((report) => ({ instance, report })))
    .sort((left, right) => new Date(right.report.generated_at).getTime() - new Date(left.report.generated_at).getTime());
  const findings = estate.instances.flatMap((instance) => instance.data.findings.data);
  const findingTitleById = new Map(findings.map((finding) => [finding.id, finding.title]));
  const normalizedQuery = query.trim().toLowerCase();
  const filteredReports = normalizedQuery
    ? reports.filter(({ instance, report }) =>
        [
          instance.companyName,
          instance.projectName,
          instance.environmentName,
          report.status,
          report.model_name,
          report.model_provider,
          report.prompt_template_id,
          report.prompt_template_version,
          report.source_finding_ids.map((id) => findingTitleById.get(id) ?? id).join(" ")
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery))
      )
    : reports;
  const successful = reports.filter(({ report }) => report.status === "completed" || report.status === "succeeded").length;
  const failed = reports.filter(({ report }) => report.status === "failed" || report.error).length;
  const linkedFindings = new Set(reports.flatMap(({ report }) => report.source_finding_ids)).size;
  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip five">
        <KpiCard icon={FileText} label="Reports" value={reports.length} tone="blue" trend="model outputs" />
        <KpiCard icon={CheckCircle2} label="Successful" value={successful} tone="green" trend={`${percentOf(successful, reports.length)}% complete`} />
        <KpiCard icon={AlertTriangle} label="Failed" value={failed} tone={failed > 0 ? "red" : "green"} trend="needs retry" />
        <KpiCard icon={ShieldHalf} label="Linked findings" value={linkedFindings} tone="orange" trend="evidence bundles" />
        <KpiCard icon={Clock3} label="Avg duration" value={averageReportDuration(reports.map(({ report }) => report))} tone="purple" trend="reported by hub" />
      </section>
      <section className="operations-grid">
        <div className="operations-main">
          <section className="panel table-panel">
            <div className="table-toolbar">
              <PanelHeading icon={FileText} title="Report Library" />
              <div className="table-actions">
                <div className="search-field compact"><Search size={16} aria-hidden="true" /><input className="form-control" placeholder="Search reports..." value={query} onChange={(event) => setQuery(event.target.value)} /></div>
                <button className="btn btn-outline-secondary" type="button" onClick={() => exportReports(filteredReports, findingTitleById)}><Download size={16} /> Export</button>
              </div>
            </div>
            <div className="table-responsive">
              <table className="table align-middle data-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Company / Site</th>
                    <th>Model</th>
                    <th>Template</th>
                    <th>Linked Finding</th>
                    <th>Evidence Bundle</th>
                    <th>Generated</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredReports.map(({ instance, report }) => (
                    <tr key={`${instance.key}:${report.id}`}>
                      <td><StatusBadge status={report.status} /></td>
                      <td><AvatarLabel iconUrls={instance.iconUrls} name={instance.companyName} /><div className="muted-line">{instance.projectName}</div></td>
                      <td>{report.model_name || report.model_provider || "unknown"}</td>
                      <td>{report.prompt_template_id}<div className="muted-line">{report.prompt_template_version}</div></td>
                      <td>{report.source_finding_ids.map((id) => findingTitleById.get(id) ?? id).join(", ") || "none"}</td>
                      <td className="mono-cell">{shortSha(report.evidence_bundle_sha256)}</td>
                      <td>{formatRelative(report.generated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filteredReports.length === 0 && <EmptyState icon={FileText} title="No reports" detail="No model analysis reports match the current search and filters." />}
          </section>
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={Sparkles} title="Model usage" />
            <BarRows rows={reportModelRows(reports.map(({ report }) => report))} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={AlertTriangle} title="Top finding types" />
            <BarRows rows={topFindingTypeRows(findings, ruleById)} />
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={ShieldCheck} title="Report queue" />
            <ReportList reports={reports.map(({ report }) => report).slice(0, 6)} />
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function SettingsView({
  actionState,
  defaultScope: fallbackScope,
  draftScope,
  inventoryScopes,
  loading,
  onActionChange,
  onScopeChange,
  onScopeSelect,
  onSubmit,
  scope,
  user
}: {
  actionState: ActionState;
  defaultScope: ApiScope;
  draftScope: ApiScope;
  inventoryScopes: InventoryOrganization[];
  loading: boolean;
  onActionChange: (state: ActionState) => void;
  onScopeChange: (scope: ApiScope) => void;
  onScopeSelect: (scope: ApiScope) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  scope: ApiScope;
  user?: HubUser;
}) {
  const scopeCount = inventoryScopes.reduce((total, organization) =>
    total + organization.projects.reduce((projectTotal, project) =>
      projectTotal + project.environments.reduce((environmentTotal, environment) =>
        environmentTotal + Math.max(environment.apps.length, 1),
        0
      ),
      0
    ),
    0
  );
  const projectCount = inventoryScopes.reduce((total, organization) => total + organization.projects.length, 0);
  const environmentCount = inventoryScopes.reduce((total, organization) =>
    total + organization.projects.reduce((projectTotal, project) => projectTotal + project.environments.length, 0),
    0
  );
  return (
    <div className="view-stack spec-page">
      <section className="kpi-strip four">
        <KpiCard icon={Building2} label="Organizations" value={inventoryScopes.length} tone="blue" trend="available scopes" />
        <KpiCard icon={Boxes} label="Projects" value={projectCount} tone="purple" trend="site groups" />
        <KpiCard icon={Server} label="Environments" value={environmentCount} tone="green" trend="runtime targets" />
        <KpiCard icon={MonitorCog} label="Selectable scopes" value={scopeCount} tone="orange" trend="org/project/env/app" />
      </section>
      <section className="operations-grid">
        <div className="operations-main">
          <section className="panel">
            <PanelTitle icon={Filter} title="Dashboard Scope" />
            <form className="settings-form" onSubmit={onSubmit}>
              <TextInput label="Hub base URL" value={draftScope.baseUrl} placeholder="Relative to current origin" onChange={(baseUrl) => onScopeChange({ ...draftScope, baseUrl })} />
              <TextInput label="Organization" value={draftScope.org} onChange={(org) => onScopeChange({ ...draftScope, org })} />
              <TextInput label="Project" value={draftScope.project} onChange={(project) => onScopeChange({ ...draftScope, project })} />
              <TextInput label="Environment" value={draftScope.environment} onChange={(environment) => onScopeChange({ ...draftScope, environment })} />
              <TextInput label="App" value={draftScope.app} onChange={(app) => onScopeChange({ ...draftScope, app })} />
              <div className="button-row">
                <button className="btn btn-primary" type="submit" disabled={loading}>
                  {loading ? <Loader2 size={16} className="spin" /> : <Save size={16} aria-hidden="true" />}
                  Save scope
                </button>
                <button className="btn btn-outline-secondary" type="button" onClick={() => onScopeChange(fallbackScope)}>
                  Reset
                </button>
              </div>
            </form>
          </section>
          <section className="panel scope-panel">
            <PanelTitle icon={DatabaseZap} title="Inventory Scopes" />
            <ScopeList
              baseUrl={draftScope.baseUrl}
              organizations={inventoryScopes}
              onSelect={(nextScope) => onScopeSelect(nextScope)}
            />
          </section>
          <UserAccessManager currentUser={user} scope={scope} />
        </div>
        <aside className="right-rail">
          <section className="panel spec-panel">
            <PanelTitle icon={ShieldCheck} title="Triage Defaults" />
            <div className="settings-form">
              <TextInput label="Actor" value={actionState.actor} onChange={(actor) => onActionChange({ ...actionState, actor })} />
              <TextInput label="Reason" value={actionState.reason} onChange={(reason) => onActionChange({ ...actionState, reason })} />
              <label className="form-label" htmlFor="default-note">Note</label>
              <textarea
                className="form-control"
                id="default-note"
                rows={4}
                value={actionState.note}
                onChange={(event) => onActionChange({ ...actionState, note: event.target.value })}
              />
            </div>
          </section>
          <section className="panel spec-panel">
            <PanelTitle icon={Settings} title="Console Behavior" />
            <dl className="detail-list compact">
              <div><dt>Refresh interval</dt><dd>{Math.round(autoRefreshIntervalMs / 1000)}s</dd></div>
              <div><dt>Scope source</dt><dd>Local browser storage</dd></div>
              <div><dt>Privacy</dt><dd>Secrets are not displayed</dd></div>
              <div><dt>Mode</dt><dd>{loading ? "Loading" : "Live"}</dd></div>
            </dl>
          </section>
        </aside>
      </section>
      <ConsoleFooter />
    </div>
  );
}

function UserAccessManager({ currentUser, scope }: { currentUser?: HubUser; scope: ApiScope }) {
  const [users, setUsers] = useState<HubUser[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [savingUserID, setSavingUserID] = useState("");
  const [userError, setUserError] = useState("");
  const [enrollment, setEnrollment] = useState<{ enrollment: HubUserTOTPEnrollment; user: HubUser } | null>(null);
  const [form, setForm] = useState({
    access_level: "operator",
    display_name: "",
    email: "",
    password: "",
    status: "active",
    two_factor_required: true
  });
  const canManageUsers = !currentUser || ["owner", "admin"].includes(currentUser.access_level);

  async function refreshUsers() {
    setLoadingUsers(true);
    setUserError("");
    try {
      setUsers(await loadHubUsers(scope));
    } catch (error) {
      setUserError(error instanceof Error ? error.message : String(error));
    } finally {
      setLoadingUsers(false);
    }
  }

  useEffect(() => {
    if (canManageUsers) {
      void refreshUsers();
    }
  }, [canManageUsers, scope.baseUrl]);

  async function submitUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setUserError("");
    setSavingUserID("new");
    try {
      const user = await createHubUser(scope, form);
      setUsers((current) => upsertHubUser(current, user));
      setForm({ access_level: "operator", display_name: "", email: "", password: "", status: "active", two_factor_required: true });
    } catch (error) {
      setUserError(error instanceof Error ? error.message : String(error));
    } finally {
      setSavingUserID("");
    }
  }

  async function saveUser(user: HubUser, patch: Partial<Pick<HubUser, "access_level" | "display_name" | "status" | "two_factor_required">>) {
    const nextUser = { ...user, ...patch };
    setSavingUserID(user.id);
    setUserError("");
    try {
      const saved = await updateHubUser(scope, user, {
        access_level: nextUser.access_level,
        display_name: nextUser.display_name,
        status: nextUser.status,
        two_factor_required: nextUser.two_factor_required
      });
      setUsers((current) => upsertHubUser(current, saved));
    } catch (error) {
      setUserError(error instanceof Error ? error.message : String(error));
    } finally {
      setSavingUserID("");
    }
  }

  async function enrollUser(user: HubUser) {
    setSavingUserID(user.id);
    setUserError("");
    try {
      const result = await enrollHubUserTOTP(scope, user);
      setEnrollment(result);
      setUsers((current) => upsertHubUser(current, result.user));
    } catch (error) {
      setUserError(error instanceof Error ? error.message : String(error));
    } finally {
      setSavingUserID("");
    }
  }

  return (
    <section className="panel user-access-panel">
      <PanelTitle icon={UserPlus} title="Users & Access" />
      {!canManageUsers ? (
        <EmptyState icon={ShieldCheck} title="Admin access required" detail="User access settings are available to admins and owners." />
      ) : (
      <>
      <form className="user-create-form" onSubmit={submitUser}>
        <TextInput label="Email" value={form.email} placeholder="person@example.com" onChange={(email) => setForm((current) => ({ ...current, email }))} />
        <TextInput label="Name" value={form.display_name} placeholder="Display name" onChange={(display_name) => setForm((current) => ({ ...current, display_name }))} />
        <label>
          Password
          <input
            autoComplete="new-password"
            className="form-control"
            minLength={12}
            required
            type="password"
            value={form.password}
            onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
          />
        </label>
        <label>
          Access level
          <select className="form-select" value={form.access_level} onChange={(event) => setForm((current) => ({ ...current, access_level: event.target.value }))}>
            <option value="owner">Owner</option>
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
        </label>
        <label className="toggle-row">
          <input type="checkbox" checked={form.two_factor_required} onChange={(event) => setForm((current) => ({ ...current, two_factor_required: event.target.checked }))} />
          Require 2FA
        </label>
        <button className="btn btn-primary" type="submit" disabled={savingUserID === "new"}>
          {savingUserID === "new" ? <Loader2 size={16} className="spin" /> : <UserPlus size={16} aria-hidden="true" />}
          Add user
        </button>
      </form>

      {userError && <div className="alert alert-warning compact-alert" role="status"><AlertTriangle size={16} />{userError}</div>}

      <div className="table-responsive">
        <table className="table align-middle data-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Access</th>
              <th>Status</th>
              <th>2FA</th>
              <th>Last Login</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>
                  <AvatarLabel name={user.display_name || user.email} />
                  <div className="muted-line">{user.display_name || "No name"}</div>
                  <div className="mono-cell">{user.email}</div>
                </td>
                <td>
                  <select className="form-select compact-select" value={user.access_level} onChange={(event) => void saveUser(user, { access_level: event.target.value })}>
                    <option value="owner">Owner</option>
                    <option value="admin">Admin</option>
                    <option value="operator">Operator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </td>
                <td>
                  <select className="form-select compact-select" value={user.status} onChange={(event) => void saveUser(user, { status: event.target.value })}>
                    <option value="active">Active</option>
                    <option value="invited">Invited</option>
                    <option value="disabled">Disabled</option>
                  </select>
                </td>
                <td>
                  <div className="two-factor-cell">
                    <StatusBadge status={user.two_factor_enabled ? "enabled" : user.two_factor_required ? "required" : "optional"} />
                    <label className="mini-check">
                      <input type="checkbox" checked={user.two_factor_required} onChange={(event) => void saveUser(user, { two_factor_required: event.target.checked })} />
                      Required
                    </label>
                  </div>
                </td>
                <td>{user.last_login_at ? formatRelative(user.last_login_at) : "never"}</td>
                <td className="actions-cell">
                  <button className="btn btn-outline-secondary" type="button" disabled={savingUserID === user.id} onClick={() => void enrollUser(user)}>
                    {savingUserID === user.id ? <Loader2 size={16} className="spin" /> : <KeyRound size={16} aria-hidden="true" />}
                    QR
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {loadingUsers && <div className="muted-line">Loading users...</div>}
      {!loadingUsers && users.length === 0 && <EmptyState icon={UserCircle} title="No users" detail="Add the first dashboard user to start access control setup." />}

      {enrollment && (
        <div className="totp-enrollment" role="status">
          <div>
            <strong>{enrollment.user.email}</strong>
            <span>2FA QR enrollment</span>
          </div>
          <img src={enrollment.enrollment.qr_code_data_url} alt={`2FA QR code for ${enrollment.user.email}`} />
          <dl className="detail-list compact">
            <div><dt>Manual key</dt><dd className="mono-cell">{enrollment.enrollment.secret}</dd></div>
            <div><dt>URI</dt><dd className="mono-cell clamp-cell">{enrollment.enrollment.otpauth_url}</dd></div>
          </dl>
        </div>
      )}
      </>
      )}
    </section>
  );
}

function upsertHubUser(users: HubUser[], user: HubUser) {
  const next = users.some((item) => item.id === user.id)
    ? users.map((item) => item.id === user.id ? user : item)
    : [...users, user];
  return next.sort((left, right) => accessLevelRank(left.access_level) - accessLevelRank(right.access_level) || left.email.localeCompare(right.email));
}

function accessLevelRank(level: string) {
  switch (level) {
    case "owner":
      return 1;
    case "admin":
      return 2;
    case "operator":
      return 3;
    default:
      return 4;
  }
}

function ScopeList({
  baseUrl,
  onSelect,
  organizations
}: {
  baseUrl: string;
  onSelect: (scope: ApiScope) => void;
  organizations: InventoryOrganization[];
}) {
  const [query, setQuery] = useState("");
  const choices: ScopeChoice[] = organizations.flatMap((organization) =>
    organization.projects.flatMap((project) =>
      project.environments.flatMap((environment): ScopeChoice[] => {
        if (environment.apps.length === 0) {
          return [{
            organization,
            project,
            environment,
            app: undefined
          }];
        }
        return environment.apps.map((app): ScopeChoice => ({
          organization,
          project,
          environment,
          app
        }));
      })
    )
  );
  const normalizedQuery = query.trim().toLowerCase();
  const filteredChoices = normalizedQuery
    ? choices.filter(({ app, environment, organization, project }) =>
        [
          organization.name,
          organization.slug,
          project.name,
          project.slug,
          environment.name,
          environment.slug,
          app?.name,
          app?.slug,
          app?.kind
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedQuery))
      )
    : choices;

  if (choices.length === 0) {
    return <EmptyState icon={Boxes} title="No scopes" detail="No organizations, projects, environments, or apps were returned." />;
  }

  return (
    <>
      <div className="search-field scope-search">
        <Search size={16} aria-hidden="true" />
        <input
          aria-label="Search inventory scopes"
          className="form-control"
          placeholder="Search organization, project, environment, app"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>
      <div className="scope-list">
        {filteredChoices.map(({ app, environment, organization, project }) => {
          const appLabel = app ? `${app.name || app.slug}${app.kind ? ` (${app.kind})` : ""}` : "All apps";
          return (
            <button
              className="stack-row scope-choice"
              key={`${organization.slug}:${project.slug}:${environment.slug}:${app?.slug ?? "all"}`}
              type="button"
              onClick={() => onSelect({
                app: app?.slug ?? "",
                baseUrl,
                environment: environment.slug,
                org: organization.slug,
                project: project.slug
              })}
            >
              <span>
                <strong>{organization.name || organization.slug}</strong>
                <small>{organization.slug}</small>
              </span>
              <span>
                <strong>{project.name || project.slug}</strong>
                <small>{project.slug} / {environment.name || environment.slug}</small>
              </span>
              <span className="scope-app">
                <strong>{appLabel}</strong>
                <small>{app?.slug ?? "all"}</small>
              </span>
              <CheckCircle2 size={18} aria-hidden="true" />
            </button>
          );
        })}
      </div>
      {filteredChoices.length === 0 && <EmptyState icon={Search} title="No matching scopes" detail="The inventory filter did not match any returned scopes." />}
    </>
  );
}

function Metric({ icon: Icon, label, tone, value }: { icon: typeof AlertTriangle; label: string; tone: string; value: number }) {
  return (
    <div className={`metric ${tone}`}>
      <div className="metric-icon"><Icon size={20} aria-hidden="true" /></div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function PanelTitle({ action, icon, onAction, title }: { action?: string; icon: typeof AlertTriangle; onAction?: () => void; title: string }) {
  return (
    <div className="panel-title">
      <PanelHeading icon={icon} title={title} />
      {action && onAction && (
        <button className="link-button" type="button" onClick={onAction}>
          {action}
        </button>
      )}
    </div>
  );
}

function PanelHeading({ icon: Icon, title }: { icon: typeof AlertTriangle; title: string }) {
  return (
    <h2 className="panel-heading">
      <Icon size={18} aria-hidden="true" />
      {title}
    </h2>
  );
}

function FindingList({ findings, onSelect, ruleById }: { findings: HubFinding[]; onSelect: (id: string) => void; ruleById: Map<string, RuleDefinition> }) {
  if (findings.length === 0) {
    return <EmptyState icon={ShieldCheck} title="No findings" detail="The queue is empty for this scope." />;
  }
  return (
    <div className="stack-list">
      {findings.map((finding) => (
        <button className="stack-row" key={finding.id} type="button" onClick={() => onSelect(finding.id)}>
          <SeverityBadge severity={finding.severity} />
          <span>
            <strong>{finding.title}</strong>
            <small>{ruleById.get(finding.rule_id)?.category ?? finding.rule_id} / {formatRelative(finding.last_event_at)}</small>
          </span>
          <StatusBadge status={finding.status} />
        </button>
      ))}
    </div>
  );
}

function EventList({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) {
    return <EmptyState icon={Clock3} title="No events" detail="No events returned for the selected window." />;
  }
  return (
    <div className="timeline-list">
      {events.map((event) => (
        <div className="timeline-row" key={event.id}>
          <span className="timeline-dot" />
          <div>
            <strong>{event.type}</strong>
            <small>{event.host} / {formatRelative(event.event_time)}</small>
            <p>{event.message}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function CoverageMatrix({ coverage }: { coverage: CoverageRecord[] }) {
  if (coverage.length === 0) {
    return <EmptyState icon={Server} title="No coverage" detail="No coverage records were returned." />;
  }
  return (
    <div className="stack-list">
      {coverage.slice(0, 6).map((record) => (
        <div className="stack-row passive" key={record.event_id}>
          <CoverageBadge level={record.coverage_level} />
          <span>
            <strong>{record.site}</strong>
            <small>{record.site_kind} / {record.host} / {formatRelative(record.reported_at)}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function ReportList({ reports }: { reports: ModelAnalysisReport[] }) {
  if (reports.length === 0) {
    return <EmptyState icon={ScrollText} title="No reports" detail="No saved reports were returned." />;
  }
  return (
    <div className="stack-list">
      {reports.map((report) => (
        <div className="stack-row passive" key={report.id}>
          <StatusBadge status={report.status} />
          <span>
            <strong>{report.model_name || report.prompt_template_id}</strong>
            <small>{report.prompt_template_version} / {formatRelative(report.generated_at)}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function SimpleRows({ rows }: { rows: string[][] }) {
  if (rows.length === 0) {
    return <EmptyState icon={Boxes} title="No records" detail="No records were returned." />;
  }
  return (
    <div className="stack-list">
      {rows.map((row) => (
        <div className="stack-row passive" key={row.join(":")}>
          <span>
            <strong>{row[0]}</strong>
            <small>{row.slice(1).filter(Boolean).join(" / ")}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function HostRows({ hosts }: { hosts: Host[] }) {
  if (hosts.length === 0) {
    return <EmptyState icon={Server} title="No hosts" detail="No hosts were returned." />;
  }
  return (
    <div className="stack-list">
      {hosts.map((host) => (
        <div className="stack-row passive" key={host.id}>
          <span>
            <strong>{host.hostname || host.slug}</strong>
            <small>{[host.slug, host.region, labelPairs(host.labels)].filter(Boolean).join(" / ")}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function AgentRows({ agents, hosts }: { agents: Agent[]; hosts: Host[] }) {
  if (agents.length === 0) {
    return <EmptyState icon={TerminalSquare} title="No agents" detail="No agents were returned." />;
  }
  return (
    <div className="stack-list">
      {agents.map((agent) => (
        <div className="stack-row passive" key={agent.id}>
          <StatusBadge status={agent.last_seen_at ? "active" : "unknown"} />
          <span>
            <strong>{agent.agent_id}</strong>
            <small>{hostLabel(hosts, agent.host_id)} / {agent.last_seen_at ? formatRelative(agent.last_seen_at) : "never seen"}</small>
          </span>
        </div>
      ))}
    </div>
  );
}

function FindingMetadata({ finding }: { finding: HubFinding }) {
  const risk = metadataRecord(finding.metadata.risk);
  const items = [
    ["Risk band", valueText(risk.band)],
    ["Risk score", valueText(risk.score)],
    ["Rule category", valueText(risk.rule_category)],
    ["Deployment active", typeof risk.deployment_active === "boolean" ? (risk.deployment_active ? "yes" : "no") : ""]
  ].filter(([, value]) => value);

  if (items.length === 0) {
    return null;
  }
  return (
    <dl className="detail-list compact">
      {items.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function ActionButton({ icon: Icon, label, loading, onClick }: { icon: typeof Eye; label: string; loading: boolean; onClick: () => void }) {
  return (
    <button className="btn btn-outline-primary" type="button" disabled={loading} onClick={onClick}>
      {loading ? <Loader2 size={16} className="spin" /> : <Icon size={16} aria-hidden="true" />}
      {label}
    </button>
  );
}

function TextInput({ label, onChange, placeholder, value }: { label: string; onChange: (value: string) => void; placeholder?: string; value: string }) {
  const id = `field-${label.toLowerCase().replaceAll(" ", "-")}`;
  return (
    <div>
      <label className="form-label" htmlFor={id}>{label}</label>
      <input className="form-control" id={id} placeholder={placeholder} value={value} onChange={(event) => onChange(event.target.value)} />
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge text-bg-${severityClass(severity)} badge-fixed`}>{severity}</span>;
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-badge ${status.replaceAll("_", "-")}`}>{status.replaceAll("_", " ")}</span>;
}

function CoverageBadge({ level }: { level: string }) {
  return <span className={`status-badge coverage-${level}`}>{level}</span>;
}

function EmptyState({ detail, icon: Icon, title }: { detail: string; icon: typeof Search; title: string }) {
  return (
    <div className="empty-state">
      <Icon size={22} aria-hidden="true" />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function ApiErrors({ data, estateErrors = [] }: { data: DashboardData; estateErrors?: string[] }) {
  const errors = uniqueStrings([
    ...Object.entries(data)
      .filter(([, state]) => state.error)
      .map(([name, state]) => `${name}: ${state.error}`),
    ...estateErrors
  ]);
  if (errors.length === 0) {
    return null;
  }
  return (
    <div className="alert alert-warning api-errors" role="status">
      <AlertTriangle size={18} aria-hidden="true" />
      <div>
        <strong>Some Hub requests did not complete.</strong>
        <ul>
          {errors.slice(0, 4).map((error) => <li key={error}>{error}</li>)}
        </ul>
      </div>
    </div>
  );
}

function breadcrumbItemsForView(view: ViewKey, company?: CompanyModel, instance?: InstanceModel): BreadcrumbItem[] {
  if (view === "overview") {
    return [];
  }

  const root: BreadcrumbItem = { label: "Overview", view: "overview" };

  if (view === "companies") {
    return [root, { label: "Company Directory" }];
  }

  if (view === "company" || view === "site" || view === "instance") {
    const items: BreadcrumbItem[] = [root, { label: "Company Directory", view: "companies" }];
    const companyName = company?.companyName ?? instance?.companyName;
    if (companyName) {
      items.push({ label: companyName, view: view === "company" ? undefined : "company" });
    }
    if (view === "site" || view === "instance") {
      items.push({ label: instance?.projectName ?? "Site / Project", view: view === "site" ? undefined : "site" });
    }
    if (view === "instance") {
      items.push({ label: instance?.environmentName ?? "Instance" });
    }
    return items;
  }

  return [root, { label: pageTitleForView(view, company, instance) }];
}

function pageTitleForView(view: ViewKey, company?: CompanyModel, instance?: InstanceModel) {
  if (view === "overview") {
    return "Operations Console";
  }
  if (view === "companies") {
    return "Company Directory";
  }
  if (view === "company") {
    return company?.companyName ?? "Companies";
  }
  if (view === "site") {
    return instance?.projectName ?? "Site / Project";
  }
  if (view === "instance") {
    return instance?.projectName ?? "Instance";
  }
  if (view === "timeline") {
    return "Activity Timeline";
  }
  if (view === "findings") {
    return "Findings & Incident Inbox";
  }
  if (view === "coverage") {
    return "Coverage Command Center";
  }
  if (view === "agents") {
    return "Agents & Collector Health";
  }
  if (view === "browser") {
    return "Browser Scripts";
  }
  return navItems.find((item) => item.key === view)?.label ?? "Dashboard";
}

function pageEyebrowForView(view: ViewKey, scope: ApiScope, company?: CompanyModel, instance?: InstanceModel) {
  if (view === "overview") {
    return "All companies / monitored estate";
  }
  if (view === "companies") {
    return "Company health / risk / monitored coverage";
  }
  if (view === "company" && company) {
    return `${company.siteCount} site${company.siteCount === 1 ? "" : "s"} / ${company.instances.length} instance${company.instances.length === 1 ? "" : "s"}`;
  }
  if (view === "site" && instance) {
    return `${instance.companyName} / ${instance.projectName} / site operations`;
  }
  if (view === "instance" && instance) {
    return `${instance.companyName} / ${instance.projectName} / ${instance.environmentName}`;
  }
  if (view === "timeline") {
    return "Chronological collector, browser, database, and incident signals";
  }
  if (view === "findings") {
    return "Open findings grouped by company";
  }
  if (view === "coverage") {
    return "Collector coverage and stale signal review";
  }
  if (view === "agents") {
    return "Collector status, queue health, and scan freshness";
  }
  if (view === "browser") {
    return "Observed scripts, allowlist drift, and external domains";
  }
  return `${scope.org} / ${scope.project} / ${scope.environment}`;
}

function viewFromLocation(): ViewKey {
  const relativePath = window.location.pathname.startsWith(basePath)
    ? window.location.pathname.slice(basePath.length)
    : "";
  const pathView = relativePath.split("/").filter(Boolean)[0];
  const hashView = window.location.hash.replace("#", "");
  const candidate = pathView || hashView || "overview";
  return viewKeys.has(candidate as ViewKey) ? candidate as ViewKey : "overview";
}

function viewPath(view: ViewKey) {
  return view === "overview" ? `${basePath}/` : `${basePath}/${view}`;
}

function loadActionDefaults(): ActionState {
  const fallback = { actor: "dashboard", reason: "reviewed", note: "" };
  const raw = localStorage.getItem("aegrail.dashboard.triage");
  if (!raw) {
    return fallback;
  }
  try {
    return { ...fallback, ...JSON.parse(raw) };
  } catch {
    return fallback;
  }
}

function saveActionDefaults(actionState: ActionState) {
  localStorage.setItem("aegrail.dashboard.triage", JSON.stringify(actionState));
}

function summarize(data: DashboardData) {
  const openFindings = data.findings.data.filter((finding) => finding.status === "open").length;
  const highRiskFindings = data.findings.data.filter((finding) => ["critical", "high"].includes(finding.severity)).length;
  const coveredSites = new Set(data.coverage.data.filter((record) => record.coverage_level !== "none").map((record) => record.site)).size;
  const activeAgents = data.topology.data.agents.filter((agent) => isRecent(agent.last_seen_at)).length;
  const scriptDomains = new Set(data.browserScripts.data.map((script) => script.domain).filter(Boolean)).size;
  const totalEvents = data.timeline.data.length;
  return { activeAgents, coveredSites, highRiskFindings, openFindings, scriptDomains, totalEvents };
}

function filterFindings(findings: HubFinding[], filters: FindingFilters) {
  const query = filters.query.trim().toLowerCase();
  return findings.filter((finding) => {
    if (filters.severity !== "all" && finding.severity !== filters.severity) {
      return false;
    }
    if (filters.status !== "all" && finding.status !== filters.status) {
      return false;
    }
    if (!query) {
      return true;
    }
    return [
      finding.title,
      finding.summary,
      finding.description,
      finding.rule_id,
      finding.severity,
      finding.status
    ]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });
}

function hasErrors(data: DashboardData) {
  return Object.values(data).some((state) => state.error);
}

function hasEndpointErrors(data: DashboardData) {
  return Object.entries(data).some(([name, state]) => name !== "health" && state.error);
}

function collectEstateErrors(instances: InstanceModel[]) {
  const errors: string[] = [];
  for (const instance of instances) {
    const label = `${instance.companyName} / ${instance.projectName} / ${instance.environmentName}`;
    for (const [name, state] of Object.entries(instance.data)) {
      if (state.error) {
        errors.push(`${label}: ${name} ${state.error}`);
      }
    }
  }
  return uniqueStrings(errors).slice(0, 8);
}

function isRecent(value?: string) {
  if (!value) {
    return false;
  }
  return Date.now() - new Date(value).getTime() < 24 * 60 * 60 * 1000;
}

function severityClass(severity: string) {
  switch (severity) {
    case "critical":
      return "danger";
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "info";
    case "info":
      return "secondary";
    default:
      return "secondary";
  }
}

function formatDate(value?: string) {
  if (!value) {
    return "unknown";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23"
  }).format(date);
}

function formatRelative(value?: string) {
  if (!value) {
    return "unknown";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60]
  ];
  for (const [unit, amount] of units) {
    if (abs >= amount) {
      return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(Math.round(seconds / amount), unit);
    }
  }
  return "just now";
}

function metadataRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function valueText(value: unknown) {
  if (value === undefined || value === null || value === "") {
    return "";
  }
  return String(value);
}

function riskLabel(finding: HubFinding) {
  const risk = metadataRecord(finding.metadata.risk);
  return valueText(risk.score) || valueText(risk.band) || "unscored";
}

function isBrowserDriftFinding(finding: HubFinding) {
  return finding.rule_id.startsWith("browser-script") && Boolean(finding.metadata.kind || finding.metadata.value);
}

function labelPairs(labels: Record<string, string>) {
  return Object.entries(labels).map(([key, value]) => `${key}=${value}`).join(", ");
}

function hostLabel(hosts: Host[], hostID: string) {
  const host = hosts.find((item) => item.id === hostID);
  return host?.slug || host?.hostname || hostID;
}
