import type {
  ApiScope,
  BrowserAllowlistEntry,
  BrowserScript,
  CoverageRecord,
  DashboardData,
  FilteredFindingsPage,
  FindingsQuery,
  HubAuthMe,
  Deployment,
  FindingsRequestState,
  HubFinding,
  HubFindingSummary,
  HubHealth,
  HubUser,
  HubUserTOTPEnrollment,
  InventoryEnvironment,
  InventoryOrganization,
  InventoryProject,
  ModelAnalysisReport,
  MonitoredApp,
  NodeProvisioning,
  PushNotificationConfig,
  RequestState,
  RuleDefinition,
  TimelineEvent,
  Topology,
  Host,
  Agent,
  Service,
  TrafficBotsResponse,
  TrafficIPDetail,
  TrafficIPPolicy,
  TrafficOverview,
  TrafficUserAgentDetail
} from "./types";
import type { TrafficTimeRange } from "./dashboard/types";

type ApiEnvelope<T> = Record<string, unknown> & T;

export const findingsPageSize = 250;

const defaults = {
  health: null as HubHealth | null,
  findings: [] as HubFinding[],
  timeline: [] as TimelineEvent[],
  coverage: [] as CoverageRecord[],
  scopes: [] as InventoryOrganization[],
  topology: { counts: {}, apps: [], services: [], hosts: [], agents: [] } as Topology,
  browserScripts: [] as BrowserScript[],
  allowlist: [] as BrowserAllowlistEntry[],
  rules: [] as RuleDefinition[]
};

const dashboardProtocol = "aegrail.dashboard.v1";
let dashboardCSRFToken = "";

export const defaultScope: ApiScope = {
  baseUrl: "",
  org: "acme",
  project: "customer-site",
  environment: "production",
  app: "main-web"
};

export type DashboardInstanceSnapshot = {
  app?: MonitoredApp;
  data: DashboardData;
  environment: InventoryEnvironment;
  organization: InventoryOrganization;
  project: InventoryProject;
  scope: ApiScope;
};

export type EstateDashboardData = {
  health: RequestState<HubHealth | null>;
  instances: DashboardInstanceSnapshot[];
  rules: RequestState<RuleDefinition[]>;
  scopes: RequestState<InventoryOrganization[]>;
};

export function loadScope(): ApiScope {
  const raw = localStorage.getItem("aegrail.dashboard.scope");
  if (!raw) {
    return defaultScope;
  }
  try {
    return { ...defaultScope, ...JSON.parse(raw) };
  } catch {
    return defaultScope;
  }
}

export function saveScope(scope: ApiScope) {
  localStorage.setItem("aegrail.dashboard.scope", JSON.stringify(scope));
}

function query(scope: ApiScope, includeApp = true, extras: Record<string, string> = {}) {
  const params = new URLSearchParams({
    org: scope.org,
    project: scope.project,
    environment: scope.environment,
    ...extras
  });
  if (includeApp && scope.app.trim() !== "") {
    params.set("app", scope.app);
  }
  return params.toString();
}

function joinUrl(scope: ApiScope, path: string) {
  const base = scope.baseUrl.trim().replace(/\/+$/, "");
  return `${base}${path}`;
}

function dashboardHeaders(mutating = false): HeadersInit {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Aegrail-Dashboard-Protocol": dashboardProtocol
  };
  if (mutating && dashboardCSRFToken) {
    headers["X-Aegrail-CSRF"] = dashboardCSRFToken;
  }
  return headers;
}

function rememberDashboardProtocol(body: { csrf_token?: string }) {
  if (body.csrf_token) {
    dashboardCSRFToken = body.csrf_token;
  }
}

async function apiGet<T>(scope: ApiScope, path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(joinUrl(scope, path), {
    credentials: "include",
    headers: dashboardHeaders(),
    signal
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

async function apiPatch<T>(scope: ApiScope, path: string, body: unknown): Promise<T> {
  const response = await fetch(joinUrl(scope, path), {
    credentials: "include",
    method: "PATCH",
    headers: {
      ...dashboardHeaders(true),
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

async function apiPost<T>(scope: ApiScope, path: string, body: unknown): Promise<T> {
  const response = await fetch(joinUrl(scope, path), {
    credentials: "include",
    method: "POST",
    headers: {
      ...dashboardHeaders(true),
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

async function apiDelete<T>(scope: ApiScope, path: string): Promise<T> {
  const response = await fetch(joinUrl(scope, path), {
    credentials: "include",
    method: "DELETE",
    headers: dashboardHeaders(true)
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

export class MFARequiredError extends Error {
  constructor() {
    super("mfa required");
    this.name = "MFARequiredError";
  }
}

export async function loadAuthMe(scope: ApiScope) {
  const body = await apiGet<HubAuthMe>(scope, "/api/v1/auth/me");
  rememberDashboardProtocol(body);
  return body;
}

export async function loginHubUser(
  scope: ApiScope,
  input: {
    email: string;
    password: string;
    totp_code?: string;
  }
) {
  const response = await fetch(joinUrl(scope, "/api/v1/auth/login"), {
    body: JSON.stringify(input),
    credentials: "include",
    headers: {
      ...dashboardHeaders(),
      "Content-Type": "application/json"
    },
    method: "POST"
  });
  if (!response.ok) {
    const text = await response.text();
    try {
      const body = JSON.parse(text) as { mfa_required?: boolean };
      if (body.mfa_required) {
        throw new MFARequiredError();
      }
    } catch (error) {
      if (error instanceof MFARequiredError) {
        throw error;
      }
    }
    throw new Error(text || `${response.status} ${response.statusText}`);
  }
  const body = (await response.json()) as ApiEnvelope<{
    csrf_token?: string;
    dashboard_ready?: boolean;
    expires_at: string;
    totp_setup_required?: boolean;
    user: HubUser;
  }>;
  rememberDashboardProtocol(body);
  return body;
}

export async function logoutHubUser(scope: ApiScope) {
  const body = await apiPost<ApiEnvelope<{ ok: boolean }>>(scope, "/api/v1/auth/logout", {});
  dashboardCSRFToken = "";
  return body;
}

async function state<T>(request: Promise<T>, fallback: T): Promise<RequestState<T>> {
  try {
    return { data: await request };
  } catch (error) {
    return { data: fallback, error: friendlyError(error) };
  }
}

async function initialFindingsState(scope: ApiScope): Promise<FindingsRequestState> {
  try {
    return await loadFindingsPage(scope);
  } catch (error) {
    return {
      complete: false,
      data: defaults.findings,
      error: friendlyError(error),
      total: 0,
      totalExact: false
    };
  }
}

export async function loadFindingsPage(scope: ApiScope, cursor = ""): Promise<FindingsRequestState> {
  const params = new URLSearchParams(query(scope));
  params.set("limit", String(findingsPageSize));
  if (cursor.trim()) {
    params.set("cursor", cursor);
  }
  const body = await apiGet<ApiEnvelope<{
    count?: number;
    findings?: HubFinding[];
    next_cursor?: string;
    summary?: unknown;
    total?: number;
  }>>(scope, `/api/v1/findings?${params.toString()}`);
  const findings = Array.isArray(body.findings) ? body.findings : [];
  const explicitTotal = nonNegativeNumber(body.total);
  const nextCursor = stringValue(body.next_cursor);
  const total = explicitTotal ?? findings.length;
  const totalExact = explicitTotal !== undefined;
  const legacyPageMayBeTruncated = !totalExact && !nextCursor && findings.length >= findingsPageSize;
  return {
    complete: !nextCursor && (Boolean(cursor.trim()) || !legacyPageMayBeTruncated) && (!totalExact || findings.length >= total),
    data: findings,
    nextCursor,
    summary: findingSummary(body.summary),
    total,
    totalExact
  };
}

export async function loadFilteredFindingsPage(
  scope: ApiScope,
  filters: FindingsQuery,
  cursor = '',
  signal?: AbortSignal
): Promise<FilteredFindingsPage> {
  const params = new URLSearchParams(query(scope));
  params.set('limit', String(filters.limit));
  if (cursor.trim()) {
    params.set('cursor', cursor);
  }
  if (filters.q.trim()) {
    params.set('q', filters.q.trim());
  }
  for (const status of filters.statuses.map((value) => value.trim()).filter(Boolean)) {
    params.append('status', status);
  }
  for (const severity of filters.severities.map((value) => value.trim()).filter(Boolean)) {
    params.append('severity', severity);
  }

  const body = await apiGet<ApiEnvelope<{
    count?: number;
    findings?: HubFinding[];
    matched_total?: number;
    next_cursor?: string;
  }>>(scope, `/api/v1/findings?${params.toString()}`, signal);
  const findings = Array.isArray(body.findings) ? body.findings : [];
  const matchedTotal = nonNegativeNumber(body.matched_total);
  const nextCursor = stringValue(body.next_cursor);
  return {
    complete: !nextCursor,
    data: findings,
    matchedTotal,
    matchedTotalExact: matchedTotal !== undefined,
    nextCursor
  };
}

export function appendFindingsPage(
  current: FindingsRequestState,
  page: FindingsRequestState
): FindingsRequestState {
  const seen = new Set<string>();
  const data = [...current.data, ...page.data].filter((finding) => {
    if (seen.has(finding.id)) {
      return false;
    }
    seen.add(finding.id);
    return true;
  });
  const totalExact = page.totalExact || current.totalExact;
  const total = page.totalExact ? page.total : current.totalExact ? current.total : Math.max(current.total, data.length);
  return {
    complete: page.complete || (totalExact && data.length >= total),
    data,
    nextCursor: page.nextCursor,
    summary: page.summary ?? current.summary,
    total,
    totalExact
  };
}

export async function loadFinding(scope: ApiScope, findingID: string) {
  const params = query(scope);
  return apiGet<ApiEnvelope<{ finding: HubFinding }>>(
    scope,
    `/api/v1/findings/${encodeURIComponent(findingID)}?${params}`
  ).then((body) => body.finding);
}

export async function loadDashboard(scope: ApiScope): Promise<DashboardData> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const scoped = query(scope);
  const environmentScoped = query(scope, false);

  const [
    health,
    findings,
    timeline,
    coverage,
    scopes,
    topology,
    browserScripts,
    allowlist,
    rules
  ] = await Promise.all([
    state(apiGet<HubHealth>(scope, "/healthz"), defaults.health),
    initialFindingsState(scope),
    state(
      apiGet<ApiEnvelope<{ events: TimelineEvent[] }>>(
        scope,
        `/api/v1/timeline?${scoped}&since=${encodeURIComponent(since)}&limit=250`
      ).then((body) => sortTimelineNewestFirst(body.events ?? [])),
      defaults.timeline
    ),
    state(
      apiGet<ApiEnvelope<{ coverage: CoverageRecord[] }>>(
        scope,
        `/api/v1/coverage?${scoped}&limit=1000`
      ).then((body) => body.coverage ?? []),
      defaults.coverage
    ),
    state(
      apiGet<ApiEnvelope<{ organizations: InventoryOrganization[] }>>(scope, "/api/v1/inventory/scopes").then(
        (body) => body.organizations ?? []
      ),
      defaults.scopes
    ),
    state(
      apiGet<Topology>(scope, `/api/v1/inventory/topology?${environmentScoped}`),
      defaults.topology
    ),
    state(
      apiGet<ApiEnvelope<{ scripts: BrowserScript[] }>>(
        scope,
        `/api/v1/browser/scripts?${scoped}&since=${encodeURIComponent(since)}&limit=500`
      ).then((body) => body.scripts ?? []),
      defaults.browserScripts
    ),
    state(
      apiGet<ApiEnvelope<{ allowlist: BrowserAllowlistEntry[] }>>(
        scope,
        `/api/v1/browser/script-allowlist?${scoped}`
      ).then((body) => body.allowlist ?? []),
      defaults.allowlist
    ),
    state(
      apiGet<ApiEnvelope<{ rules: RuleDefinition[] }>>(scope, "/api/v1/rules").then((body) => body.rules ?? []),
      defaults.rules
    )
  ]);

  return { health, findings, timeline, coverage, scopes, topology, browserScripts, allowlist, rules };
}

export async function loadEstateDashboard(scope: ApiScope): Promise<EstateDashboardData> {
  const [health, scopes, rules] = await Promise.all([
    state(apiGet<HubHealth>(scope, "/healthz"), defaults.health),
    state(
      apiGet<ApiEnvelope<{ organizations: InventoryOrganization[] }>>(scope, "/api/v1/inventory/scopes").then(
        (body) => body.organizations ?? []
      ),
      defaults.scopes
    ),
    state(
      apiGet<ApiEnvelope<{ rules: RuleDefinition[] }>>(scope, "/api/v1/rules").then((body) => body.rules ?? []),
      defaults.rules
    )
  ]);

  const choices = estateScopeChoices(scope.baseUrl, scopes.data);
  const shared = { health, scopes, rules };
  const topologyCache = new Map<string, Promise<RequestState<Topology>>>();
  const instances = await Promise.all(
    choices.map(async (choice) => ({
      ...choice,
      data: await loadEstateInstanceDashboard(choice.scope, shared, topologyCache)
    }))
  );

  return { health, instances, rules, scopes };
}

export async function loadTimelineEventsByID(scope: ApiScope, eventIDs: string[]): Promise<TimelineEvent[]> {
  const ids = Array.from(new Set(eventIDs.map((eventID) => eventID.trim()).filter(Boolean))).slice(0, 200);
  if (!ids.length) {
    return [];
  }
  const params = new URLSearchParams(query(scope));
  for (const eventID of ids) {
    params.append("id", eventID);
  }
  return apiGet<ApiEnvelope<{ events: TimelineEvent[] }>>(scope, `/api/v1/timeline?${params.toString()}`).then(
    (body) => body.events ?? []
  );
}

async function loadEstateInstanceDashboard(
  scope: ApiScope,
  shared: Pick<DashboardData, "health" | "rules" | "scopes">,
  topologyCache: Map<string, Promise<RequestState<Topology>>>
): Promise<DashboardData> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const scoped = query(scope);

  const [
    findings,
    timeline,
    coverage,
    topology,
    browserScripts,
    allowlist
  ] = await Promise.all([
    initialFindingsState(scope),
    state(
      apiGet<ApiEnvelope<{ events: TimelineEvent[] }>>(
        scope,
        `/api/v1/timeline?${scoped}&since=${encodeURIComponent(since)}&limit=250`
      ).then((body) => sortTimelineNewestFirst(body.events ?? [])),
      defaults.timeline
    ),
    state(
      apiGet<ApiEnvelope<{ coverage: CoverageRecord[] }>>(
        scope,
        `/api/v1/coverage?${scoped}&limit=1000`
      ).then((body) => body.coverage ?? []),
      defaults.coverage
    ),
    estateTopologyState(scope, topologyCache),
    state(
      apiGet<ApiEnvelope<{ scripts: BrowserScript[] }>>(
        scope,
        `/api/v1/browser/scripts?${scoped}&since=${encodeURIComponent(since)}&limit=500`
      ).then((body) => body.scripts ?? []),
      defaults.browserScripts
    ),
    state(
      apiGet<ApiEnvelope<{ allowlist: BrowserAllowlistEntry[] }>>(
        scope,
        `/api/v1/browser/script-allowlist?${scoped}`
      ).then((body) => body.allowlist ?? []),
      defaults.allowlist
    ),
  ]);

  return { ...shared, findings, timeline, coverage, topology, browserScripts, allowlist };
}

function estateTopologyState(scope: ApiScope, cache: Map<string, Promise<RequestState<Topology>>>) {
  const key = [scope.baseUrl, scope.org, scope.project, scope.environment].join("\u0000");
  const existing = cache.get(key);
  if (existing) {
    return existing;
  }
  const request = state(apiGet<Topology>(scope, `/api/v1/inventory/topology?${query(scope, false)}`), defaults.topology);
  cache.set(key, request);
  return request;
}

export async function updateFindingStatus(
  scope: ApiScope,
  finding: HubFinding,
  status: string,
  actor: string,
  reason: string,
  note: string
) {
  const params = query(scope, false);
  return apiPatch<ApiEnvelope<{ finding: HubFinding }>>(
    scope,
    `/api/v1/findings/${encodeURIComponent(finding.id)}/status?${params}`,
    {
      status,
      actor,
      reason,
      note
    }
  ).then((body) => body.finding);
}

export async function acceptFindingsBaseline(
  scope: ApiScope,
  input: {
    actor: string;
    note?: string;
    reason?: string;
  }
) {
  const params = query(scope);
  return apiPost<ApiEnvelope<{ actor: string; note: string; reason: string; status: string; updated: number }>>(
    scope,
    `/api/v1/findings/baseline?${params}`,
    input
  );
}

export async function allowBrowserScriptFromFinding(scope: ApiScope, finding: HubFinding, actor: string, reason: string) {
  const params = query(scope);
  return apiPost(
    scope,
    `/api/v1/findings/${encodeURIComponent(finding.id)}/browser-script-allowlist?${params}`,
    {
      approved_by: actor,
      reason
    }
  );
}

export async function ignoreFilePathFromFinding(
  scope: ApiScope,
  finding: HubFinding,
  path: string,
  actor: string,
  reason: string
) {
  const params = query(scope);
  return apiPost(
    scope,
    `/api/v1/findings/${encodeURIComponent(finding.id)}/file-ignore?${params}`,
    {
      actor,
      path,
      reason
    }
  );
}

export async function generateModelAnalysisFromFinding(
  scope: ApiScope,
  finding: HubFinding,
  input: {
    max_collection_entries?: number;
    max_events?: number;
    max_metadata_depth?: number;
    max_string_length?: number;
    model?: string;
  } = {}
) {
  const params = query(scope);
  return apiPost<ApiEnvelope<{ report: ModelAnalysisReport }>>(
    scope,
    `/api/v1/findings/${encodeURIComponent(finding.id)}/model-analysis?${params}`,
    input
  ).then((body) => body.report);
}

export async function createBrowserScriptAllowlistEntry(
  scope: ApiScope,
  input: {
    approved_by: string;
    kind: string;
    page_url?: string;
    reason: string;
    value: string;
  }
) {
  const params = query(scope);
  return apiPost<ApiEnvelope<{ entry: BrowserAllowlistEntry }>>(
    scope,
    `/api/v1/browser/script-allowlist?${params}`,
    input
  ).then((body) => body.entry);
}

export async function loadHubUsers(scope: ApiScope) {
  return apiGet<ApiEnvelope<{ users: HubUser[] }>>(scope, "/api/v1/access/users").then((body) => body.users ?? []);
}

export async function loadPushNotificationConfig(scope: ApiScope) {
  return apiGet<PushNotificationConfig>(scope, "/api/v1/notifications/push/config");
}

export async function savePushSubscription(scope: ApiScope, subscription: PushSubscriptionJSON) {
  return apiPost(scope, "/api/v1/notifications/push/subscriptions", subscription);
}

export async function deletePushSubscription(scope: ApiScope, endpoint: string) {
  return apiPost(scope, "/api/v1/notifications/push/subscriptions/delete", { endpoint });
}

export async function createHubUser(
  scope: ApiScope,
  input: {
    access_level: string;
    display_name: string;
    email: string;
    password?: string;
    status: string;
    two_factor_required: boolean;
  }
) {
  return apiPost<ApiEnvelope<{ user: HubUser }>>(scope, "/api/v1/access/users", input).then((body) => body.user);
}

export async function createInventoryCompany(
  scope: ApiScope,
  input: {
    name: string;
    slug: string;
  }
) {
  return apiPost<ApiEnvelope<{ organization: InventoryOrganization }>>(
    scope,
    "/api/v1/inventory/companies",
    input
  ).then((body) => body.organization);
}

export async function updateInventoryCompany(
  scope: ApiScope,
  organization: InventoryOrganization,
  input: {
    name: string;
    slug: string;
  }
) {
  return apiPatch<ApiEnvelope<{ organization: InventoryOrganization }>>(
    scope,
    `/api/v1/inventory/companies/${encodeURIComponent(organization.id)}`,
    input
  ).then((body) => body.organization);
}

export async function createInventorySite(
  scope: ApiScope,
  input: {
    app?: string;
    app_name?: string;
    environment?: string;
    environment_name?: string;
    kind?: string;
    org: string;
    project: string;
    project_name?: string;
    service?: string;
    service_name?: string;
    service_role?: string;
  }
) {
  return apiPost<
    ApiEnvelope<{
      app: MonitoredApp;
      environment: InventoryEnvironment;
      project: InventoryProject;
    }>
  >(scope, "/api/v1/inventory/sites", input);
}

export async function updateInventoryProject(
  scope: ApiScope,
  project: InventoryProject,
  input: {
    name: string;
    slug: string;
  }
) {
  return apiPatch<ApiEnvelope<{ project: InventoryProject }>>(
    scope,
    `/api/v1/inventory/projects/${encodeURIComponent(project.id)}`,
    input
  ).then((body) => body.project);
}

export async function updateInventoryEnvironment(
  scope: ApiScope,
  environment: InventoryEnvironment,
  input: {
    name: string;
    slug: string;
  }
) {
  return apiPatch<ApiEnvelope<{ environment: InventoryEnvironment }>>(
    scope,
    `/api/v1/inventory/environments/${encodeURIComponent(environment.id)}`,
    input
  ).then((body) => body.environment);
}

export async function updateInventoryApp(
  scope: ApiScope,
  app: MonitoredApp,
  input: {
    kind: string;
    name: string;
    slug: string;
  }
) {
  return apiPatch<ApiEnvelope<{ app: MonitoredApp }>>(
    scope,
    `/api/v1/inventory/apps/${encodeURIComponent(app.id)}`,
    input
  ).then((body) => body.app);
}

export async function updateInventoryService(
  scope: ApiScope,
  service: Service,
  input: {
    name: string;
    role: string;
    slug: string;
  }
) {
  return apiPatch<ApiEnvelope<{ service: Service }>>(
    scope,
    `/api/v1/inventory/services/${encodeURIComponent(service.id)}`,
    input
  ).then((body) => body.service);
}

export async function createInventoryNode(
  scope: ApiScope,
  input: {
    agent_id?: string;
    app?: string;
    environment?: string;
    host: string;
    hostname?: string;
    interval?: string;
    labels?: Record<string, string>;
    org: string;
    project: string;
    queue_dir?: string;
    region?: string;
    service?: string;
    state_dir?: string;
    version?: string;
  }
) {
  return apiPost<NodeProvisioning>(scope, "/api/v1/inventory/nodes", input);
}

export async function updateInventoryHost(
  scope: ApiScope,
  host: Host,
  input: {
    hostname: string;
    labels?: Record<string, string>;
    region?: string;
    slug: string;
  }
) {
  return apiPatch<ApiEnvelope<{ host: Host }>>(
    scope,
    `/api/v1/inventory/hosts/${encodeURIComponent(host.id)}`,
    input
  ).then((body) => body.host);
}

export async function updateInventoryAgent(
  scope: ApiScope,
  agent: Agent,
  input: {
    agent_id: string;
    version?: string;
  }
) {
  return apiPatch<ApiEnvelope<{ agent: Agent }>>(
    scope,
    `/api/v1/inventory/agents/${encodeURIComponent(agent.id)}`,
    input
  ).then((body) => body.agent);
}

export async function updateHubUser(
  scope: ApiScope,
  user: HubUser,
  input: {
    access_level: string;
    display_name: string;
    status: string;
    two_factor_required: boolean;
  }
) {
  return apiPatch<ApiEnvelope<{ user: HubUser }>>(
    scope,
    `/api/v1/access/users/${encodeURIComponent(user.id)}`,
    input
  ).then((body) => body.user);
}

export async function startHubUserTOTP(scope: ApiScope, user: HubUser) {
  return apiPost<ApiEnvelope<{ enrollment: HubUserTOTPEnrollment; user: HubUser }>>(
    scope,
    `/api/v1/access/users/${encodeURIComponent(user.id)}/totp/start`,
    { issuer: "Aegrail" }
  ).then((body) => body);
}

export async function startCurrentHubUserTOTP(scope: ApiScope) {
  return apiPost<ApiEnvelope<{ enrollment: HubUserTOTPEnrollment; user: HubUser }>>(
    scope,
    "/api/v1/auth/totp/start",
    { issuer: "Aegrail" }
  ).then((body) => body);
}

export async function verifyHubUserTOTP(scope: ApiScope, user: HubUser, code: string) {
  return apiPost<ApiEnvelope<{ user: HubUser }>>(
    scope,
    `/api/v1/access/users/${encodeURIComponent(user.id)}/totp/verify`,
    { code }
  ).then((body) => body.user);
}

export async function verifyCurrentHubUserTOTP(scope: ApiScope, code: string) {
  return apiPost<ApiEnvelope<{ user: HubUser }>>(
    scope,
    "/api/v1/auth/totp/verify",
    { code }
  ).then((body) => body.user);
}

export async function disableHubUserTOTP(scope: ApiScope, user: HubUser) {
  return apiDelete<ApiEnvelope<{ user: HubUser }>>(
    scope,
    `/api/v1/access/users/${encodeURIComponent(user.id)}/totp`
  ).then((body) => body.user);
}

export async function deleteHubUser(scope: ApiScope, user: HubUser) {
  return apiDelete<void>(
    scope,
    `/api/v1/access/users/${encodeURIComponent(user.id)}`
  );
}

export async function createDeployment(
  scope: ApiScope,
  input: {
    version: string;
    commit_sha?: string;
  }
) {
  const params = query(scope);
  return apiPost<ApiEnvelope<{ deployment: Deployment; acknowledged_findings?: number }>>(
    scope,
    `/api/v1/deployments?${params}`,
    input
  );
}

export async function loadDeployments(scope: ApiScope) {
  return apiGet<ApiEnvelope<{ deployments: Deployment[] }>>(
    scope,
    `/api/v1/deployments?${query(scope)}`
  ).then((body) => body.deployments ?? []);
}

function trafficQuery(scope: ApiScope, range: TrafficTimeRange) {
  const params = new URLSearchParams(query(scope));
  params.set("since", range.since);
  params.set("until", range.until);
  return params;
}

export async function loadTraffic(scope: ApiScope, range: TrafficTimeRange, signal?: AbortSignal) {
  return apiGet<ApiEnvelope<{ traffic: TrafficOverview }>>(
    scope,
    `/api/v1/traffic?${trafficQuery(scope, range).toString()}`,
    signal
  ).then((body) => body.traffic);
}

export async function loadTrafficIPDetail(scope: ApiScope, ip: string, range: TrafficTimeRange, signal?: AbortSignal) {
  return apiGet<ApiEnvelope<{ ip: TrafficIPDetail }>>(
    scope,
    `/api/v1/traffic/ips/${encodeURIComponent(ip)}?${trafficQuery(scope, range).toString()}`,
    signal
  ).then((body) => body.ip);
}

export async function updateTrafficIPPolicy(
  scope: ApiScope,
  ip: string,
  policy: "neutral" | "trusted" | "blocked",
  reason: string
) {
  return apiPatch<ApiEnvelope<{ policy: TrafficIPPolicy }>>(
    scope,
    `/api/v1/traffic/ips/${encodeURIComponent(ip)}/policy?${query(scope)}`,
    { policy, reason }
  ).then((body) => body.policy);
}

export async function loadTrafficUserAgentDetail(scope: ApiScope, hash: string, range: TrafficTimeRange, signal?: AbortSignal) {
  return apiGet<ApiEnvelope<{ user_agent: TrafficUserAgentDetail }>>(
    scope,
    `/api/v1/traffic/user-agents/${encodeURIComponent(hash)}?${trafficQuery(scope, range).toString()}`,
    signal
  ).then((body) => body.user_agent);
}

export async function loadTrafficBots(scope: ApiScope, range: TrafficTimeRange, signal?: AbortSignal) {
  const params = trafficQuery(scope, range);
  params.set("limit", "100");
  return apiGet<TrafficBotsResponse>(
    scope,
    `/api/v1/traffic/bots?${params.toString()}`,
    signal
  );
}

export async function loadModelAnalysisReportsForFinding(scope: ApiScope, finding: HubFinding) {
  const params = new URLSearchParams(query(scope));
  params.set("limit", "50");
  return apiGet<ApiEnvelope<{ reports: ModelAnalysisReport[] }>>(
    scope,
    `/api/v1/findings/${encodeURIComponent(finding.id)}/model-analysis?${params.toString()}`
  ).then((body) => body.reports ?? []);
}

export async function updateBrowserAllowlistEntryStatus(
  scope: ApiScope,
  entry: BrowserAllowlistEntry,
  status: string,
  reason: string,
  approved_by: string
) {
  return apiPatch<ApiEnvelope<{ entry: BrowserAllowlistEntry }>>(
    scope,
    `/api/v1/browser/script-allowlist/${encodeURIComponent(entry.id)}/status`,
    { status, reason, approved_by }
  ).then((body) => body.entry);
}

function friendlyError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  if (/failed to fetch|networkerror|load failed/i.test(message)) {
    return "Hub unavailable";
  }
  if (/502|bad gateway/i.test(message)) {
    return "Hub unavailable (502 Bad Gateway)";
  }
  if (/service unavailable|503/i.test(message)) {
    return "Hub unavailable (503 Service Unavailable)";
  }
  return message;
}

function nonNegativeNumber(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function findingSummary(value: unknown): HubFindingSummary | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const statusCounts = numberMap(record.status_counts ?? record.statusCounts);
  const severityCounts = numberMap(record.severity_counts ?? record.severityCounts);
  const openSeverityCounts = numberMap(record.open_severity_counts ?? record.openSeverityCounts);
  if (!statusCounts && !severityCounts && !openSeverityCounts) {
    return undefined;
  }
  return {
    openSeverityCounts,
    severityCounts,
    statusCounts
  };
}

function numberMap(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const result: Record<string, number> = {};
  for (const [key, item] of Object.entries(value)) {
    const count = nonNegativeNumber(item);
    if (count !== undefined) {
      result[key] = count;
    }
  }
  return result;
}

function estateScopeChoices(baseUrl: string, organizations: InventoryOrganization[]): Omit<DashboardInstanceSnapshot, "data">[] {
  return organizations.flatMap((organization) =>
    organization.projects.flatMap((project) =>
      project.environments.flatMap((environment) => {
        if (environment.apps.length === 0) {
          return [{
            environment,
            organization,
            project,
            scope: {
              app: "",
              baseUrl,
              environment: environment.slug,
              org: organization.slug,
              project: project.slug
            }
          }];
        }
        return environment.apps.map((app) => ({
          app,
          environment,
          organization,
          project,
          scope: {
            app: app.slug,
            baseUrl,
            environment: environment.slug,
            org: organization.slug,
            project: project.slug
          }
        }));
      })
    )
  );
}

function sortTimelineNewestFirst(events: TimelineEvent[]) {
  return [...events].sort((left, right) => {
    const eventTimeDiff = new Date(right.event_time).getTime() - new Date(left.event_time).getTime();
    if (eventTimeDiff !== 0) {
      return eventTimeDiff;
    }
    return new Date(right.received_time).getTime() - new Date(left.received_time).getTime();
  });
}
