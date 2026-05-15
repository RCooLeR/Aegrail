import type {
  ApiScope,
  BrowserAllowlistEntry,
  BrowserScript,
  CoverageRecord,
  DashboardData,
  HubAuthMe,
  Deployment,
  HubFinding,
  HubHealth,
  HubUser,
  HubUserTOTPEnrollment,
  InventoryEnvironment,
  InventoryOrganization,
  InventoryProject,
  ModelAnalysisReport,
  MonitoredApp,
  RequestState,
  RuleDefinition,
  TimelineEvent,
  Topology
} from "./types";

type ApiEnvelope<T> = Record<string, unknown> & T;

const defaults = {
  health: null as HubHealth | null,
  findings: [] as HubFinding[],
  timeline: [] as TimelineEvent[],
  coverage: [] as CoverageRecord[],
  scopes: [] as InventoryOrganization[],
  topology: { counts: {}, apps: [], services: [], hosts: [], agents: [] } as Topology,
  deployments: [] as Deployment[],
  browserScripts: [] as BrowserScript[],
  allowlist: [] as BrowserAllowlistEntry[],
  reports: [] as ModelAnalysisReport[],
  rules: [] as RuleDefinition[]
};

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

async function apiGet<T>(scope: ApiScope, path: string): Promise<T> {
  const response = await fetch(joinUrl(scope, path), {
    credentials: "include",
    headers: { Accept: "application/json" }
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

async function apiPatch<T>(scope: ApiScope, path: string, body: unknown): Promise<T> {
  const response = await fetch(joinUrl(scope, path), {
    credentials: "include",
    method: "PATCH",
    headers: {
      Accept: "application/json",
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
      Accept: "application/json",
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

export class MFARequiredError extends Error {
  constructor() {
    super("mfa required");
    this.name = "MFARequiredError";
  }
}

export async function loadAuthMe(scope: ApiScope) {
  return apiGet<HubAuthMe>(scope, "/api/v1/auth/me");
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
      Accept: "application/json",
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
  return (await response.json()) as ApiEnvelope<{ user: HubUser; expires_at: string }>;
}

export async function logoutHubUser(scope: ApiScope) {
  return apiPost<ApiEnvelope<{ ok: boolean }>>(scope, "/api/v1/auth/logout", {});
}

async function state<T>(request: Promise<T>, fallback: T): Promise<RequestState<T>> {
  try {
    return { data: await request };
  } catch (error) {
    return { data: fallback, error: friendlyError(error) };
  }
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
    deployments,
    browserScripts,
    allowlist,
    reports,
    rules
  ] = await Promise.all([
    state(apiGet<HubHealth>(scope, "/healthz"), defaults.health),
    state(
      apiGet<ApiEnvelope<{ findings: HubFinding[] }>>(scope, `/api/v1/findings?${scoped}&limit=200`).then(
        (body) => body.findings ?? []
      ),
      defaults.findings
    ),
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
      apiGet<ApiEnvelope<{ deployments: Deployment[] }>>(scope, `/api/v1/deployments?${scoped}`).then(
        (body) => body.deployments ?? []
      ),
      defaults.deployments
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
      apiGet<ApiEnvelope<{ reports: ModelAnalysisReport[] }>>(
        scope,
        `/api/v1/reports/model-analysis?${scoped}&limit=50`
      ).then((body) => body.reports ?? []),
      defaults.reports
    ),
    state(
      apiGet<ApiEnvelope<{ rules: RuleDefinition[] }>>(scope, "/api/v1/rules").then((body) => body.rules ?? []),
      defaults.rules
    )
  ]);

  return { health, findings, timeline, coverage, scopes, topology, deployments, browserScripts, allowlist, reports, rules };
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
  const instances = await Promise.all(
    choices.map(async (choice) => ({
      ...choice,
      data: await loadDashboard(choice.scope)
    }))
  );

  return { health, instances, rules, scopes };
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
  return apiPatch(scope, `/api/v1/findings/${encodeURIComponent(finding.id)}/status?${params}`, {
    status,
    actor,
    reason,
    note
  });
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

export async function enrollHubUserTOTP(scope: ApiScope, user: HubUser) {
  return apiPost<ApiEnvelope<{ enrollment: HubUserTOTPEnrollment; user: HubUser }>>(
    scope,
    `/api/v1/access/users/${encodeURIComponent(user.id)}/totp`,
    { issuer: "Aegrail" }
  ).then((body) => body);
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
