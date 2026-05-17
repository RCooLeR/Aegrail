export type ApiScope = {
  baseUrl: string;
  org: string;
  project: string;
  environment: string;
  app: string;
};

export type RequestState<T> = {
  data: T;
  error?: string;
};

export type Severity = "critical" | "high" | "medium" | "low" | "info" | string;

export type HubFinding = {
  id: string;
  rule_id: string;
  rule_version: string;
  dedupe_key: string;
  severity: Severity;
  confidence: string;
  title: string;
  summary?: string;
  description?: string;
  operator_action?: Record<string, unknown>;
  event_ids: string[];
  first_event_at: string;
  last_event_at: string;
  status: string;
  status_reason?: string;
  status_note?: string;
  status_actor?: string;
  status_updated_at: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type TimelineEvent = {
  id: string;
  batch_id: string;
  app?: string;
  service?: string;
  host: string;
  hostname: string;
  agent: string;
  event_time: string;
  received_time: string;
  type: string;
  target: string;
  severity: Severity;
  message: string;
  region?: string;
  labels: Record<string, string>;
  payload: Record<string, unknown>;
};

export type CoverageRecord = {
  event_id: string;
  app?: string;
  host: string;
  hostname: string;
  agent: string;
  reported_at: string;
  received_time: string;
  site: string;
  site_kind: string;
  coverage_level: string;
  labels: Record<string, string>;
  payload: Record<string, unknown>;
};

export type MonitoredApp = {
  id: string;
  slug: string;
  name: string;
  kind: string;
  services?: Service[];
  created_at: string;
  updated_at: string;
};

export type InventoryEnvironment = {
  id: string;
  project_id: string;
  slug: string;
  name: string;
  apps: MonitoredApp[];
  hosts?: Host[];
  created_at: string;
  updated_at: string;
};

export type InventoryProject = {
  id: string;
  organization_id: string;
  slug: string;
  name: string;
  environments: InventoryEnvironment[];
  created_at: string;
  updated_at: string;
};

export type InventoryOrganization = {
  id: string;
  slug: string;
  name: string;
  projects: InventoryProject[];
  created_at: string;
  updated_at: string;
};

export type Service = {
  id: string;
  app_id: string;
  slug: string;
  name: string;
  role: string;
  created_at: string;
  updated_at: string;
};

export type Host = {
  id: string;
  slug: string;
  hostname: string;
  region?: string;
  labels: Record<string, string>;
  agents?: Agent[];
  created_at: string;
  updated_at: string;
};

export type Agent = {
  id: string;
  host_id: string;
  agent_id: string;
  fingerprint: string;
  version?: string;
  last_seen_at?: string;
  wire_protocol?: string;
  node_public_key?: string;
  created_at: string;
  updated_at: string;
};

export type NodeProvisioning = {
  host: Host;
  agent: Agent;
  node_id: string;
  node_secret: string;
  hub_public_key: string;
  sample_config: string;
};

export type Topology = {
  counts: Record<string, number>;
  apps: MonitoredApp[];
  services: Service[];
  hosts: Host[];
  agents: Agent[];
};

export type Deployment = {
  id: string;
  app_id?: string;
  version: string;
  commit_sha?: string;
  actor?: string;
  started_at: string;
  finished_at?: string;
  created_at: string;
};

export type BrowserScript = {
  event_id: string;
  app?: string;
  host: string;
  hostname: string;
  agent: string;
  event_time: string;
  received_time: string;
  type: string;
  target: string;
  severity: Severity;
  page_url?: string;
  final_url?: string;
  mode?: string;
  source_type?: string;
  url?: string;
  url_redacted?: string;
  domain?: string;
  path?: string;
  sha256?: string;
  inline_bytes?: number;
  tag_manager: boolean;
  tag_manager_ids?: string[];
  labels: Record<string, string>;
  payload: Record<string, unknown>;
};

export type BrowserAllowlistEntry = {
  id: string;
  app_id: string;
  page_url: string;
  kind: string;
  value: string;
  reason?: string;
  approved_by?: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type HubUser = {
  id: string;
  email: string;
  display_name: string;
  access_level: string;
  status: string;
  two_factor_required: boolean;
  two_factor_enabled: boolean;
  two_factor_pending?: boolean;
  totp_enrolled_at?: string;
  pending_totp_started_at?: string;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
};

export type HubAuthMe = {
  authenticated: boolean;
  auth_configured: boolean;
  csrf_token?: string;
  dashboard_ready?: boolean;
  protocol?: string;
  requires_bootstrap: boolean;
  totp_setup_required?: boolean;
  user?: HubUser;
};

export type HubUserTOTPEnrollment = {
  otpauth_url: string;
  qr_code_data_url: string;
  secret: string;
};

export type ModelAnalysisReport = {
  id: string;
  app_id?: string;
  schema: string;
  status: string;
  model_provider?: string;
  model_name?: string;
  prompt_template_id: string;
  prompt_template_version: string;
  evidence_bundle_sha256: string;
  source_finding_ids: string[];
  analysis?: string;
  error?: string;
  total_duration_millis?: number;
  prompt_eval_count?: number;
  eval_count?: number;
  generated_at: string;
  created_at: string;
};

export type RuleDefinition = {
  id: string;
  version: string;
  title: string;
  category: string;
  platforms: string[];
  evidence_types: string[];
  action_hints: string[];
};

export type HubHealth = {
  status: string;
  service: string;
  mode?: string;
};

export type DashboardData = {
  health: RequestState<HubHealth | null>;
  findings: RequestState<HubFinding[]>;
  timeline: RequestState<TimelineEvent[]>;
  coverage: RequestState<CoverageRecord[]>;
  scopes: RequestState<InventoryOrganization[]>;
  topology: RequestState<Topology>;
  deployments: RequestState<Deployment[]>;
  browserScripts: RequestState<BrowserScript[]>;
  allowlist: RequestState<BrowserAllowlistEntry[]>;
  reports: RequestState<ModelAnalysisReport[]>;
  rules: RequestState<RuleDefinition[]>;
};
