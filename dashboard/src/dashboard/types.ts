import type { InstanceModel } from "../estate";
import type {
  BrowserAllowlistEntry,
  BrowserScript,
  Deployment,
  HubFinding,
  TimelineEvent,
  TrafficBotsResponse,
  TrafficIPDetail,
  TrafficOverview,
  TrafficUserAgentDetail
} from "../types";

export type ViewKey = "overview" | "nodes" | "issues" | "issue" | "signals" | "traffic" | "bots" | "browser" | "deployments" | "settings";

export type ActionState = {
  actor: string;
  model: string;
  reason: string;
  note: string;
};

export type FilterState = {
  company: string;
  site: string;
  node: string;
  severity: string;
  query: string;
};

export type SiteRow = {
  agentActive: number;
  agentCount: number;
  companyName: string;
  companySlug: string;
  criticalIssues: number;
  findingCountsExact: boolean;
  instances: InstanceModel[];
  key: string;
  lastSignalAt?: string;
  openIssues: number;
  projectName: string;
  projectSlug: string;
  status: "critical" | "warning" | "healthy";
  statusReason: string;
};

export type IssueRow = {
  finding: HubFinding;
  instance: InstanceModel;
  service: string;
};

export type IssueQueuePageSize = 25 | 50 | 100 | 250 | 500 | "all";

export type TrafficTimeframe = "15m" | "30m" | "1h" | "3h" | "6h" | "12h" | "24h" | "3d" | "7d" | "10d" | "14d" | "30d";

export type TrafficTimeRange = {
  since: string;
  until: string;
};

export type SignalRow = {
  event: TimelineEvent;
  instance: InstanceModel;
  issue?: HubFinding;
  service: string;
};

export type BrowserScriptRow = {
  instance: InstanceModel;
  script: BrowserScript;
  allowlisted: boolean;
};

export type AllowlistRow = {
  instance: InstanceModel;
  entry: BrowserAllowlistEntry;
};

export type DeploymentRow = {
  instance: InstanceModel;
  deployment: Deployment;
};

export type TrafficScopeData = {
  instance: InstanceModel;
  traffic: TrafficOverview;
};

export type TrafficBotsScopeData = {
  instance: InstanceModel;
  traffic: TrafficBotsResponse;
};

export type TrafficIPDetailState = {
  detail: TrafficIPDetail;
  instance: InstanceModel;
};

export type TrafficUserAgentDetailState = {
  detail: TrafficUserAgentDetail;
  instance: InstanceModel;
};

export type DashboardStats = {
  affectedCompanies: number;
  coverageProblems: number;
  criticalIssues: number;
  findingCountsExact: boolean;
  highIssues: number;
  offlineNodes: number;
  signals: number;
};
