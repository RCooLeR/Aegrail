import type { InstanceModel } from "../estate";
import type { BrowserAllowlistEntry, BrowserScript, Deployment, HubFinding, ModelAnalysisReport, TimelineEvent } from "../types";

export type ViewKey = "overview" | "companies" | "sites" | "nodes" | "issues" | "issue" | "signals" | "browser" | "deployments" | "reports" | "settings";

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

export type SignalRow = {
  event: TimelineEvent;
  instance: InstanceModel;
  issue?: HubFinding;
  service: string;
};

export type ReportRow = {
  instance: InstanceModel;
  report: ModelAnalysisReport;
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

export type DashboardStats = {
  affectedCompanies: number;
  coverageProblems: number;
  criticalIssues: number;
  highIssues: number;
  offlineNodes: number;
  signals: number;
};
