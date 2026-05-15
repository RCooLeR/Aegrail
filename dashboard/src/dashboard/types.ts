import type { InstanceModel } from "../estate";
import type { HubFinding, ModelAnalysisReport, TimelineEvent } from "../types";

export type ViewKey = "overview" | "companies" | "sites" | "nodes" | "issues" | "issue" | "signals" | "reports" | "settings";

export type ActionState = {
  actor: string;
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

export type DashboardStats = {
  affectedCompanies: number;
  coverageProblems: number;
  criticalIssues: number;
  highIssues: number;
  offlineNodes: number;
  signals: number;
};
