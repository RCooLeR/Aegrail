import { buildEstateModel, collectorIsProblem, type CompanyModel, type EstateModel, type InstanceModel } from "../../estate";
import type { HubFinding, RuleDefinition, TimelineEvent } from "../../types";
import { severityRank } from "../config/navigation";
import type { DashboardStats, FilterState, IssueRow, ReportRow, SignalRow, SiteRow, ViewKey } from "../types";
import { newest, titleCase } from "../utils/time";

export function buildSiteRows(instances: InstanceModel[]): SiteRow[] {
  const groups = new Map<string, InstanceModel[]>();
  for (const instance of instances) {
    const key = `${instance.companySlug}:${instance.projectSlug}`;
    groups.set(key, [...(groups.get(key) ?? []), instance]);
  }
  return Array.from(groups.entries()).map(([key, groupInstances]) => {
    const first = groupInstances[0];
    const status = worstStatus(groupInstances);
    const worst = sortIssueRows(buildIssueRows(groupInstances, new Map())).find((row) => row.finding.status === "open");
    return {
      agentActive: groupInstances.reduce((sum, instance) => sum + instance.activeAgentCount, 0),
      agentCount: groupInstances.reduce((sum, instance) => sum + instance.agentCount, 0),
      companyName: first.companyName,
      companySlug: first.companySlug,
      criticalIssues: groupInstances.reduce((sum, instance) => sum + instance.criticalFindings, 0),
      instances: groupInstances,
      key,
      lastSignalAt: newest(groupInstances.map((instance) => instance.lastSignalAt)),
      openIssues: groupInstances.reduce((sum, instance) => sum + instance.openFindings, 0),
      projectName: first.projectName,
      projectSlug: first.projectSlug,
      status,
      statusReason: worst?.finding.title ?? groupInstances.find((instance) => instance.status !== "healthy")?.statusReason ?? "OK"
    };
  }).sort((left, right) => statusRank(right.status) - statusRank(left.status) || right.openIssues - left.openIssues || left.projectName.localeCompare(right.projectName));
}

export function companiesFromInstances(instances: InstanceModel[]): CompanyModel[] {
  return buildEstateModel(instances.map((instance) => instance.snapshot)).companies;
}

export function filterInstances(instances: InstanceModel[], filters: FilterState) {
  const query = filters.query.trim().toLowerCase();
  return instances.filter((instance) => {
    if (filters.company !== "all" && instance.companySlug !== filters.company) return false;
    if (filters.site !== "all" && `${instance.companySlug}:${instance.projectSlug}` !== filters.site) return false;
    if (filters.node !== "all" && instance.key !== filters.node) return false;
    if (query && ![instance.companyName, instance.projectName, instance.environmentName, instance.appName, instance.appKind].some((value) => value.toLowerCase().includes(query))) {
      return instance.data.findings.data.some((finding) => [finding.title, finding.summary, finding.rule_id].filter(Boolean).some((value) => String(value).toLowerCase().includes(query))) ||
        instance.data.timeline.data.some((event) => [event.type, event.message, event.target].filter(Boolean).some((value) => String(value).toLowerCase().includes(query)));
    }
    return true;
  });
}

export function buildIssueRows(instances: InstanceModel[], ruleByID: Map<string, RuleDefinition>): IssueRow[] {
  return sortIssueRows(instances.flatMap((instance) =>
    instance.data.findings.data.map((finding) => ({
      finding,
      instance,
      service: serviceForFinding(finding, ruleByID.get(finding.rule_id))
    }))
  ));
}

export function filterIssueRows(rows: IssueRow[], filters: FilterState) {
  const query = filters.query.trim().toLowerCase();
  return rows.filter((row) => {
    if (filters.severity !== "all" && row.finding.severity !== filters.severity) return false;
    if (!query) return true;
    return [row.finding.title, row.finding.summary, row.finding.description, row.finding.rule_id, row.instance.companyName, row.instance.projectName, row.service]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });
}

export function sortIssueRows(rows: IssueRow[]) {
  return [...rows].sort((left, right) =>
    (severityRank[right.finding.severity] ?? 0) - (severityRank[left.finding.severity] ?? 0) ||
    new Date(right.finding.last_event_at).getTime() - new Date(left.finding.last_event_at).getTime()
  );
}

export function buildSignalRows(instances: InstanceModel[], issueRows: IssueRow[]): SignalRow[] {
  const issueByEvent = new Map<string, HubFinding>();
  for (const row of issueRows) {
    for (const eventID of row.finding.event_ids) {
      issueByEvent.set(eventID, row.finding);
    }
  }
  return instances.flatMap((instance) =>
    instance.data.timeline.data.map((event) => ({
      event,
      instance,
      issue: issueByEvent.get(event.id),
      service: serviceForEvent(event)
    }))
  ).sort((left, right) => new Date(right.event.event_time).getTime() - new Date(left.event.event_time).getTime());
}

export function filterSignalRows(rows: SignalRow[], filters: FilterState) {
  const query = filters.query.trim().toLowerCase();
  return rows.filter((row) => {
    if (filters.severity !== "all" && row.event.severity !== filters.severity) return false;
    if (!query) return true;
    return signalSearchValues(row).some((value) => value.toLowerCase().includes(query));
  });
}

export function buildReportRows(instances: InstanceModel[]): ReportRow[] {
  return instances.flatMap((instance) =>
    instance.data.reports.data.map((report) => ({ instance, report }))
  ).sort((left, right) => new Date(right.report.generated_at).getTime() - new Date(left.report.generated_at).getTime());
}

export function summarizeEstate(instances: InstanceModel[], issueRows: IssueRow[], signalRows: SignalRow[]): DashboardStats {
  const openRows = issueRows.filter((row) => row.finding.status === "open");
  return {
    affectedCompanies: new Set(openRows.map((row) => row.instance.companySlug)).size,
    coverageProblems: instances.filter((instance) => instance.coverageWarnings > 0 || instance.collectors.some(collectorIsProblem)).length,
    criticalIssues: openRows.filter((row) => row.finding.severity === "critical").length,
    highIssues: openRows.filter((row) => row.finding.severity === "high").length,
    offlineNodes: instances.filter((instance) => instance.activeAgentCount === 0 || instance.staleAgents > 0).length,
    signals: signalRows.length
  };
}

export function serviceFromCollector(key: string) {
  switch (key) {
    case "files": return "Files";
    case "database": return "Database";
    case "browser": return "Browser";
    case "config": return "Config";
    default: return titleCase(key);
  }
}

export function collectorLabel(event: TimelineEvent) {
  if (event.type.startsWith("db.")) return "DB collector";
  if (event.type.startsWith("file.")) return "Files collector";
  if (event.type.startsWith("browser.")) return "Browser collector";
  if (event.type.includes("config")) return "Config collector";
  if (event.type.startsWith("agent.")) return "Agent";
  return event.labels.collector || "Hub";
}

export function signalTypeLabel(event: TimelineEvent) {
  const type = event.type;
  if (type.includes("entity") && type.includes("db")) return "Database change";
  if (type.startsWith("db.")) return "Database check";
  if (type.includes("file") && type.includes("added")) return "File added";
  if (type.startsWith("file.")) return "File changed";
  if (type.includes("script")) return "Browser script";
  if (type.includes("coverage")) return "Coverage warning";
  if (type.startsWith("agent.")) return "Agent signal";
  return titleCase(type.replace(/[._-]/g, " "));
}

export function nodeLabel(instance: InstanceModel) {
  return `${environmentLabel(instance.environmentName)} ${appKindLabel(instance.appKind)}`.trim();
}

export function issueStatusLabel(status: string, reason = "") {
  if (status === "acknowledged" && reason === "baseline_accepted") {
    return "Baseline";
  }
  switch (status) {
    case "open": return "New";
    case "acknowledged": return "Triaged";
    case "resolved": return "Fixed";
    case "false_positive": return "False positive";
    default: return titleCase(status.replace(/[_-]/g, " "));
  }
}

export function recommendedAction(row: IssueRow, rule?: RuleDefinition) {
  if (rule?.action_hints?.length) {
    return rule.action_hints.join(" ");
  }
  switch (row.service) {
    case "Browser": return "Check whether the script came from a known plugin, tag manager, checkout provider, or marketing tool. Allow it only after confirming it is expected.";
    case "Database": return "Review the account or option change, confirm it with the site owner, and remove unauthorized access before marking fixed.";
    case "Files": return "Compare the changed file with a known deploy or CMS update. Treat executable files in uploads as suspicious.";
    case "Config": return "Fix the collector or site configuration, then wait for a clean scan.";
    default: return "Review the linked signals, confirm ownership, and update the issue status.";
  }
}

export function severityTone(value: string) {
  switch (value) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "info";
  }
}

export function statusTone(value: string) {
  const lower = value.toLowerCase();
  if (["critical", "missing", "failed", "new"].includes(lower)) return "critical";
  if (["warning", "stale", "required", "triaged", "medium"].includes(lower)) return "warning";
  if (["healthy", "fresh", "fixed", "ok", "enabled", "active", "completed", "baseline"].includes(lower)) return "healthy";
  if (["disabled", "optional"].includes(lower)) return "neutral";
  return "neutral";
}

export function viewSubtitle(view: ViewKey, filters: FilterState, estate: EstateModel) {
  const company = filters.company === "all" ? "all companies" : estate.companies.find((item) => item.companySlug === filters.company)?.companyName ?? filters.company;
  switch (view) {
    case "overview": return `What needs attention right now / ${company}`;
    case "companies": return "Customers and business groups";
    case "sites": return "Websites and projects";
    case "nodes": return "Monitored runtime targets";
    case "issues": return "Working queue";
    case "issue": return "Issue investigation";
    case "signals": return "Raw events for investigation";
    case "reports": return "Human-readable summaries";
    case "settings": return "Access, scope, and defaults";
  }
}

function worstStatus(instances: InstanceModel[]): "critical" | "warning" | "healthy" {
  if (instances.some((instance) => instance.status === "critical")) return "critical";
  if (instances.some((instance) => instance.status === "warning")) return "warning";
  return "healthy";
}

function statusRank(status: string) {
  switch (status) {
    case "critical": return 3;
    case "warning": return 2;
    case "healthy": return 1;
    default: return 0;
  }
}

function serviceForFinding(finding: HubFinding, rule?: RuleDefinition) {
  const text = [finding.rule_id, finding.title, finding.summary, finding.description, rule?.category].filter(Boolean).join(" ").toLowerCase();
  if (text.includes("browser") || text.includes("script") || text.includes("tag-manager")) return "Browser";
  if (text.includes("database") || text.includes("db.") || text.includes("wordpress user") || text.includes("employee")) return "Database";
  if (text.includes("file")) return "Files";
  if (text.includes("config") || text.includes("coverage")) return "Config";
  if (text.includes("agent")) return "Agent";
  return "Web";
}

function serviceForEvent(event: TimelineEvent) {
  if (event.type.startsWith("browser.")) return "Browser";
  if (event.type.startsWith("db.")) return "Database";
  if (event.type.startsWith("file.")) return "Files";
  if (event.type.includes("config") || event.type.includes("coverage")) return "Config";
  if (event.type.startsWith("agent.")) return "Agent";
  return "Web";
}

function signalSearchValues(row: SignalRow) {
  return [
    row.event.type,
    row.event.message,
    row.event.target,
    row.event.host,
    row.event.hostname,
    row.event.agent,
    row.event.severity,
    row.service,
    collectorLabel(row.event),
    signalTypeLabel(row.event),
    row.instance.companyName,
    row.instance.companySlug,
    row.instance.projectName,
    row.instance.projectSlug,
    row.instance.environmentName,
    row.instance.appName,
    row.instance.appKind,
    row.issue?.title,
    row.issue?.summary,
    row.issue?.description,
    row.issue?.rule_id,
    row.issue?.status,
    ...Object.values(row.event.labels),
    ...payloadSearchValues(row.event.payload)
  ].filter((value): value is string => typeof value === "string" && value.trim() !== "").map((value) => value.toLowerCase());
}

function payloadSearchValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (typeof value === "number" || typeof value === "boolean") return [String(value)];
  if (Array.isArray(value)) return value.flatMap(payloadSearchValues);
  if (value && typeof value === "object") return Object.values(value as Record<string, unknown>).flatMap(payloadSearchValues);
  return [];
}

function environmentLabel(value: string) {
  const lower = value.toLowerCase();
  if (lower === "prod" || lower === "production") return "production";
  if (lower === "stage" || lower === "staging") return "staging";
  if (lower === "dev" || lower === "development") return "development";
  if (lower === "local") return "local";
  return value;
}

function appKindLabel(kind: string) {
  switch (kind) {
    case "wordpress-multisite": return "WordPress Network";
    case "wordpress": return "WordPress";
    case "prestashop": return "PrestaShop";
    default: return titleCase(kind || "app");
  }
}
