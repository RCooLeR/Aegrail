import type { DashboardInstanceSnapshot } from "./api";
import type { ApiScope, CoverageRecord, HubFinding, TimelineEvent } from "./types";

export type EstateStatus = "critical" | "warning" | "healthy";
export type CollectorKey = "files" | "database" | "browser" | "config";
export type CollectorStatus = "fresh" | "warning" | "stale" | "missing" | "disabled";

export type CollectorState = {
  detail: string;
  key: CollectorKey;
  label: string;
  lastSeenAt?: string;
  status: CollectorStatus;
};

export type InstanceModel = {
  activeAgentCount: number;
  agentCount: number;
  appKind: string;
  appName: string;
  appSlug: string;
  collectors: CollectorState[];
  companyName: string;
  companySlug: string;
  coverageLevel: string;
  coverageWarnings: number;
  criticalFindings: number;
  data: DashboardInstanceSnapshot["data"];
  environmentName: string;
  environmentSlug: string;
  highFindings: number;
  iconUrls: string[];
  key: string;
  lastSignalAt?: string;
  mediumFindings: number;
  openFindings: number;
  projectName: string;
  projectSlug: string;
  scope: ApiScope;
  snapshot: DashboardInstanceSnapshot;
  staleAgents: number;
  status: EstateStatus;
  statusReason: string;
  totalFindings: number;
  worstFinding?: HubFinding;
};

export type CompanyModel = {
  companyName: string;
  companySlug: string;
  coverageWarnings: number;
  criticalFindings: number;
  highFindings: number;
  iconUrls: string[];
  instances: InstanceModel[];
  lastSignalAt?: string;
  mediumFindings: number;
  openFindings: number;
  siteCount: number;
  staleAgents: number;
  status: EstateStatus;
  statusReason: string;
  totalFindings: number;
  worstFinding?: HubFinding;
};

export type EstateModel = {
  companies: CompanyModel[];
  instances: InstanceModel[];
  totals: {
    activeAgents: number;
    companies: number;
    criticalFindings: number;
    highFindings: number;
    instances: number;
    openFindings: number;
    sites: number;
    staleAgents: number;
    warningInstances: number;
  };
};

const staleSignalMs = 30 * 60 * 1000;

const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export function buildEstateModel(snapshots: DashboardInstanceSnapshot[]): EstateModel {
  const instances = snapshots.map(buildInstanceModel);
  const companyMap = new Map<string, InstanceModel[]>();

  for (const instance of instances) {
    const existing = companyMap.get(instance.companySlug) ?? [];
    existing.push(instance);
    companyMap.set(instance.companySlug, existing);
  }

  const companies = Array.from(companyMap.entries())
    .map(([, companyInstances]) => buildCompanyModel(companyInstances))
    .sort((left, right) => statusRank(right.status) - statusRank(left.status) || left.companyName.localeCompare(right.companyName));

  const siteKeys = new Set(instances.map((instance) => `${instance.companySlug}:${instance.projectSlug}`));

  return {
    companies,
    instances,
    totals: {
      activeAgents: sum(instances, (instance) => instance.activeAgentCount),
      companies: companies.length,
      criticalFindings: sum(instances, (instance) => instance.criticalFindings),
      highFindings: sum(instances, (instance) => instance.highFindings),
      instances: instances.length,
      openFindings: sum(instances, (instance) => instance.openFindings),
      sites: siteKeys.size,
      staleAgents: sum(instances, (instance) => instance.staleAgents),
      warningInstances: instances.filter((instance) => instance.status !== "healthy").length
    }
  };
}

export function instanceScopeKey(scope: ApiScope) {
  return `${scope.org}:${scope.project}:${scope.environment}:${scope.app}`;
}

function instanceIconCandidates(snapshot: DashboardInstanceSnapshot) {
  const declaredIcons: string[] = [];
  const origins: string[] = [];
  const data = snapshot.data;
  const addOrigin = (value: unknown) => {
    const origin = safeURLOrigin(value);
    if (origin) {
      origins.push(origin);
    }
  };
  const addDeclaredIcons = (payload: Record<string, unknown>) => {
    for (const url of payloadIconURLs(payload)) {
      declaredIcons.push(url);
      addOrigin(url);
    }
  };

  for (const script of data.browserScripts.data) {
    addOrigin(script.final_url);
    addOrigin(script.page_url);
    addDeclaredIcons(script.payload);
  }
  for (const entry of data.allowlist.data) {
    addOrigin(entry.page_url);
  }
  for (const event of data.timeline.data) {
    addOrigin(payloadString(event.payload, "final_url"));
    addOrigin(payloadString(event.payload, "page_url"));
    addDeclaredIcons(event.payload);
  }
  for (const finding of data.findings.data) {
    addOrigin(payloadString(finding.metadata, "final_url"));
    addOrigin(payloadString(finding.metadata, "page_url"));
    addDeclaredIcons(finding.metadata);
  }

  const guessedIcons = uniqueStrings(origins).flatMap((origin) => [
    `${origin}/favicon.ico`,
    `${origin}/favicon.svg`,
    `${origin}/apple-touch-icon.png`,
    `${origin}/apple-touch-icon-precomposed.png`
  ]);
  return uniqueStrings([...declaredIcons, ...guessedIcons]);
}

function buildInstanceModel(snapshot: DashboardInstanceSnapshot): InstanceModel {
  const data = snapshot.data;
  const rawOpenFindings = data.findings.data.filter((finding) => finding.status === "open");
  const openFindings = uniqueFindingGroups(rawOpenFindings);
  const worstFinding = sortFindings(openFindings)[0] ?? sortFindings(data.findings.data)[0];
  const criticalFindings = openFindings.filter((finding) => finding.severity === "critical").length;
  const highFindings = openFindings.filter((finding) => finding.severity === "high").length;
  const mediumFindings = openFindings.filter((finding) => finding.severity === "medium").length;
  const latestCoverage = latestCoverageRecord(data.coverage.data);
  const coverageWarnings = data.coverage.data.filter((record) => isCoverageProblem(record.coverage_level)).length;
  const collectors = buildCollectorStates(data.timeline.data, latestCoverage);
  const lastSignalAt = maxTime([
    ...data.timeline.data.map((event) => event.event_time),
    ...data.coverage.data.map((record) => record.reported_at),
    ...data.topology.data.agents.map((agent) => agent.last_seen_at),
    ...data.findings.data.map((finding) => finding.last_event_at)
  ]);
  const freshSignalAgents = new Set([
    ...data.timeline.data.filter((event) => isFresh(event.event_time)).map((event) => event.agent).filter(Boolean),
    ...data.coverage.data.filter((record) => isFresh(record.reported_at)).map((record) => record.agent).filter(Boolean)
  ]);
  const activeAgents = data.topology.data.agents.filter((agent) => isFresh(agent.last_seen_at));
  const hasFreshScopedSignal = freshSignalAgents.size > 0 || Boolean(lastSignalAt && isFresh(lastSignalAt));
  const staleAgents = hasFreshScopedSignal
    ? []
    : data.topology.data.agents.filter((agent) => agent.last_seen_at && !isFresh(agent.last_seen_at));
  const activeAgentCount = Math.max(activeAgents.length, freshSignalAgents.size, hasFreshScopedSignal ? 1 : 0);
  const agentCount = Math.max(data.topology.data.agents.length, freshSignalAgents.size, activeAgentCount);

  const appKind = snapshot.app?.kind || latestCoverage?.site_kind || "app";
  const status = instanceStatus({
    coverageWarnings,
    criticalFindings,
    highFindings,
    lastSignalAt,
    mediumFindings,
    staleAgents: staleAgents.length,
    collectors
  });

  return {
    activeAgentCount,
    agentCount,
    appKind,
    appName: snapshot.app?.name || snapshot.app?.slug || "All apps",
    appSlug: snapshot.app?.slug ?? "",
    collectors,
    companyName: snapshot.organization.name || snapshot.organization.slug,
    companySlug: snapshot.organization.slug,
    coverageLevel: latestCoverage?.coverage_level || "unknown",
    coverageWarnings,
    criticalFindings,
    data,
    environmentName: snapshot.environment.name || snapshot.environment.slug,
    environmentSlug: snapshot.environment.slug,
    highFindings,
    iconUrls: instanceIconCandidates(snapshot),
    key: instanceScopeKey(snapshot.scope),
    lastSignalAt,
    mediumFindings,
    openFindings: openFindings.length,
    projectName: snapshot.project.name || snapshot.project.slug,
    projectSlug: snapshot.project.slug,
    scope: snapshot.scope,
    snapshot,
    staleAgents: staleAgents.length,
    status,
    statusReason: instanceStatusReason(status, {
      coverageWarnings,
      highFindings,
      lastSignalAt,
      mediumFindings,
      staleAgents: staleAgents.length,
      worstFinding
    }),
    totalFindings: data.findings.data.length,
    worstFinding
  };
}

function buildCompanyModel(instances: InstanceModel[]): CompanyModel {
  const first = instances[0];
  const worstFinding = sortFindings(instances.flatMap((instance) => instance.data.findings.data.filter((finding) => finding.status === "open")))[0];
  const status = companyStatus(instances);
  const projectKeys = new Set(instances.map((instance) => instance.projectSlug));

  return {
    companyName: first?.companyName ?? "Unknown company",
    companySlug: first?.companySlug ?? "",
    coverageWarnings: sum(instances, (instance) => instance.coverageWarnings),
    criticalFindings: sum(instances, (instance) => instance.criticalFindings),
    highFindings: sum(instances, (instance) => instance.highFindings),
    iconUrls: uniqueStrings(instances.flatMap((instance) => instance.iconUrls)),
    instances,
    lastSignalAt: maxTime(instances.map((instance) => instance.lastSignalAt)),
    mediumFindings: sum(instances, (instance) => instance.mediumFindings),
    openFindings: sum(instances, (instance) => instance.openFindings),
    siteCount: projectKeys.size,
    staleAgents: sum(instances, (instance) => instance.staleAgents),
    status,
    statusReason: companyStatusReason(status, instances, worstFinding),
    totalFindings: sum(instances, (instance) => instance.totalFindings),
    worstFinding
  };
}

function buildCollectorStates(events: TimelineEvent[], latestCoverage?: CoverageRecord): CollectorState[] {
  return [
    coverageAwareCollectorState("files", "Files", events, latestCoverage, (event) => event.type.startsWith("file.")),
    coverageAwareCollectorState("database", "Database", events, latestCoverage, (event) => event.type.startsWith("db.")),
    coverageAwareCollectorState("browser", "Browser", events, latestCoverage, (event) => event.type.startsWith("browser.")),
    configCollectorState(latestCoverage)
  ];
}

function configCollectorState(record?: CoverageRecord): CollectorState {
  if (!record) {
    return { detail: "No config coverage record", key: "config", label: "Config", status: "missing" };
  }
  if (configCoverageEnabled(record) === false || record.coverage_level === "disabled") {
    return {
      detail: "Disabled in agent config",
      key: "config",
      label: "Config",
      lastSeenAt: record.reported_at,
      status: "disabled"
    };
  }
  if (!isGoodCoverage(record.coverage_level)) {
    return {
      detail: `Coverage ${record.coverage_level || "unknown"}`,
      key: "config",
      label: "Config",
      lastSeenAt: record.reported_at,
      status: "warning"
    };
  }
  return {
    detail: `Coverage ${record.coverage_level}`,
    key: "config",
    label: "Config",
    lastSeenAt: record.reported_at,
    status: "fresh"
  };
}

function coverageAwareCollectorState(
  key: Exclude<CollectorKey, "config">,
  label: string,
  events: TimelineEvent[],
  latestCoverage: CoverageRecord | undefined,
  predicate: (event: TimelineEvent) => boolean
): CollectorState {
  if (collectorCoverageEnabled(latestCoverage, key) === false) {
    return {
      detail: "Disabled in agent config",
      key,
      label,
      lastSeenAt: latestCoverage?.reported_at,
      status: "disabled"
    };
  }
  return collectorState(key, label, events, predicate);
}

function collectorState(
  key: CollectorKey,
  label: string,
  events: TimelineEvent[],
  predicate: (event: TimelineEvent) => boolean,
  options: { stale?: boolean } = {}
): CollectorState {
  const event = latestEvent(events.filter(predicate), (item) => item.event_time);
  if (!event) {
    return { detail: "No signal in window", key, label, status: "missing" };
  }
  if (["critical", "high", "medium"].includes(event.severity)) {
    return { detail: event.message || event.type, key, label, lastSeenAt: event.event_time, status: "warning" };
  }
  if (options.stale !== false && !isFresh(event.event_time)) {
    return { detail: "Last signal is stale", key, label, lastSeenAt: event.event_time, status: "stale" };
  }
  return { detail: event.type, key, label, lastSeenAt: event.event_time, status: "fresh" };
}

function companyStatus(instances: InstanceModel[]): EstateStatus {
  if (instances.some((instance) => instance.status === "critical")) {
    return "critical";
  }
  if (instances.some((instance) => instance.status === "warning")) {
    return "warning";
  }
  return "healthy";
}

function companyStatusReason(status: EstateStatus, instances: InstanceModel[], worstFinding?: HubFinding) {
  if (status === "critical" && worstFinding) {
    return worstFinding.title;
  }
  const staleAgents = sum(instances, (instance) => instance.staleAgents);
  if (staleAgents > 0) {
    return `${staleAgents} stale agent${staleAgents === 1 ? "" : "s"}`;
  }
  const warnings = sum(instances, (instance) => instance.coverageWarnings);
  if (warnings > 0) {
    return `${warnings} coverage warning${warnings === 1 ? "" : "s"}`;
  }
  if (status === "warning") {
    return "Needs operator review";
  }
  return "No open high-risk signals";
}

function instanceStatus({
  collectors,
  coverageWarnings,
  criticalFindings,
  highFindings,
  lastSignalAt,
  mediumFindings,
  staleAgents
}: {
  collectors: CollectorState[];
  coverageWarnings: number;
  criticalFindings: number;
  highFindings: number;
  lastSignalAt?: string;
  mediumFindings: number;
  staleAgents: number;
}): EstateStatus {
  if (criticalFindings > 0 || highFindings > 0 || staleAgents > 0 || (lastSignalAt && !isFresh(lastSignalAt))) {
    return "critical";
  }
  if (mediumFindings > 0 || coverageWarnings > 0 || collectors.some(collectorIsProblem)) {
    return "warning";
  }
  return "healthy";
}

export function collectorIsProblem(collector: CollectorState) {
  return !["fresh", "disabled"].includes(collector.status);
}

function instanceStatusReason(
  status: EstateStatus,
  input: {
    coverageWarnings: number;
    highFindings: number;
    lastSignalAt?: string;
    mediumFindings: number;
    staleAgents: number;
    worstFinding?: HubFinding;
  }
) {
  if (status === "critical" && input.worstFinding) {
    return input.worstFinding.title;
  }
  if (input.staleAgents > 0) {
    return `${input.staleAgents} stale agent${input.staleAgents === 1 ? "" : "s"}`;
  }
  if (input.lastSignalAt && !isFresh(input.lastSignalAt)) {
    return "No fresh signal";
  }
  if (input.mediumFindings > 0) {
    return `${input.mediumFindings} medium finding${input.mediumFindings === 1 ? "" : "s"}`;
  }
  if (input.coverageWarnings > 0) {
    return `${input.coverageWarnings} coverage warning${input.coverageWarnings === 1 ? "" : "s"}`;
  }
  return "Collectors fresh";
}

function sortFindings(findings: HubFinding[]) {
  return [...findings].sort((left, right) => {
    const severityDiff = (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0);
    if (severityDiff !== 0) {
      return severityDiff;
    }
    return toTime(right.last_event_at) - toTime(left.last_event_at);
  });
}

function uniqueFindingGroups(findings: HubFinding[]) {
  const seen = new Set<string>();
  const groups: HubFinding[] = [];
  for (const finding of sortFindings(findings)) {
    const key = finding.title || finding.rule_id || finding.dedupe_key || finding.id;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    groups.push(finding);
  }
  return groups;
}

function latestCoverageRecord(records: CoverageRecord[]) {
  return latestEvent(records, (record) => record.reported_at);
}

function isGoodCoverage(level: string) {
  return ["complete", "full", "strong"].includes(level);
}

function isCoverageProblem(level: string) {
  return !isGoodCoverage(level) && level !== "disabled";
}

function configCoverageEnabled(record?: CoverageRecord) {
  const coverage = coveragePayload(record);
  const value = coverage?.enabled;
  return typeof value === "boolean" ? value : undefined;
}

function collectorCoverageEnabled(record: CoverageRecord | undefined, key: Exclude<CollectorKey, "config">) {
  const coverage = coveragePayload(record);
  const payloadKey = key === "database" ? "databases" : key;
  const section = coverage?.[payloadKey];
  if (!section || typeof section !== "object" || Array.isArray(section)) {
    return undefined;
  }
  const value = (section as Record<string, unknown>).enabled;
  return typeof value === "boolean" ? value : undefined;
}

function coveragePayload(record?: CoverageRecord) {
  const value = record?.payload.coverage;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function latestEvent<T>(items: T[], time: (item: T) => string | undefined) {
  return items.reduce<T | undefined>((latest, item) => {
    if (!latest) {
      return item;
    }
    return toTime(time(item)) > toTime(time(latest)) ? item : latest;
  }, undefined);
}

function maxTime(values: Array<string | undefined>) {
  const latest = values.reduce((max, value) => Math.max(max, toTime(value)), 0);
  return latest > 0 ? new Date(latest).toISOString() : undefined;
}

function isFresh(value?: string) {
  return Boolean(value && Date.now() - toTime(value) < staleSignalMs);
}

function toTime(value?: string) {
  if (!value) {
    return 0;
  }
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function statusRank(status: EstateStatus) {
  switch (status) {
    case "critical":
      return 3;
    case "warning":
      return 2;
    case "healthy":
      return 1;
  }
}

function sum<T>(items: T[], selector: (item: T) => number) {
  return items.reduce((total, item) => total + selector(item), 0);
}

function safeURLOrigin(value: unknown) {
  if (typeof value !== "string" || value.trim() === "") {
    return "";
  }
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.origin;
  } catch {
    return "";
  }
}

function payloadIconURLs(payload: Record<string, unknown>) {
  const rawIcons = payload.site_icons;
  if (!Array.isArray(rawIcons)) {
    return [];
  }
  return rawIcons
    .map((icon) => {
      if (!icon || typeof icon !== "object" || Array.isArray(icon)) {
        return "";
      }
      const record = icon as Record<string, unknown>;
      return typeof record.url_redacted === "string" ? record.url_redacted : "";
    })
    .filter((value) => safeURLOrigin(value));
}

function payloadString(payload: Record<string, unknown>, key: string) {
  const value = payload[key];
  return typeof value === "string" ? value : "";
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}
