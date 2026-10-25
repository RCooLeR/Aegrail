import type { InstanceModel } from "../../estate";
import type {
  TrafficIPSummary,
  TrafficPathSummary,
  TrafficStatusCount,
  TrafficTimelineBucket,
  TrafficUserAgentSummary
} from "../../types";
import type { TrafficBotsScopeData, TrafficScopeData } from "../types";

export type TrafficOrigin = {
  instance: InstanceModel;
  requests: number;
};

export type AggregatedTrafficIP = Omit<TrafficIPSummary, "manual_policy" | "trusted" | "blocked"> & {
  blocked: boolean;
  manual_policy: string;
  origins: TrafficOrigin[];
  trusted: boolean;
};

export type AggregatedTrafficPath = TrafficPathSummary & {
  scope_count: number;
};

export type AggregatedTrafficUserAgent = TrafficUserAgentSummary & {
  origins: TrafficOrigin[];
  unique_ips_approximate: boolean;
};

export type AggregatedTraffic = {
  bot_requests: number;
  error_requests: number;
  represented_ips: number;
  reported_unique_ips: number;
  scope_count: number;
  since: string;
  status_codes: TrafficStatusCount[];
  timeline: TrafficTimelineBucket[];
  timeline_bucket: string;
  top_ips: AggregatedTrafficIP[];
  top_paths: AggregatedTrafficPath[];
  top_user_agents: AggregatedTrafficUserAgent[];
  total_bytes: number;
  total_requests: number;
  ranking_counts_approximate: boolean;
  unique_ips_approximate: boolean;
  until: string;
};

export type AggregatedBots = {
  bots: AggregatedTrafficUserAgent[];
  bot_requests: number;
  error_requests: number;
  page_metadata_complete: boolean;
  returned: number;
  row_counts_approximate: boolean;
  scope_count: number;
  since: string;
  total_clients: number;
  totals_complete: boolean;
  truncated: boolean;
  until: string;
  verified_requests: number;
};

export function aggregateTraffic(scopes: TrafficScopeData[]): AggregatedTraffic {
  const statusCodes = new Map<number, number>();
  const timeline = new Map<string, TrafficTimelineBucket>();
  const paths = new Map<string, AggregatedTrafficPath>();
  const ips = aggregateIPs(scopes.flatMap(({ instance, traffic }) =>
    traffic.top_ips.map((summary) => ({ instance, summary }))
  ));
  const userAgents = aggregateUserAgents(scopes.flatMap(({ instance, traffic }) =>
    traffic.top_user_agents.map((summary) => ({ instance, summary }))
  ));

  for (const { traffic } of scopes) {
    for (const item of traffic.status_codes) {
      statusCodes.set(item.status_code, (statusCodes.get(item.status_code) ?? 0) + item.requests);
    }
    for (const item of traffic.timeline) {
      const current = timeline.get(item.start);
      timeline.set(item.start, current ? {
        start: item.start,
        requests: current.requests + item.requests,
        error_requests: current.error_requests + item.error_requests,
        bot_requests: current.bot_requests + item.bot_requests,
        total_bytes: current.total_bytes + item.total_bytes
      } : { ...item });
    }
    for (const item of traffic.top_paths) {
      const current = paths.get(item.path);
      paths.set(item.path, current ? {
        path: item.path,
        requests: current.requests + item.requests,
        error_requests: current.error_requests + item.error_requests,
        total_bytes: current.total_bytes + item.total_bytes,
        last_seen: latestTime(current.last_seen, item.last_seen),
        scope_count: current.scope_count + 1
      } : { ...item, scope_count: 1 });
    }
  }

  return {
    bot_requests: sum(scopes, ({ traffic }) => traffic.bot_requests),
    error_requests: sum(scopes, ({ traffic }) => traffic.error_requests),
    represented_ips: ips.length,
    reported_unique_ips: sum(scopes, ({ traffic }) => traffic.unique_ips),
    scope_count: scopes.length,
    since: earliestTime(...scopes.map(({ traffic }) => traffic.since)),
    status_codes: Array.from(statusCodes, ([status_code, requests]) => ({ status_code, requests }))
      .sort((left, right) => left.status_code - right.status_code),
    timeline: Array.from(timeline.values()).sort((left, right) => time(left.start) - time(right.start)),
    timeline_bucket: commonValue(scopes.map(({ traffic }) => traffic.timeline_bucket)) || "mixed",
    top_ips: ips.sort(byRequests).slice(0, 100),
    top_paths: Array.from(paths.values()).sort(byRequests).slice(0, 100),
    top_user_agents: userAgents.sort(byRequests).slice(0, 100),
    total_bytes: sum(scopes, ({ traffic }) => traffic.total_bytes),
    total_requests: sum(scopes, ({ traffic }) => traffic.total_requests),
    ranking_counts_approximate: scopes.length > 1,
    unique_ips_approximate: scopes.length > 1,
    until: latestTime(...scopes.map(({ traffic }) => traffic.until))
  };
}

export function aggregateBots(scopes: TrafficBotsScopeData[]): AggregatedBots {
  const bots = aggregateUserAgents(scopes.flatMap(({ instance, traffic }) =>
    traffic.bots.map((summary) => ({ instance, summary }))
  )).sort(byRequests);
  const returned = sum(scopes, ({ traffic }) => responseTotal(traffic.returned, traffic.bots.length));
  const totalClients = sum(scopes, ({ traffic }) => responseTotal(traffic.total_clients, traffic.count ?? traffic.bots.length));
  const pageMetadataComplete = scopes.every(({ traffic }) =>
    isReportedTotal(traffic.returned) && typeof traffic.truncated === "boolean"
  );
  const truncated = scopes.some(({ traffic }) =>
    traffic.truncated === true || responseTotal(traffic.returned, traffic.bots.length) < responseTotal(traffic.total_clients, traffic.count ?? traffic.bots.length)
  );
  return {
    bots,
    bot_requests: sum(scopes, ({ traffic }) => responseTotal(traffic.total_requests, sum(traffic.bots, (bot) => bot.requests))),
    error_requests: sum(scopes, ({ traffic }) => responseTotal(traffic.total_error_requests, sum(traffic.bots, (bot) => bot.error_requests))),
    page_metadata_complete: pageMetadataComplete,
    returned,
    row_counts_approximate: scopes.length > 1 && (truncated || !pageMetadataComplete),
    scope_count: scopes.length,
    since: earliestTime(...scopes.map(({ traffic }) => traffic.since)),
    total_clients: totalClients,
    totals_complete: scopes.every(({ traffic }) =>
      isReportedTotal(traffic.total_clients) &&
      isReportedTotal(traffic.total_requests) &&
      isReportedTotal(traffic.total_verified_requests) &&
      isReportedTotal(traffic.total_error_requests)
    ),
    truncated,
    until: latestTime(...scopes.map(({ traffic }) => traffic.until)),
    verified_requests: sum(scopes, ({ traffic }) => responseTotal(traffic.total_verified_requests, sum(traffic.bots, (bot) => bot.verified_requests ?? 0)))
  };
}

export function trafficScopeLabel(instance: InstanceModel) {
  return [instance.companyName, instance.projectName, instance.environmentName, instance.appName]
    .filter(Boolean)
    .join(" / ");
}

function aggregateIPs(rows: Array<{ instance: InstanceModel; summary: TrafficIPSummary }>) {
  const merged = new Map<string, AggregatedTrafficIP>();
  for (const { instance, summary } of rows) {
    const current = merged.get(summary.ip);
    if (!current) {
      merged.set(summary.ip, {
        ...summary,
        // Trust is deliberately derived only from the manual policy. Provider
        // verification establishes identity; it never grants trust.
        trusted: summary.manual_policy === "trusted",
        blocked: summary.manual_policy === "blocked",
        origins: [{ instance, requests: summary.requests }]
      });
      continue;
    }
    const policies = new Set([current.manual_policy, summary.manual_policy]);
    const manualPolicy = policies.size === 1 ? current.manual_policy : "mixed";
    current.requests += summary.requests;
    current.error_requests += summary.error_requests;
    current.total_bytes += summary.total_bytes;
    current.first_seen = earliestTime(current.first_seen, summary.first_seen);
    current.last_seen = latestTime(current.last_seen, summary.last_seen);
    current.manual_policy = manualPolicy;
    current.trusted = manualPolicy === "trusted";
    current.blocked = manualPolicy === "blocked";
    current.provider_verified ||= summary.provider_verified;
    current.recognized_provider = joinedValue(current.recognized_provider, summary.recognized_provider);
    current.origins.push({ instance, requests: summary.requests });
  }
  for (const item of merged.values()) {
    item.origins.sort((left, right) => right.requests - left.requests);
  }
  return Array.from(merged.values());
}

function aggregateUserAgents(rows: Array<{ instance: InstanceModel; summary: TrafficUserAgentSummary }>) {
  const merged = new Map<string, AggregatedTrafficUserAgent>();
  for (const { instance, summary } of rows) {
    const current = merged.get(summary.hash);
    if (!current) {
      merged.set(summary.hash, {
        ...summary,
        origins: [{ instance, requests: summary.requests }],
        unique_ips_approximate: false
      });
      continue;
    }
    current.requests += summary.requests;
    current.verified_requests = (current.verified_requests ?? 0) + (summary.verified_requests ?? 0);
    current.unique_ips += summary.unique_ips;
    current.error_requests += summary.error_requests;
    current.first_seen = earliestTime(current.first_seen, summary.first_seen);
    current.last_seen = latestTime(current.last_seen, summary.last_seen);
    current.risk_score = Math.max(current.risk_score, summary.risk_score);
    current.is_bot ||= summary.is_bot;
    current.is_tool ||= summary.is_tool;
    current.known_actor = joinedValue(current.known_actor, summary.known_actor);
    current.origins.push({ instance, requests: summary.requests });
    current.unique_ips_approximate = true;
  }
  for (const item of merged.values()) {
    item.origins.sort((left, right) => right.requests - left.requests);
  }
  return Array.from(merged.values());
}

function commonValue(values: string[]) {
  const normalized = Array.from(new Set(values.filter(Boolean)));
  return normalized.length === 1 ? normalized[0] : "";
}

function joinedValue(left?: string, right?: string) {
  return Array.from(new Set([left, right].filter((value): value is string => Boolean(value))))
    .join(", ");
}

function earliestTime(...values: string[]) {
  return values.filter(Boolean).sort((left, right) => time(left) - time(right))[0] ?? "";
}

function latestTime(...values: string[]) {
  return values.filter(Boolean).sort((left, right) => time(right) - time(left))[0] ?? "";
}

function time(value: string) {
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
}

function byRequests(left: { requests: number }, right: { requests: number }) {
  return right.requests - left.requests;
}

function sum<T>(items: T[], pick: (item: T) => number) {
  return items.reduce((total, item) => total + pick(item), 0);
}

function isReportedTotal(value: number | undefined): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function responseTotal(value: number | undefined, fallback: number) {
  return isReportedTotal(value) ? value : fallback;
}
