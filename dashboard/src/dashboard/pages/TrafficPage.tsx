import { Activity, AlertTriangle, Bot, Globe, Network, Users } from "lucide-react";
import { useMemo, useState } from "react";
import { Area, AreaChart, CartesianGrid, Tooltip, XAxis, YAxis } from "recharts";
import type { InstanceModel } from "../../estate";
import type { TrafficIPDetailState, TrafficScopeData, TrafficTimeframe, TrafficUserAgentDetailState } from "../types";
import {
  aggregateTraffic,
  trafficScopeLabel,
  type AggregatedTrafficIP,
  type AggregatedTrafficUserAgent
} from "../model/traffic";
import { formatRelative } from "../utils/time";
import { formatBytes, TrafficIPDetailPanel, TrafficUserAgentDetailPanel } from "../components/TrafficDetailPanel";
import { TrafficTimeframeSelect } from "../components/TrafficTimeframeSelect";
import { EmptyState, InlineAlert, LoadingBlock, MetricCard, Panel, ResponsiveTable, StatusPill } from "../components/common";
import { trafficTimeframeLabel } from "../utils/trafficTimeframes";

type SelectedIP = { instance: InstanceModel; row: AggregatedTrafficIP };
type SelectedUserAgent = { instance: InstanceModel; row: AggregatedTrafficUserAgent };

export function TrafficPage({
  canManagePolicy,
  data,
  error,
  ipDetail,
  ipDetailError,
  ipDetailLoading,
  loading,
  onCloseIP,
  onCloseUserAgent,
  onIP,
  onPolicy,
  onTimeframe,
  onUserAgent,
  policyLoading,
  query,
  timeframe,
  userAgentDetail,
  userAgentDetailError,
  userAgentDetailLoading
}: {
  canManagePolicy: boolean;
  data: TrafficScopeData[];
  error: string;
  ipDetail: TrafficIPDetailState | null;
  ipDetailError: string;
  ipDetailLoading: boolean;
  loading: boolean;
  onCloseIP: () => void;
  onCloseUserAgent: () => void;
  onIP: (instance: InstanceModel, ip: string) => Promise<void>;
  onPolicy: (instance: InstanceModel, ip: string, policy: "neutral" | "trusted" | "blocked", reason: string) => Promise<unknown>;
  onTimeframe: (timeframe: TrafficTimeframe) => void;
  onUserAgent: (instance: InstanceModel, hash: string) => Promise<void>;
  policyLoading: boolean;
  query: string;
  timeframe: TrafficTimeframe;
  userAgentDetail: TrafficUserAgentDetailState | null;
  userAgentDetailError: string;
  userAgentDetailLoading: boolean;
}) {
  const traffic = useMemo(() => aggregateTraffic(data), [data]);
  const [selectedIP, setSelectedIP] = useState<SelectedIP | null>(null);
  const [selectedUserAgent, setSelectedUserAgent] = useState<SelectedUserAgent | null>(null);
  const search = query.trim().toLowerCase();
  const ips = traffic.top_ips.filter((row) => !search || [row.ip, row.recognized_provider, row.manual_policy]
    .some((value) => value?.toLowerCase().includes(search)));
  const paths = traffic.top_paths.filter((row) => !search || row.path.toLowerCase().includes(search));
  const userAgents = traffic.top_user_agents.filter((row) => !search || [row.user_agent, row.family, row.known_actor, row.actor_type]
    .some((value) => value?.toLowerCase().includes(search)));

  function selectIP(row: AggregatedTrafficIP, instance = row.origins[0]?.instance) {
    if (!instance) return;
    onCloseUserAgent();
    setSelectedUserAgent(null);
    setSelectedIP({ instance, row });
    void onIP(instance, row.ip);
  }

  function selectUserAgent(row: AggregatedTrafficUserAgent, instance = row.origins[0]?.instance) {
    if (!instance) return;
    onCloseIP();
    setSelectedIP(null);
    setSelectedUserAgent({ instance, row });
    void onUserAgent(instance, row.hash);
  }

  function closeIP() {
    setSelectedIP(null);
    onCloseIP();
  }

  function closeUserAgent() {
    setSelectedUserAgent(null);
    onCloseUserAgent();
  }

  const hasDetail = Boolean(selectedIP || selectedUserAgent);
  return (
    <div className={`traffic-page-layout ${hasDetail ? "with-detail" : ""}`}>
      <div className="page-stack traffic-main-column">
        <TrafficTimeframeSelect loading={loading} onChange={onTimeframe} value={timeframe} />
        {error && <InlineAlert message={error} />}
        {loading && data.length === 0 && <LoadingBlock title={`Loading traffic from the ${trafficTimeframeLabel(timeframe).toLowerCase()}`} />}
        <section className="summary-grid traffic-summary" aria-label="Traffic summary">
          <MetricCard icon={Activity} label="Requests" value={formatCount(traffic.total_requests)} />
          <MetricCard icon={Users} label={traffic.unique_ips_approximate ? "IPs represented" : "Unique IPs"} value={formatCount(traffic.unique_ips_approximate ? traffic.represented_ips : traffic.reported_unique_ips)} />
          <MetricCard icon={Bot} label="Bot requests" value={formatCount(traffic.bot_requests)} tone={traffic.bot_requests ? "warning" : "neutral"} />
          <MetricCard icon={AlertTriangle} label="Error requests" value={formatCount(traffic.error_requests)} tone={traffic.error_requests ? "danger" : "ok"} />
          <MetricCard icon={Network} label="Transferred" value={formatBytes(traffic.total_bytes)} />
          <MetricCard icon={Globe} label="App scopes" value={formatCount(traffic.scope_count)} />
        </section>
        {traffic.unique_ips_approximate && (
          <p className="traffic-aggregation-note">
            IPs represented is the union of the scoped top-IP lists, not a sum of per-app unique counts. The complete estate-wide unique-IP total may be higher.
          </p>
        )}
        {data.length > 0 && (
          <p className="traffic-aggregation-note">
            Top IP, path, and user-agent tables are represented rankings built from each app&apos;s truncated top list.
            {traffic.ranking_counts_approximate && " In this merged view, row request, error, and byte counts are approximate because entries omitted by an app cannot be included."}
          </p>
        )}

        <div className="two-column traffic-chart-grid">
          <Panel icon={Activity} title="Request volume">
            {traffic.timeline.length > 0 ? (
              <div className="traffic-chart" aria-label="Request volume timeline">
                <AreaChart
                  data={traffic.timeline}
                  margin={{ left: -12, right: 8, top: 8 }}
                  responsive
                  style={{ height: "100%", width: "100%" }}
                >
                  <defs>
                    <linearGradient id="trafficRequests" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="5%" stopColor="#2563eb" stopOpacity={0.28} />
                      <stop offset="95%" stopColor="#2563eb" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#e7edf5" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="start" minTickGap={28} tickFormatter={(value) => formatChartTime(String(value), traffic.timeline_bucket)} tickLine={false} />
                  <YAxis allowDecimals={false} tickLine={false} width={52} />
                  <Tooltip labelFormatter={(value) => formatChartLabel(String(value))} />
                  <Area dataKey="requests" fill="url(#trafficRequests)" name="Requests" stroke="#2563eb" strokeWidth={2} type="monotone" />
                  <Area dataKey="bot_requests" fill="transparent" name="Bots" stroke="#f59e0b" strokeWidth={1.5} type="monotone" />
                  <Area dataKey="error_requests" fill="transparent" name="Errors" stroke="#ef4444" strokeWidth={1.5} type="monotone" />
                </AreaChart>
              </div>
            ) : <EmptyState title="No request activity in this window" />}
          </Panel>
          <Panel icon={Network} title="HTTP status distribution">
            <div className="traffic-status-list">
              {traffic.status_codes.map((status) => {
                const percent = traffic.total_requests > 0 ? status.requests / traffic.total_requests * 100 : 0;
                return (
                  <div className="traffic-status-row" key={status.status_code}>
                    <span><StatusPill tone={statusTone(status.status_code)} value={String(status.status_code)} /><strong>{formatCount(status.requests)}</strong></span>
                    <div aria-label={`${percent.toFixed(1)} percent`} className={`traffic-status-bar ${statusTone(status.status_code)}`}>
                      <span style={{ width: `${Math.max(percent, status.requests ? 1.5 : 0)}%` }} />
                    </div>
                    <small>{percent.toFixed(percent < 1 ? 1 : 0)}%</small>
                  </div>
                );
              })}
              {traffic.status_codes.length === 0 && <EmptyState title="No status codes recorded" />}
            </div>
          </Panel>
        </div>

        <Panel icon={Network} title="Top IP addresses (represented)" action={<span className="traffic-panel-meta">{ips.length} represented</span>}>
          <ResponsiveTable>
            <thead><tr><th>IP / identity</th><th>Requests{traffic.ranking_counts_approximate ? " (approx.)" : ""}</th><th>Errors{traffic.ranking_counts_approximate ? " (approx.)" : ""}</th><th>Transferred{traffic.ranking_counts_approximate ? " (approx.)" : ""}</th><th>Policy</th><th>Last seen</th></tr></thead>
            <tbody>
              {ips.map((row) => (
                <tr className={selectedIP?.row.ip === row.ip ? "selected" : ""} key={row.ip}>
                  <td>
                    <button className="traffic-row-button" onClick={() => selectIP(row)} type="button">
                      <code>{row.ip}</code>
                      <small>{row.recognized_provider || `${row.origins.length} scope${row.origins.length === 1 ? "" : "s"}`}</small>
                    </button>
                    {row.provider_verified && <StatusPill tone="neutral" value="Verified identity" />}
                  </td>
                  <td>{rankedValue(formatCount(row.requests), traffic.ranking_counts_approximate)}</td>
                  <td>{rankedValue(formatCount(row.error_requests), traffic.ranking_counts_approximate)}<small>{percentage(row.error_requests, row.requests)}</small></td>
                  <td>{rankedValue(formatBytes(row.total_bytes), traffic.ranking_counts_approximate)}</td>
                  <td><StatusPill tone={policyTone(row.manual_policy)} value={policyLabel(row.manual_policy)} /></td>
                  <td>{formatRelative(row.last_seen)}</td>
                </tr>
              ))}
              {ips.length === 0 && <tr><td colSpan={6}><EmptyState title="No IP addresses match" /></td></tr>}
            </tbody>
          </ResponsiveTable>
        </Panel>

        <div className="two-column traffic-lists-grid">
          <Panel icon={Globe} title="Top paths (represented)" action={<span className="traffic-panel-meta">{Math.min(paths.length, 25)} represented</span>}>
            <ResponsiveTable>
              <thead><tr><th>Path</th><th>Requests{traffic.ranking_counts_approximate ? " (approx.)" : ""}</th><th>Errors{traffic.ranking_counts_approximate ? " (approx.)" : ""}</th></tr></thead>
              <tbody>
                {paths.slice(0, 25).map((row) => (
                  <tr key={row.path}><td><code>{row.path}</code><small>{row.scope_count} scope{row.scope_count === 1 ? "" : "s"}</small></td><td>{rankedValue(formatCount(row.requests), traffic.ranking_counts_approximate)}</td><td>{rankedValue(formatCount(row.error_requests), traffic.ranking_counts_approximate)}</td></tr>
                ))}
                {paths.length === 0 && <tr><td colSpan={3}><EmptyState title="No paths match" /></td></tr>}
              </tbody>
            </ResponsiveTable>
          </Panel>
          <Panel icon={Users} title="Top user agents (represented)" action={<span className="traffic-panel-meta">{Math.min(userAgents.length, 25)} represented</span>}>
            <ResponsiveTable>
              <thead><tr><th>Client</th><th>Type</th><th>Requests{traffic.ranking_counts_approximate ? " (approx.)" : ""}</th><th>IPs{traffic.ranking_counts_approximate ? " (approx.)" : ""}</th><th>Risk</th></tr></thead>
              <tbody>
                {userAgents.slice(0, 25).map((row) => (
                  <tr className={selectedUserAgent?.row.hash === row.hash ? "selected" : ""} key={row.hash}>
                    <td>
                      <button className="traffic-row-button ua" onClick={() => selectUserAgent(row)} type="button">
                        <strong>{row.known_actor || row.family || "Unknown client"}</strong>
                        <small>{row.user_agent || "Empty user-agent header"}</small>
                      </button>
                    </td>
                    <td>
                      <StatusPill
                        tone={row.actor_type === "malicious" ? "critical" : row.is_bot ? "warning" : "neutral"}
                        value={row.actor_type === "malicious" ? "Suspicious automation" : row.is_bot ? "Bot" : row.is_tool ? "Tool" : "Client"}
                      />
                    </td>
                    <td>{rankedValue(formatCount(row.requests), traffic.ranking_counts_approximate)}</td>
                    <td>{rankedValue(formatCount(row.unique_ips), row.unique_ips_approximate || traffic.ranking_counts_approximate)}</td>
                    <td><StatusPill tone={riskTone(row.risk_score)} value={String(row.risk_score)} /></td>
                  </tr>
                ))}
                {userAgents.length === 0 && <tr><td colSpan={5}><EmptyState title="No user agents match" /></td></tr>}
              </tbody>
            </ResponsiveTable>
          </Panel>
        </div>

        {data.length > 0 && (
          <p className="traffic-window-note">
            {trafficTimeframeLabel(timeframe)} | {traffic.scope_count} deduplicated app scope{traffic.scope_count === 1 ? "" : "s"} | {data.map(({ instance }) => trafficScopeLabel(instance)).join("; ")}
          </p>
        )}
      </div>

      {selectedIP && (
        <TrafficIPDetailPanel
          canManagePolicy={canManagePolicy}
          detailState={ipDetail}
          error={ipDetailError}
          instance={selectedIP.instance}
          ip={selectedIP.row.ip}
          loading={ipDetailLoading}
          onClose={closeIP}
          onOrigin={(instance) => selectIP(selectedIP.row, instance)}
          onPolicy={onPolicy}
          origins={selectedIP.row.origins}
          policyLoading={policyLoading}
        />
      )}
      {selectedUserAgent && (
        <TrafficUserAgentDetailPanel
          detailState={userAgentDetail}
          error={userAgentDetailError}
          hash={selectedUserAgent.row.hash}
          instance={selectedUserAgent.instance}
          loading={userAgentDetailLoading}
          onClose={closeUserAgent}
          onOrigin={(instance) => selectUserAgent(selectedUserAgent.row, instance)}
          origins={selectedUserAgent.row.origins}
        />
      )}
    </div>
  );
}

function formatCount(value: number) {
  return new Intl.NumberFormat().format(value);
}

function percentage(value: number, total: number) {
  return total > 0 ? `${(value / total * 100).toFixed(1)}%` : "0%";
}

function rankedValue(value: string, approximate: boolean) {
  return approximate ? `~ ${value}` : value;
}

function formatChartTime(value: string, bucket: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  if (bucket === "day") {
    return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(date);
  }
  if (bucket === "hour" || bucket === "6 hours") {
    return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit" }).format(date);
  }
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(date);
}

function formatChartLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function statusTone(status: number) {
  if (status >= 500) return "critical";
  if (status >= 400) return "warning";
  if (status >= 200 && status < 300) return "healthy";
  return "neutral";
}

function policyTone(policy: string) {
  if (policy === "trusted") return "healthy";
  if (policy === "blocked") return "critical";
  if (policy === "mixed") return "warning";
  return "neutral";
}

function policyLabel(policy: string) {
  if (policy === "trusted") return "Trusted";
  if (policy === "blocked") return "Blocked";
  if (policy === "mixed") return "Mixed";
  return "Neutral";
}

function riskTone(score: number) {
  if (score >= 70) return "critical";
  if (score >= 40) return "warning";
  return "neutral";
}
