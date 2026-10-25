import { AlertTriangle, Bot, CheckCircle2, Network, Radar, Users } from "lucide-react";
import { useMemo, useState } from "react";
import type { InstanceModel } from "../../estate";
import type { TrafficBotsScopeData, TrafficTimeframe, TrafficUserAgentDetailState } from "../types";
import { aggregateBots, type AggregatedTrafficUserAgent } from "../model/traffic";
import { TrafficUserAgentDetailPanel } from "../components/TrafficDetailPanel";
import { TrafficTimeframeSelect } from "../components/TrafficTimeframeSelect";
import { EmptyState, InlineAlert, LoadingBlock, MetricCard, Panel, ResponsiveTable, StatusPill } from "../components/common";
import { formatRelative } from "../utils/time";
import { trafficTimeframeLabel } from "../utils/trafficTimeframes";

type BotFilter = "all" | "ai" | "rag" | "search" | "seo" | "social" | "monitors" | "tools" | "suspicious" | "other";
type Selection = { instance: InstanceModel; row: AggregatedTrafficUserAgent };

export function BotsPage({
  data,
  detail,
  detailError,
  detailLoading,
  error,
  loading,
  onClose,
  onTimeframe,
  onUserAgent,
  query,
  timeframe
}: {
  data: TrafficBotsScopeData[];
  detail: TrafficUserAgentDetailState | null;
  detailError: string;
  detailLoading: boolean;
  error: string;
  loading: boolean;
  onClose: () => void;
  onTimeframe: (timeframe: TrafficTimeframe) => void;
  onUserAgent: (instance: InstanceModel, hash: string) => Promise<void>;
  query: string;
  timeframe: TrafficTimeframe;
}) {
  const summary = useMemo(() => aggregateBots(data), [data]);
  const [filter, setFilter] = useState<BotFilter>("all");
  const [selection, setSelection] = useState<Selection | null>(null);
  const search = query.trim().toLowerCase();
  const rows = summary.bots.filter((row) => {
    if (search && ![row.user_agent, row.family, row.known_actor, row.actor_type]
      .some((value) => value?.toLowerCase().includes(search))) return false;
    return filter === "all" || botCategory(row) === filter;
  });
  const knownActors = summary.bots.filter((bot) => bot.known_actor).length;
  const highRisk = summary.bots.filter((bot) => bot.risk_score >= 70).length;

  function select(row: AggregatedTrafficUserAgent, instance = row.origins[0]?.instance) {
    if (!instance) return;
    setSelection({ instance, row });
    void onUserAgent(instance, row.hash);
  }

  function close() {
    setSelection(null);
    onClose();
  }

  return (
    <div className={`traffic-page-layout ${selection ? "with-detail" : ""}`}>
      <div className="page-stack traffic-main-column">
        <TrafficTimeframeSelect loading={loading} onChange={onTimeframe} value={timeframe} />
        {error && <InlineAlert message={error} />}
        {loading && data.length === 0 && <LoadingBlock title={`Loading bots and crawlers from the ${trafficTimeframeLabel(timeframe).toLowerCase()}`} />}
        <section className="summary-grid traffic-summary" aria-label="Bot and crawler summary">
          <MetricCard icon={Bot} label={summary.scope_count > 1 ? "Client-scope entries" : "Automation clients"} value={formatCount(summary.total_clients)} />
          <MetricCard icon={Radar} label="Automation requests" value={formatCount(summary.bot_requests)} />
          <MetricCard icon={CheckCircle2} label="Known represented" value={formatCount(knownActors)} tone={knownActors ? "ok" : "neutral"} />
          <MetricCard icon={AlertTriangle} label="High-risk represented" value={formatCount(highRisk)} tone={highRisk ? "danger" : "ok"} />
          <MetricCard icon={Network} label="Cached verified requests" value={formatCount(summary.verified_requests)} />
          <MetricCard icon={AlertTriangle} label="Error requests" value={formatCount(summary.error_requests)} tone={summary.error_requests ? "danger" : "ok"} />
          <MetricCard icon={Users} label="App scopes" value={formatCount(summary.scope_count)} />
        </section>
        <p className="traffic-aggregation-note">
          {summary.totals_complete
            ? "Request, verification, and error metrics use server aggregate totals for all matching automation. "
            : "Some scopes do not provide aggregate totals, so their metrics fall back to represented rows. "}
          The table merges {formatCount(summary.returned)} server-returned rows into {formatCount(summary.bots.length)} represented signatures{summary.truncated ? " and is truncated" : summary.page_metadata_complete ? "" : "; truncation is unknown for compatibility responses"}.
          {summary.scope_count > 1 && " Client-scope entries sum per-app distinct clients, so the same signature may be counted once per app."}
          {summary.row_counts_approximate && " Merged table row counts are approximate because an app may omit a signature from its top list."}
          {" "}Cached verification confirms provider identity only; it never makes a bot or IP trusted.
        </p>

        <Panel
          icon={Bot}
          title="Bot and crawler activity"
          action={
            <div className="traffic-table-controls">
              <span>{rows.length} of {summary.bots.length} represented</span>
              <label>
                <span className="sr-only">Filter bot signatures</span>
                <select onChange={(event) => setFilter(event.target.value as BotFilter)} value={filter}>
                  <option value="all">All automation</option>
                  <option value="ai">AI crawlers</option>
                  <option value="rag">RAG agents</option>
                  <option value="search">Search engines</option>
                  <option value="seo">SEO crawlers</option>
                  <option value="social">Social previews</option>
                  <option value="monitors">Monitors</option>
                  <option value="tools">Tools / scripts</option>
                  <option value="suspicious">Suspicious</option>
                  <option value="other">Other automation</option>
                </select>
              </label>
            </div>
          }
        >
          <ResponsiveTable>
            <thead>
              <tr><th>Bot / crawler</th><th>Classification</th><th>Requests{summary.row_counts_approximate ? " (approx.)" : ""}</th><th>Cached verified{summary.row_counts_approximate ? " (approx.)" : ""}</th><th>IPs{summary.row_counts_approximate ? " (approx.)" : ""}</th><th>Errors{summary.row_counts_approximate ? " (approx.)" : ""}</th><th>Risk</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr className={selection?.row.hash === row.hash ? "selected" : ""} key={row.hash}>
                  <td>
                    <button className="traffic-row-button ua" onClick={() => select(row)} type="button">
                      <strong>{row.known_actor || row.family || "Unidentified bot"}</strong>
                      <small>{row.user_agent || "Empty user-agent header"}</small>
                    </button>
                    <small>{row.origins.length} app scope{row.origins.length === 1 ? "" : "s"}</small>
                  </td>
                  <td>
                    <StatusPill value={categoryLabel(botCategory(row))} tone={row.risk_score >= 70 ? "critical" : row.known_actor ? "healthy" : "warning"} />
                    <small>{humanize(row.actor_type || "automation")}</small>
                  </td>
                  <td>{rankedValue(formatCount(row.requests), summary.row_counts_approximate)}</td>
                  <td>
                    {rankedValue(formatCount(row.verified_requests ?? 0), summary.row_counts_approximate)}
                    <small>{percentage(row.verified_requests ?? 0, row.requests)}</small>
                  </td>
                  <td>{rankedValue(formatCount(row.unique_ips), row.unique_ips_approximate || summary.row_counts_approximate)}</td>
                  <td>{rankedValue(formatCount(row.error_requests), summary.row_counts_approximate)}<small>{percentage(row.error_requests, row.requests)}</small></td>
                  <td><StatusPill value={String(row.risk_score)} tone={riskTone(row.risk_score)} /></td>
                  <td>{formatRelative(row.last_seen)}</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><td colSpan={8}><EmptyState title={summary.bots.length ? "No bots match the current filters" : "No bots or crawlers detected"} /></td></tr>
              )}
            </tbody>
          </ResponsiveTable>
        </Panel>

        {data.length > 0 && (
          <p className="traffic-window-note">
            {trafficTimeframeLabel(timeframe)} | {summary.scope_count} deduplicated app scope{summary.scope_count === 1 ? "" : "s"} | Values marked ~ are represented approximations.
          </p>
        )}
      </div>
      {selection && (
        <TrafficUserAgentDetailPanel
          detailState={detail}
          error={detailError}
          hash={selection.row.hash}
          instance={selection.instance}
          loading={detailLoading}
          onClose={close}
          onOrigin={(instance) => select(selection.row, instance)}
          origins={selection.row.origins}
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

function humanize(value: string) {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function riskTone(score: number) {
  if (score >= 70) return "critical";
  if (score >= 40) return "warning";
  return "neutral";
}

function botCategory(row: AggregatedTrafficUserAgent): Exclude<BotFilter, "all"> {
  const actorType = row.actor_type.toLowerCase();
  const identity = [row.known_actor, row.family, row.user_agent].filter(Boolean).join(" ").toLowerCase();
  if (actorType === "rag") return "rag";
  if (/openai|gptbot|anthropic|claude|perplexity|cohere|amazon quick|diffbot|you\.com|youbot|omgili/.test(identity)) return "ai";
  if (actorType === "monitor") return "monitors";
  if (row.is_tool || actorType === "tool") return "tools";
  if (actorType === "malicious" || row.risk_score >= 70) return "suspicious";
  if (/ahrefs|semrush|\bmoz\b|majestic|mj12|screaming frog|sitebulb|blex|dataforseo|addsearch/.test(identity)) return "seo";
  if (/\bmeta\b|facebook|facebot|bytedance|bytespider|linkedin|twitter|pinterest/.test(identity)) return "social";
  if (/google|bing|duckduckgo|yahoo|yandex|baidu|applebot|\bask\b|teoma|aolbot/.test(identity)) return "search";
  return "other";
}

function categoryLabel(category: Exclude<BotFilter, "all">) {
  switch (category) {
    case "ai": return "AI crawler";
    case "rag": return "RAG agent";
    case "search": return "Search engine";
    case "seo": return "SEO crawler";
    case "social": return "Social preview";
    case "monitors": return "Monitor";
    case "tools": return "Tool / script";
    case "suspicious": return "Suspicious";
    default: return "Other automation";
  }
}
