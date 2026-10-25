import { Loader2, ShieldCheck, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { InstanceModel } from "../../estate";
import type { TrafficIPDetail, TrafficUserAgentDetail } from "../../types";
import type { TrafficOrigin } from "../model/traffic";
import type { TrafficIPDetailState, TrafficUserAgentDetailState } from "../types";
import { formatDate, formatRelative } from "../utils/time";
import { EmptyState, InlineAlert, LoadingBlock, ResponsiveTable, StatusPill } from "./common";

type OriginProps = {
  instance: InstanceModel;
  onOrigin: (instance: InstanceModel) => void;
  origins: TrafficOrigin[];
};

export function TrafficIPDetailPanel({
  canManagePolicy,
  detailState,
  error,
  instance,
  ip,
  loading,
  onClose,
  onOrigin,
  onPolicy,
  origins,
  policyLoading
}: {
  canManagePolicy: boolean;
  detailState: TrafficIPDetailState | null;
  error: string;
  instance: InstanceModel;
  ip: string;
  loading: boolean;
  onClose: () => void;
  onOrigin: (instance: InstanceModel) => void;
  onPolicy: (instance: InstanceModel, ip: string, policy: "neutral" | "trusted" | "blocked", reason: string) => Promise<unknown>;
  origins: TrafficOrigin[];
  policyLoading: boolean;
}) {
  const panelRef = useRef<HTMLElement>(null);
  const [reason, setReason] = useState("");

  useEffect(() => {
    panelRef.current?.focus();
  }, [ip]);

  useEffect(() => {
    setReason(detailState?.detail.policy.reason ?? "");
  }, [detailState?.detail.policy.reason, detailState?.detail.policy.policy]);

  const detail = detailState?.detail;
  const manualPolicy = detail?.policy.policy ?? "neutral";

  return (
    <aside
      aria-labelledby="traffic-ip-detail-title"
      aria-live="polite"
      className="traffic-detail-panel"
      onKeyDown={(event) => {
        if (event.key === "Escape") onClose();
      }}
      ref={panelRef}
      tabIndex={-1}
    >
      <DetailHeader eyebrow="IP address" id="traffic-ip-detail-title" onClose={onClose} title={ip} />
      <OriginPicker instance={instance} onOrigin={onOrigin} origins={origins} />
      {loading && <LoadingBlock title="Looking up IP details" />}
      {error && <InlineAlert message={error} />}
      {!loading && detail && (
        <div className="traffic-detail-content">
          <div className={`traffic-trust-card ${policyTone(manualPolicy)}`}>
            <ShieldCheck size={20} />
            <span>
              <strong>{policyLabel(manualPolicy)}</strong>
              <small>{policyDescription(manualPolicy)}</small>
            </span>
          </div>

          <DetailMetrics
            values={[
              ["Requests", formatCount(detail.requests)],
              ["Errors", formatCount(detail.error_requests)],
              ["Transferred", formatBytes(detail.total_bytes)],
              ["Last seen", formatRelative(detail.last_seen)]
            ]}
          />

          <section className="traffic-detail-section">
            <h3>Network intelligence</h3>
            <dl className="traffic-detail-list">
              <DetailItem label="Network" value={humanize(detail.intel.network_class)} />
              <DetailItem label="Lookup" value={humanize(detail.intel.lookup_status)} />
              <DetailItem label="Reverse DNS" value={detail.intel.reverse_dns.join(", ") || "No hostname found"} />
              <DetailItem label="DNS confirmed" value={detail.intel.dns_verified ? "Yes" : "No"} />
              <DetailItem label="Provider" value={detail.intel.recognized_provider || "Not recognized"} />
              <DetailItem
                label="Provider identity"
                value={detail.intel.provider_verified ? "Verified by forward-confirmed DNS" : "Not verified"}
              />
            </dl>
            {detail.intel.provider_verified && (
              <p className="traffic-identity-note">
                Verified provider identity identifies the network owner. It does not mark this IP as trusted.
              </p>
            )}
            {detail.intel.last_error && <InlineAlert message={detail.intel.last_error} />}
          </section>

          <section className="traffic-detail-section">
            <h3>Manual policy</h3>
            <p className="traffic-section-copy">
              Only an explicit Trusted policy labels this address as trusted. Policy labels do not suppress findings or enforce network rules.
            </p>
            <label className="traffic-policy-reason">
              Reason
              <textarea
                disabled={!canManagePolicy || policyLoading}
                maxLength={2000}
                onChange={(event) => setReason(event.target.value)}
                placeholder="Why is this policy appropriate?"
                value={reason}
              />
            </label>
            <div className="traffic-policy-actions" role="group" aria-label="IP policy">
              {(["neutral", "trusted", "blocked"] as const).map((policy) => (
                <button
                  aria-pressed={manualPolicy === policy}
                  className={`ghost-button compact policy-${policy}`}
                  disabled={!canManagePolicy || policyLoading || (
                    manualPolicy === policy && reason.trim() === (detail.policy.reason ?? "").trim()
                  )}
                  key={policy}
                  onClick={() => void onPolicy(instance, detail.ip, policy, reason)}
                  type="button"
                >
                  {policyLoading && manualPolicy !== policy && <Loader2 className="spin" size={14} />}
                  {policyLabel(policy)}
                </button>
              ))}
            </div>
            {!canManagePolicy && <small className="traffic-permission-note">Operator access is required to change policy.</small>}
            {detail.policy.updated_by && (
              <small className="traffic-permission-note">
                Last changed by {detail.policy.updated_by}{detail.policy.updated_at ? `, ${formatRelative(detail.policy.updated_at)}` : ""}.
              </small>
            )}
          </section>

          <Breakdown detail={detail} />
        </div>
      )}
      {!loading && !error && !detail && <EmptyState title="No IP details loaded" />}
    </aside>
  );
}

export function TrafficUserAgentDetailPanel({
  detailState,
  error,
  hash,
  instance,
  loading,
  onClose,
  onOrigin,
  origins
}: {
  detailState: TrafficUserAgentDetailState | null;
  error: string;
  hash: string;
  instance: InstanceModel;
  loading: boolean;
  onClose: () => void;
  onOrigin: (instance: InstanceModel) => void;
  origins: TrafficOrigin[];
}) {
  const panelRef = useRef<HTMLElement>(null);
  useEffect(() => {
    panelRef.current?.focus();
  }, [hash]);
  const detail = detailState?.detail;
  return (
    <aside
      aria-labelledby="traffic-ua-detail-title"
      aria-live="polite"
      className="traffic-detail-panel"
      onKeyDown={(event) => {
        if (event.key === "Escape") onClose();
      }}
      ref={panelRef}
      tabIndex={-1}
    >
      <DetailHeader
        eyebrow="User agent"
        id="traffic-ua-detail-title"
        onClose={onClose}
        title={detail?.known_actor || detail?.family || "Client details"}
      />
      <OriginPicker instance={instance} onOrigin={onOrigin} origins={origins} />
      {loading && <LoadingBlock title="Loading user-agent details" />}
      {error && <InlineAlert message={error} />}
      {!loading && detail && (
        <div className="traffic-detail-content">
          <div className="traffic-identity-row">
            <StatusPill
              value={detail.actor_type === "malicious" ? "Suspicious automation" : detail.is_bot ? "Bot / crawler" : detail.is_tool ? "Automation tool" : "Browser / client"}
              tone={detail.actor_type === "malicious" ? "critical" : detail.is_bot ? "warning" : "neutral"}
            />
            {detail.known_actor && <StatusPill value={detail.known_actor} tone="healthy" />}
            <StatusPill value={`Risk ${detail.risk_score}`} tone={detail.risk_score >= 70 ? "critical" : detail.risk_score >= 40 ? "warning" : "neutral"} />
          </div>
          <code className="traffic-user-agent-raw">{detail.user_agent || "Empty user-agent header"}</code>
          <DetailMetrics
            values={[
              ["Requests", formatCount(detail.requests)],
              ["Unique IPs", formatCount(detail.unique_ips)],
              ["Errors", formatCount(detail.error_requests)],
              ["Last seen", formatRelative(detail.last_seen)]
            ]}
          />
          <section className="traffic-detail-section">
            <h3>Client analysis</h3>
            <dl className="traffic-detail-list">
              <DetailItem label="Family" value={detail.family || "Unknown"} />
              <DetailItem label="Actor type" value={humanize(detail.actor_type)} />
              <DetailItem label="Browser" value={versionedLabel(detail.browser_family, detail.browser_version)} />
              <DetailItem label="Operating system" value={versionedLabel(detail.os_family, detail.os_version)} />
              <DetailItem label="Device" value={detail.device_family || "Unknown"} />
              <DetailItem label="SHA-256" value={detail.hash} />
            </dl>
          </section>
          <UserAgentBreakdown detail={detail} />
        </div>
      )}
      {!loading && !error && !detail && <EmptyState title="No user-agent details loaded" />}
    </aside>
  );
}

function DetailHeader({ eyebrow, id, onClose, title }: { eyebrow: string; id: string; onClose: () => void; title: string }) {
  return (
    <header className="traffic-detail-header">
      <span>
        <small>{eyebrow}</small>
        <h2 id={id}>{title}</h2>
      </span>
      <button aria-label="Close details" className="icon-button traffic-detail-close" onClick={onClose} type="button">
        <X size={17} />
      </button>
    </header>
  );
}

function OriginPicker({ instance, onOrigin, origins }: OriginProps) {
  return (
    <label className="traffic-origin-picker">
      Scope
      <select
        onChange={(event) => {
          const next = origins.find((origin) => origin.instance.key === event.target.value);
          if (next) onOrigin(next.instance);
        }}
        value={instance.key}
      >
        {origins.map((origin) => (
          <option key={origin.instance.key} value={origin.instance.key}>
            {scopeLabel(origin.instance)} | {formatCount(origin.requests)} requests
          </option>
        ))}
      </select>
    </label>
  );
}

function DetailMetrics({ values }: { values: Array<[string, string]> }) {
  return (
    <div className="traffic-detail-metrics">
      {values.map(([label, value]) => <span key={label}><small>{label}</small><strong>{value}</strong></span>)}
    </div>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return <><dt>{label}</dt><dd>{value}</dd></>;
}

function Breakdown({ detail }: { detail: TrafficIPDetail }) {
  return (
    <>
      <StatusBreakdown statusCodes={detail.status_codes} total={detail.requests} />
      <section className="traffic-detail-section">
        <h3>Top paths</h3>
        <ResponsiveTable>
          <thead><tr><th>Path</th><th>Requests</th><th>Errors</th></tr></thead>
          <tbody>
            {detail.top_paths.slice(0, 8).map((path) => (
              <tr key={path.path}><td><code>{path.path}</code></td><td>{formatCount(path.requests)}</td><td>{formatCount(path.error_requests)}</td></tr>
            ))}
          </tbody>
        </ResponsiveTable>
      </section>
      <section className="traffic-detail-section">
        <h3>Top user agents</h3>
        <ResponsiveTable>
          <thead><tr><th>Client</th><th>Requests</th><th>Risk</th></tr></thead>
          <tbody>
            {detail.user_agents.slice(0, 8).map((client) => (
              <tr key={client.hash}>
                <td><strong>{client.known_actor || client.family || "Unknown client"}</strong><small>{client.user_agent || "Empty user-agent header"}</small></td>
                <td>{formatCount(client.requests)}</td>
                <td><StatusPill value={String(client.risk_score)} tone={client.risk_score >= 70 ? "critical" : client.risk_score >= 40 ? "warning" : "neutral"} /></td>
              </tr>
            ))}
          </tbody>
        </ResponsiveTable>
      </section>
      <RecentRequests requests={detail.recent_requests} />
    </>
  );
}

function UserAgentBreakdown({ detail }: { detail: TrafficUserAgentDetail }) {
  return (
    <>
      <StatusBreakdown statusCodes={detail.status_codes} total={detail.requests} />
      <section className="traffic-detail-section">
        <h3>Top IPs</h3>
        <ResponsiveTable>
          <thead><tr><th>IP</th><th>Requests</th><th>Policy</th></tr></thead>
          <tbody>
            {detail.top_ips.slice(0, 8).map((ip) => (
              <tr key={ip.ip}>
                <td><code>{ip.ip}</code></td>
                <td>{formatCount(ip.requests)}</td>
                <td><StatusPill value={policyLabel(ip.manual_policy)} tone={policyTone(ip.manual_policy)} /></td>
              </tr>
            ))}
          </tbody>
        </ResponsiveTable>
      </section>
      <section className="traffic-detail-section">
        <h3>Top paths</h3>
        <ResponsiveTable>
          <thead><tr><th>Path</th><th>Requests</th><th>Errors</th></tr></thead>
          <tbody>
            {detail.top_paths.slice(0, 8).map((path) => (
              <tr key={path.path}><td><code>{path.path}</code></td><td>{formatCount(path.requests)}</td><td>{formatCount(path.error_requests)}</td></tr>
            ))}
          </tbody>
        </ResponsiveTable>
      </section>
      <RecentRequests requests={detail.recent_requests} />
    </>
  );
}

function StatusBreakdown({ statusCodes, total }: { statusCodes: TrafficIPDetail["status_codes"]; total: number }) {
  return (
    <section className="traffic-detail-section">
      <h3>HTTP status</h3>
      <div className="traffic-identity-row">
        {statusCodes.map((item) => (
          <StatusPill
            key={item.status_code}
            tone={item.status_code >= 500 ? "critical" : item.status_code >= 400 ? "warning" : item.status_code >= 200 && item.status_code < 300 ? "healthy" : "neutral"}
            value={`${item.status_code}: ${formatCount(item.requests)} (${total ? (item.requests / total * 100).toFixed(1) : "0"}%)`}
          />
        ))}
        {statusCodes.length === 0 && <span className="traffic-permission-note">No status-code breakdown available.</span>}
      </div>
    </section>
  );
}

function RecentRequests({ requests }: { requests: TrafficIPDetail["recent_requests"] }) {
  return (
    <section className="traffic-detail-section">
      <h3>Recent requests</h3>
      <ResponsiveTable>
        <thead><tr><th>Time</th><th>Request</th><th>Status</th></tr></thead>
        <tbody>
          {requests.slice(0, 12).map((request) => (
            <tr key={request.event_id}>
              <td title={formatDate(request.event_time)}>{formatRelative(request.event_time)}</td>
              <td><strong>{request.method}</strong><small>{request.path}</small></td>
              <td>{request.status_code || "-"}</td>
            </tr>
          ))}
        </tbody>
      </ResponsiveTable>
    </section>
  );
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
  if (policy === "mixed") return "Mixed policy";
  return "Neutral";
}

function policyDescription(policy: string) {
  if (policy === "trusted") return "Manually labeled trusted; findings remain unchanged.";
  if (policy === "blocked") return "Marked blocked for triage; enforce it in your proxy or firewall.";
  return "No manual trust decision has been made.";
}

function scopeLabel(instance: InstanceModel) {
  return `${instance.companyName} / ${instance.projectName} / ${instance.environmentName} / ${instance.appName}`;
}

function humanize(value?: string) {
  if (!value) return "Unknown";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function versionedLabel(family?: string, version?: string) {
  if (!family && !version) return "Unknown";
  return [family, version].filter(Boolean).join(" ");
}

function formatCount(value: number) {
  return new Intl.NumberFormat().format(value);
}

export function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const scaled = value / 1024 ** index;
  return `${scaled.toLocaleString(undefined, { maximumFractionDigits: index === 0 ? 0 : 1 })} ${units[index]}`;
}
