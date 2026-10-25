import type { ActionState, IssueQueuePageSize, TrafficTimeframe } from "../types";
import { isTrafficTimeframe } from "./trafficTimeframes";

const finiteIssueQueuePageSizes = new Set<IssueQueuePageSize>([25, 50, 100, 250, 500]);

export function loadActionDefaults(): ActionState {
  const fallback = { actor: "dashboard", model: "", reason: "reviewed", note: "" };
  const raw = localStorage.getItem("aegrail.dashboard.triage");
  if (!raw) return fallback;
  try {
    return { ...fallback, ...JSON.parse(raw) };
  } catch {
    return fallback;
  }
}

export function saveActionDefaults(actionState: ActionState) {
  localStorage.setItem("aegrail.dashboard.triage", JSON.stringify(actionState));
}

export function loadIssueQueuePageSize(): IssueQueuePageSize {
  const parsed = Number(localStorage.getItem("aegrail.dashboard.issue-page-size"));
  return finiteIssueQueuePageSizes.has(parsed as IssueQueuePageSize) ? parsed as IssueQueuePageSize : 50;
}

export function saveIssueQueuePageSize(pageSize: IssueQueuePageSize) {
  // "All" is deliberately session-only so opening the dashboard never starts
  // an unexpectedly large fetch from a persisted preference.
  if (pageSize !== "all") {
    localStorage.setItem("aegrail.dashboard.issue-page-size", String(pageSize));
  }
}

export function loadTrafficTimeframe(): TrafficTimeframe {
  const value = localStorage.getItem("aegrail.dashboard.traffic-timeframe") ?? "";
  return isTrafficTimeframe(value) ? value : "24h";
}

export function saveTrafficTimeframe(timeframe: TrafficTimeframe) {
  localStorage.setItem("aegrail.dashboard.traffic-timeframe", timeframe);
}
