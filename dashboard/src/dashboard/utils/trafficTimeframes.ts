import type { TrafficTimeframe, TrafficTimeRange } from "../types";

const minute = 60_000;
const hour = 60 * minute;
const day = 24 * hour;

export const trafficTimeframeOptions: Array<{
  durationMs: number;
  label: string;
  value: TrafficTimeframe;
}> = [
  { value: "15m", label: "Last 15 minutes", durationMs: 15 * minute },
  { value: "30m", label: "Last 30 minutes", durationMs: 30 * minute },
  { value: "1h", label: "Last hour", durationMs: hour },
  { value: "3h", label: "Last 3 hours", durationMs: 3 * hour },
  { value: "6h", label: "Last 6 hours", durationMs: 6 * hour },
  { value: "12h", label: "Last 12 hours", durationMs: 12 * hour },
  { value: "24h", label: "Last 24 hours", durationMs: day },
  { value: "3d", label: "Last 3 days", durationMs: 3 * day },
  { value: "7d", label: "Last 7 days", durationMs: 7 * day },
  { value: "10d", label: "Last 10 days", durationMs: 10 * day },
  { value: "14d", label: "Last 14 days", durationMs: 14 * day },
  { value: "30d", label: "Last 30 days", durationMs: 30 * day }
];

const optionByValue = new Map(trafficTimeframeOptions.map((option) => [option.value, option]));

export function isTrafficTimeframe(value: string): value is TrafficTimeframe {
  return optionByValue.has(value as TrafficTimeframe);
}

export function trafficTimeframeLabel(value: TrafficTimeframe) {
  return optionByValue.get(value)?.label ?? "Last 24 hours";
}

export function trafficTimeframeDurationMs(value: TrafficTimeframe) {
  return optionByValue.get(value)?.durationMs ?? day;
}

export function trafficTimeRange(value: TrafficTimeframe, now = Date.now()): TrafficTimeRange {
  return {
    since: new Date(now - trafficTimeframeDurationMs(value)).toISOString(),
    until: new Date(now).toISOString()
  };
}
