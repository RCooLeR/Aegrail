import { Clock3 } from "lucide-react";
import type { TrafficTimeframe } from "../types";
import { trafficTimeframeLabel, trafficTimeframeOptions } from "../utils/trafficTimeframes";

export function TrafficTimeframeSelect({
  loading,
  onChange,
  value
}: {
  loading: boolean;
  onChange: (value: TrafficTimeframe) => void;
  value: TrafficTimeframe;
}) {
  return (
    <section className="traffic-timeframe-toolbar" aria-label="Traffic timeframe">
      <div>
        <Clock3 aria-hidden="true" size={18} />
        <span>
          <strong>Traffic timeframe</strong>
          <small>{loading ? `Loading ${trafficTimeframeLabel(value).toLowerCase()}` : trafficTimeframeLabel(value)}</small>
        </span>
      </div>
      <label>
        <span className="sr-only">Select traffic timeframe</span>
        <select onChange={(event) => onChange(event.target.value as TrafficTimeframe)} value={value}>
          {trafficTimeframeOptions.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
      </label>
    </section>
  );
}
