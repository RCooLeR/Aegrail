import {
  Activity,
  AlertTriangle,
  Bot,
  ChartNoAxesCombined,
  GitBranch,
  Globe,
  LayoutDashboard,
  MonitorCog,
  Settings,
  type LucideIcon
} from "lucide-react";
import type { FilterState, ViewKey } from "../types";

export const basePath = import.meta.env.BASE_URL.replace(/\/$/, "") || "/dashboard";
export const autoRefreshIntervalMs = 30_000;

export const navItems: Array<{ key: ViewKey; label: string; icon: LucideIcon }> = [
  { key: "overview", label: "Overview", icon: LayoutDashboard },
  { key: "nodes", label: "Nodes", icon: MonitorCog },
  { key: "issues", label: "Issues", icon: AlertTriangle },
  { key: "traffic", label: "Traffic", icon: ChartNoAxesCombined },
  { key: "bots", label: "Bots / crawlers", icon: Bot },
  { key: "signals", label: "Signals", icon: Activity },
  { key: "browser", label: "Browser scripts", icon: Globe },
  { key: "deployments", label: "Deployments", icon: GitBranch },
  { key: "settings", label: "Settings", icon: Settings }
];

export const viewKeys = new Set<ViewKey>([...navItems.map((item) => item.key), "issue"]);

export const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export const initialFilters: FilterState = {
  company: "all",
  site: "all",
  node: "all",
  severity: "all",
  query: ""
};
