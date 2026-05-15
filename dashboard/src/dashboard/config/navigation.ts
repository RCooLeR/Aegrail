import {
  Activity,
  AlertTriangle,
  Boxes,
  Building2,
  FileText,
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
  { key: "companies", label: "Companies", icon: Building2 },
  { key: "sites", label: "Sites", icon: Boxes },
  { key: "nodes", label: "Nodes", icon: MonitorCog },
  { key: "issues", label: "Issues", icon: AlertTriangle },
  { key: "signals", label: "Signals", icon: Activity },
  { key: "reports", label: "Reports", icon: FileText },
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
