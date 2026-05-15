import { ChevronLeft, ChevronRight, Loader2, RefreshCw, ShieldCheck, UserCircle } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import type { EstateModel } from "../../estate";
import type { HubUser } from "../../types";
import { navItems } from "../config/navigation";
import { viewSubtitle } from "../model/viewModels";
import type { FilterState, SiteRow, ViewKey } from "../types";
import { formatRelative } from "../utils/time";
import { userInitials } from "../utils/users";
import { GlobalFilters } from "./GlobalFilters";
import { InlineAlert, InlineSuccess } from "./common";

const sidebarStorageKey = "aegrail.dashboard.sidebarCollapsed";

export function DashboardShell({
  actionError,
  actionLoading,
  actionMessage,
  allSites,
  children,
  estate,
  filters,
  lastLoadedAt,
  loading,
  onAcceptBaseline,
  onFilterChange,
  onFilterReset,
  onRefresh,
  onSignOut,
  onView,
  user,
  visibleOpenIssueCount,
  view
}: {
  actionError: string;
  actionLoading: boolean;
  actionMessage: string;
  allSites: SiteRow[];
  children: ReactNode;
  estate: EstateModel;
  filters: FilterState;
  lastLoadedAt: Date | null;
  loading: boolean;
  onAcceptBaseline: () => void;
  onFilterChange: (patch: Partial<FilterState>) => void;
  onFilterReset: () => void;
  onRefresh: () => void;
  onSignOut: () => void;
  onView: (view: ViewKey) => void;
  user?: HubUser;
  visibleOpenIssueCount: number;
  view: ViewKey;
}) {
  const [isSidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === "undefined") {
      return false;
    }
    const stored = window.localStorage.getItem(sidebarStorageKey);
    if (stored !== null) {
      return stored === "true";
    }
    return window.matchMedia("(max-width: 900px)").matches;
  });

  useEffect(() => {
    window.localStorage.setItem(sidebarStorageKey, String(isSidebarCollapsed));
  }, [isSidebarCollapsed]);

  return (
    <div className={`app-shell ${isSidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      <aside className={`sidebar ${isSidebarCollapsed ? "collapsed" : ""}`}>
        <a className="brand" href="/dashboard/" aria-label="Aegrail dashboard">
          <img className="brand-logo-full" src={`${import.meta.env.BASE_URL}aegrail-horizontal-white.png`} alt="Aegrail" />
          <img className="brand-logo-icon" src={`${import.meta.env.BASE_URL}icon.png`} alt="" aria-hidden="true" />
        </a>
        <button
          className="sidebar-toggle"
          type="button"
          aria-controls="dashboard-side-nav"
          aria-expanded={!isSidebarCollapsed}
          aria-label={isSidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-pressed={isSidebarCollapsed}
          title={isSidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={() => setSidebarCollapsed((current) => !current)}
        >
          {isSidebarCollapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}
          <span>{isSidebarCollapsed ? "Expand" : "Collapse"}</span>
        </button>
        <nav className="side-nav" id="dashboard-side-nav" aria-label="Dashboard navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = view === item.key || (view === "issue" && item.key === "issues");
            return (
              <button
                aria-label={isSidebarCollapsed ? item.label : undefined}
                className={active ? "active" : ""}
                key={item.key}
                title={isSidebarCollapsed ? item.label : undefined}
                type="button"
                onClick={() => onView(item.key)}
              >
                <Icon size={18} aria-hidden="true" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <span className={`live-dot ${loading ? "loading" : "ok"}`} />
          <span>{loading ? "Refreshing" : "Live"}</span>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">{viewSubtitle(view, filters, estate)}</p>
            <h1>{view === "issue" ? "Issue detail" : navItems.find((item) => item.key === view)?.label ?? "Overview"}</h1>
          </div>
          <div className="topbar-actions">
            <span className="last-refresh">{lastLoadedAt ? `Updated ${formatRelative(lastLoadedAt.toISOString())}` : "Not loaded yet"}</span>
            {view !== "settings" && (
              <button className="primary-button baseline-button" type="button" disabled={loading || actionLoading || visibleOpenIssueCount === 0} onClick={onAcceptBaseline}>
                {actionLoading ? <Loader2 size={17} className="spin" /> : <ShieldCheck size={17} />}
                <span>Accept baseline{visibleOpenIssueCount > 0 ? ` (${visibleOpenIssueCount})` : ""}</span>
              </button>
            )}
            <button className="icon-button" type="button" disabled={loading} onClick={onRefresh}>
              {loading ? <Loader2 size={17} className="spin" /> : <RefreshCw size={17} />}
              <span>Refresh</span>
            </button>
            <button className="avatar-button" type="button" onClick={onSignOut} title="Sign out">
              <UserCircle size={17} />
              <span>{userInitials(user)}</span>
            </button>
          </div>
        </header>

        {view !== "settings" && view !== "issue" && (
          <GlobalFilters
            allSites={allSites}
            estate={estate}
            filters={filters}
            onChange={onFilterChange}
            onReset={onFilterReset}
          />
        )}

        {actionError && <InlineAlert message={actionError} />}
        {actionMessage && <InlineSuccess message={actionMessage} />}
        {children}
      </main>
    </div>
  );
}
