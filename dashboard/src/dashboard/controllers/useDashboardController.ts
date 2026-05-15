import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  acceptFindingsBaseline,
  allowBrowserScriptFromFinding,
  loadAuthMe,
  loadEstateDashboard,
  loadScope,
  logoutHubUser,
  saveScope,
  updateFindingStatus
} from "../../api";
import { buildEstateModel, type CompanyModel, type EstateModel } from "../../estate";
import type { ApiScope, HubAuthMe, InventoryOrganization, RuleDefinition } from "../../types";
import { autoRefreshIntervalMs, basePath, initialFilters } from "../config/navigation";
import {
  buildIssueRows,
  buildReportRows,
  buildSignalRows,
  buildSiteRows,
  companiesFromInstances,
  filterInstances,
  filterIssueRows,
  filterSignalRows,
  summarizeEstate
} from "../model/viewModels";
import type { ActionState, FilterState, IssueRow, SiteRow, ViewKey } from "../types";
import { issueIDFromLocation, viewFromLocation } from "../utils/routing";
import { loadActionDefaults, saveActionDefaults } from "../utils/storage";

export function useDashboardController() {
  const [scope, setScope] = useState<ApiScope>(() => loadScope());
  const [draftScope, setDraftScope] = useState<ApiScope>(() => loadScope());
  const [auth, setAuth] = useState<HubAuthMe | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authError, setAuthError] = useState("");
  const [estate, setEstate] = useState<EstateModel>(() => buildEstateModel([]));
  const [inventory, setInventory] = useState<InventoryOrganization[]>([]);
  const [rules, setRules] = useState<RuleDefinition[]>([]);
  const [view, setView] = useState<ViewKey>(() => viewFromLocation());
  const [filters, setFilters] = useState<FilterState>(initialFilters);
  const [loading, setLoading] = useState(true);
  const [lastLoadedAt, setLastLoadedAt] = useState<Date | null>(null);
  const [selectedIssueID, setSelectedIssueID] = useState(() => issueIDFromLocation());
  const [actionState, setActionState] = useState<ActionState>(() => loadActionDefaults());
  const [actionError, setActionError] = useState("");
  const [actionMessage, setActionMessage] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const refreshToken = useRef(0);

  async function refreshAuth(activeScope = scope) {
    setAuthLoading(true);
    setAuthError("");
    try {
      const nextAuth = await loadAuthMe(activeScope);
      setAuth(nextAuth);
      return nextAuth;
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : String(error));
      const fallback = { authenticated: false, auth_configured: true, requires_bootstrap: false };
      setAuth(fallback);
      return fallback;
    } finally {
      setAuthLoading(false);
    }
  }

  async function refresh(activeScope = scope) {
    const token = ++refreshToken.current;
    setLoading(true);
    try {
      const data = await loadEstateDashboard(activeScope);
      if (token === refreshToken.current) {
        setEstate(buildEstateModel(data.instances));
        setInventory(data.scopes.data);
        setRules(data.rules.data);
        setLastLoadedAt(new Date());
      }
    } finally {
      if (token === refreshToken.current) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    void refreshAuth(scope);
  }, [scope.baseUrl]);

  useEffect(() => {
    if (authLoading || !auth?.authenticated) {
      return;
    }
    void refresh(scope);
    const interval = window.setInterval(() => void refresh(scope), autoRefreshIntervalMs);
    return () => window.clearInterval(interval);
  }, [auth?.authenticated, authLoading, scope]);

  useEffect(() => {
    const handlePopState = () => {
      setView(viewFromLocation());
      setSelectedIssueID(issueIDFromLocation());
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    saveActionDefaults(actionState);
  }, [actionState]);

  const ruleByID = useMemo(() => new Map(rules.map((rule) => [rule.id, rule])), [rules]);
  const allSites = useMemo(() => buildSiteRows(estate.instances), [estate.instances]);
  const visibleInstances = useMemo(() => filterInstances(estate.instances, filters), [estate.instances, filters]);
  const visibleSites = useMemo(() => buildSiteRows(visibleInstances), [visibleInstances]);
  const issueRows = useMemo(() => filterIssueRows(buildIssueRows(visibleInstances, ruleByID), filters), [filters, ruleByID, visibleInstances]);
  const signalInstances = useMemo(() => filterInstances(estate.instances, { ...filters, severity: "all", query: "" }), [estate.instances, filters]);
  const signalRows = useMemo(() => {
    const linkedIssueRows = buildIssueRows(signalInstances, ruleByID);
    return filterSignalRows(buildSignalRows(signalInstances, linkedIssueRows), filters).slice(0, 500);
  }, [filters, ruleByID, signalInstances]);
  const reportRows = useMemo(() => buildReportRows(visibleInstances), [visibleInstances]);
  const selectedIssue = issueRows.find((row) => row.finding.id === selectedIssueID) ?? (view === "issue" ? undefined : issueRows[0]);
  const dashboardStats = useMemo(() => summarizeEstate(visibleInstances, issueRows, signalRows), [issueRows, signalRows, visibleInstances]);
  const visibleCompanies = useMemo(() => companiesFromInstances(visibleInstances), [visibleInstances]);
  const visibleOpenIssueCount = useMemo(() => issueRows.filter((row) => row.finding.status === "open").length, [issueRows]);

  function go(nextView: ViewKey, issueID = selectedIssueID) {
    setView(nextView);
    const nextPath = nextView === "overview"
      ? `${basePath}/`
      : nextView === "issue"
        ? `${basePath}/issue/${encodeURIComponent(issueID)}`
        : `${basePath}/${nextView}`;
    if (window.location.pathname !== nextPath) {
      window.history.pushState({}, "", nextPath);
    }
  }

  function applyScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalized = { ...draftScope, baseUrl: draftScope.baseUrl.trim().replace(/\/+$/, "") };
    setScope(normalized);
    saveScope(normalized);
  }

  function updateFilters(patch: Partial<FilterState>) {
    setFilters((current) => {
      const next = { ...current, ...patch };
      if (patch.company !== undefined) {
        next.site = "all";
        next.node = "all";
      }
      if (patch.site !== undefined) {
        next.node = "all";
      }
      return next;
    });
  }

  function selectCompany(company: CompanyModel) {
    updateFilters({ company: company.companySlug });
    go("sites");
  }

  function selectSite(site: SiteRow) {
    updateFilters({ company: site.companySlug, site: site.key });
    go("nodes");
  }

  function selectIssue(row: IssueRow) {
    setSelectedIssueID(row.finding.id);
    go("issue", row.finding.id);
  }

  async function setIssueStatus(row: IssueRow, status: string) {
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      await updateFindingStatus(row.instance.scope, row.finding, status, actionState.actor, actionState.reason, actionState.note);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setActionLoading(false);
    }
  }

  async function allowScript(row: IssueRow) {
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      await allowBrowserScriptFromFinding(row.instance.scope, row.finding, actionState.actor, actionState.reason);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setActionLoading(false);
    }
  }

  async function acceptCurrentBaseline() {
    const openRows = issueRows.filter((row) => row.finding.status === "open");
    if (openRows.length === 0) {
      setActionMessage("No open issues in the current view.");
      return;
    }
    const confirmMessage = `Accept ${openRows.length} open issue(s) in the current view as the safe baseline?\n\nExisting evidence stays available, but these issues stop counting as active. New future issues will still open.`;
    if (!window.confirm(confirmMessage)) {
      return;
    }
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
    const note = "Accepted current first-scan findings as the safe baseline. Future changes should still open new issues.";
    try {
      let updated = 0;
      const hasFineFilter = filters.severity !== "all" || filters.query.trim() !== "";
      if (hasFineFilter) {
        for (const row of openRows) {
          await updateFindingStatus(row.instance.scope, row.finding, "acknowledged", actor, "baseline_accepted", note);
          updated += 1;
        }
      } else {
        const instancesByKey = new Map(openRows.map((row) => [row.instance.key, row.instance]));
        for (const instance of instancesByKey.values()) {
          const result = await acceptFindingsBaseline(instance.scope, {
            actor,
            note,
            reason: "baseline_accepted"
          });
          updated += result.updated;
        }
      }
      setActionMessage(`Accepted ${updated} current issue(s) as baseline.`);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setActionLoading(false);
    }
  }

  async function signOut() {
    setAuthError("");
    try {
      await logoutHubUser(scope);
      setEstate(buildEstateModel([]));
      await refreshAuth(scope);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : String(error));
    }
  }

  async function handleAuthenticated() {
    const nextAuth = await refreshAuth(scope);
    if (nextAuth.authenticated) {
      await refresh(scope);
    }
  }

  return {
    actionError,
    actionLoading,
    actionMessage,
    actionState,
    acceptCurrentBaseline,
    allSites,
    applyScope,
    auth,
    authError,
    authLoading,
    dashboardStats,
    draftScope,
    estate,
    filters,
    go,
    handleAuthenticated,
    inventory,
    issueRows,
    lastLoadedAt,
    loading,
    refresh: () => void refresh(),
    reportRows,
    ruleByID,
    scope,
    selectedIssue,
    selectCompany,
    selectIssue,
    selectSite,
    setActionState,
    setDraftScope,
    setFilters,
    setIssueStatus,
    setSelectedIssueID,
    signalRows,
    signOut: () => void signOut(),
    allowScript,
    updateFilters,
    view,
    visibleCompanies,
    visibleOpenIssueCount,
    visibleInstances,
    visibleSites
  };
}
