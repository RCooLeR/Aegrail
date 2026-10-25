import { type FormEvent, useDeferredValue, useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import {
  acceptFindingsBaseline,
  allowBrowserScriptFromFinding,
  createBrowserScriptAllowlistEntry,
  createDeployment,
  generateModelAnalysisFromFinding,
  ignoreFilePathFromFinding,
  loadAuthMe,
  loadDeployments,
  loadEstateDashboard,
  loadFinding,
  loadFilteredFindingsPage,
  loadScope,
  loadTraffic,
  loadTrafficBots,
  loadTrafficIPDetail,
  loadTrafficUserAgentDetail,
  logoutHubUser,
  saveScope,
  updateTrafficIPPolicy as saveTrafficIPPolicy,
  updateBrowserAllowlistEntryStatus,
  updateFindingStatus,
  type DashboardInstanceSnapshot
} from "../../api";
import { buildEstateModel, type CompanyModel, type EstateModel, type InstanceModel } from "../../estate";
import type { ApiScope, FilteredFindingsPage, FindingsQuery, FindingsRequestState, HubAuthMe, HubFinding, HubFindingSummary, InventoryOrganization, RuleDefinition } from "../../types";
import { autoRefreshIntervalMs, basePath, initialFilters, severityRank } from "../config/navigation";
import {
  buildIssueRows,
  buildAllowlistRows,
  buildBrowserScriptRows,
  buildSignalRows,
  buildSiteRows,
  filterInstances,
  filterIssueRows,
  filterSignalRows,
  nodeLabel,
  serviceForFinding,
  summarizeEstate
} from "../model/viewModels";
import type {
  ActionState,
  AllowlistRow,
  BrowserScriptRow,
  DeploymentRow,
  FilterState,
  IssueQueuePageSize,
  IssueRow,
  TrafficBotsScopeData,
  TrafficIPDetailState,
  TrafficScopeData,
  TrafficTimeframe,
  TrafficTimeRange,
  TrafficUserAgentDetailState,
  ViewKey
} from "../types";
import { fileIgnorePathCandidate } from "../utils/metadata";
import { issueIDFromLocation, viewFromLocation } from "../utils/routing";
import { loadActionDefaults, loadIssueQueuePageSize, loadTrafficTimeframe, saveActionDefaults, saveIssueQueuePageSize, saveTrafficTimeframe } from "../utils/storage";
import { trafficTimeRange } from "../utils/trafficTimeframes";

const issueQueueAllBatchSize = 500;

type IssueQueueScopeProgress = {
  loaded: number;
  matchedTotal?: number;
  matchedTotalExact: boolean;
};

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
  const [issueQueueByInstance, setIssueQueueByInstance] = useState<Record<string, FilteredFindingsPage>>({});
  const [issueQueueError, setIssueQueueError] = useState("");
  const [issueQueueLoading, setIssueQueueLoading] = useState(false);
  const [issueQueuePage, setIssueQueuePage] = useState(0);
  const [issueQueuePageSize, setIssueQueuePageSize] = useState<IssueQueuePageSize>(() => loadIssueQueuePageSize());
  const [issueQueueProgressByInstance, setIssueQueueProgressByInstance] = useState<Record<string, IssueQueueScopeProgress>>({});
  const [issueQueueRefreshVersion, setIssueQueueRefreshVersion] = useState(0);
  const [issueQueueStatus, setIssueQueueStatus] = useState("open");
  const [issueLookupLoading, setIssueLookupLoading] = useState(false);
  const [issueLookupError, setIssueLookupError] = useState("");
  const [deploymentRows, setDeploymentRows] = useState<DeploymentRow[]>([]);
  const [deploymentLoading, setDeploymentLoading] = useState(false);
  const [deploymentError, setDeploymentError] = useState("");
  const [trafficScopes, setTrafficScopes] = useState<TrafficScopeData[]>([]);
  const [trafficLoading, setTrafficLoading] = useState(false);
  const [trafficError, setTrafficError] = useState("");
  const [trafficBotsScopes, setTrafficBotsScopes] = useState<TrafficBotsScopeData[]>([]);
  const [trafficBotsLoading, setTrafficBotsLoading] = useState(false);
  const [trafficBotsError, setTrafficBotsError] = useState("");
  const [trafficIPDetail, setTrafficIPDetail] = useState<TrafficIPDetailState | null>(null);
  const [trafficIPDetailLoading, setTrafficIPDetailLoading] = useState(false);
  const [trafficIPDetailError, setTrafficIPDetailError] = useState("");
  const [trafficUserAgentDetail, setTrafficUserAgentDetail] = useState<TrafficUserAgentDetailState | null>(null);
  const [trafficUserAgentDetailLoading, setTrafficUserAgentDetailLoading] = useState(false);
  const [trafficUserAgentDetailError, setTrafficUserAgentDetailError] = useState("");
  const [trafficPolicyLoading, setTrafficPolicyLoading] = useState(false);
  const [trafficTimeframe, setTrafficTimeframeState] = useState<TrafficTimeframe>(() => loadTrafficTimeframe());
  const refreshToken = useRef(0);
  const issueQueueAbortController = useRef<AbortController | null>(null);
  const issueQueueGeneration = useRef(0);
  const issueQueuePageSizeRef = useRef<IssueQueuePageSize>(issueQueuePageSize);
  const issueQueueRequestKey = useRef("");
  const issueLookupKey = useRef("");
  const trafficIPDetailAbortController = useRef<AbortController | null>(null);
  const trafficUserAgentDetailAbortController = useRef<AbortController | null>(null);
  const trafficWindowRef = useRef<TrafficTimeRange>(trafficTimeRange(trafficTimeframe));
  const debouncedIssueQuery = useDebouncedValue(filters.query.trim(), 275);

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

  async function refresh(activeScope = scope, refreshIssueQueue = true) {
    const token = ++refreshToken.current;
    setLoading(true);
    try {
      const data = await loadEstateDashboard(activeScope);
      if (token === refreshToken.current) {
        setEstate((current) => buildEstateModel(mergeRefreshedSnapshots(current, data.instances)));
        setInventory(data.scopes.data);
        setRules(data.rules.data);
        setLastLoadedAt(new Date());
        if (refreshIssueQueue) {
          setIssueQueueRefreshVersion((current) => current + 1);
        }
      }
    } finally {
      if (token === refreshToken.current) {
        setLoading(false);
      }
    }
  }

  const refreshVisibleDashboard = useEffectEvent(() => {
    if (document.visibilityState === "visible") {
      void refresh(scope, issueQueuePageSize !== "all");
    }
  });

  useEffect(() => {
    void refreshAuth(scope);
  }, [scope.baseUrl]);

  useEffect(() => {
    if (authLoading || !auth?.authenticated) {
      return;
    }
    void refresh(scope);
    const interval = window.setInterval(refreshVisibleDashboard, autoRefreshIntervalMs);
    document.addEventListener("visibilitychange", refreshVisibleDashboard);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", refreshVisibleDashboard);
    };
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

  useEffect(() => {
    issueQueuePageSizeRef.current = issueQueuePageSize;
    saveIssueQueuePageSize(issueQueuePageSize);
  }, [issueQueuePageSize]);

  useEffect(() => {
    saveTrafficTimeframe(trafficTimeframe);
  }, [trafficTimeframe]);

  const deferredQuery = useDeferredValue(filters.query, "");
  const deferredFilters = useMemo<FilterState>(
    () => ({
      company: filters.company,
      node: filters.node,
      query: deferredQuery,
      severity: filters.severity,
      site: filters.site
    }),
    [deferredQuery, filters.company, filters.node, filters.severity, filters.site]
  );
  const scopeFilters = useMemo<FilterState>(
    () => ({
      company: filters.company,
      node: filters.node,
      query: "",
      severity: "all",
      site: filters.site
    }),
    [filters.company, filters.node, filters.site]
  );
  const ruleByID = useMemo(() => new Map(rules.map((rule) => [rule.id, rule])), [rules]);
  const allSites = useMemo(() => buildSiteRows(estate.instances), [estate.instances]);
  const visibleInstances = useMemo(
    () => filterInstances(estate.instances, deferredFilters),
    [deferredFilters, estate.instances]
  );
  const issueScopeInstances = useMemo(
    () => filterInstances(estate.instances, scopeFilters),
    [estate.instances, scopeFilters]
  );
  const allIssueRows = useMemo(() => buildIssueRows(estate.instances, ruleByID), [estate.instances, ruleByID]);
  const visibleIssueRows = useMemo(() => buildIssueRows(visibleInstances, ruleByID), [ruleByID, visibleInstances]);
  const issueRows = useMemo(
    () => filterIssueRows(visibleIssueRows, deferredFilters),
    [deferredFilters, visibleIssueRows]
  );
  const issueQueueAllRows = useMemo(() => {
    const rows = issueScopeInstances.flatMap((instance) =>
      (issueQueueByInstance[instance.key]?.data ?? []).map((finding) => ({
        finding,
        instance,
        service: serviceForFinding(finding, ruleByID.get(finding.rule_id))
      }))
    );
    return rows.sort(compareIssueQueueRows);
  }, [issueQueueByInstance, issueScopeInstances, ruleByID]);
  const issueQueueResultsTotalExact = issueScopeInstances.every(
    (instance) => issueQueueByInstance[instance.key]?.matchedTotalExact
  );
  const issueQueueResultsTotal = issueScopeInstances.reduce(
    (total, instance) => total + (issueQueueByInstance[instance.key]?.matchedTotal ?? 0),
    0
  );
  const issueQueueProgressTotalExact = issueScopeInstances.every(
    (instance) => issueQueueProgressByInstance[instance.key]?.matchedTotalExact
  );
  const issueQueueProgressTotal = issueScopeInstances.reduce(
    (total, instance) => total + (issueQueueProgressByInstance[instance.key]?.matchedTotal ?? 0),
    0
  );
  const issueQueueLoadedCount = issueQueuePageSize === "all" && issueQueueLoading
    ? issueScopeInstances.reduce(
        (total, instance) => total + (issueQueueProgressByInstance[instance.key]?.loaded ?? 0),
        0
      )
    : issueQueueAllRows.length;
  const issueQueueMatchedTotalExact = issueQueueResultsTotalExact || (
    issueQueuePageSize === "all" && issueQueueLoading && issueQueueProgressTotalExact
  );
  const issueQueueMatchedTotal = issueQueueResultsTotalExact
    ? issueQueueResultsTotal
    : issueQueueMatchedTotalExact
      ? issueQueueProgressTotal
      : 0;
  const issueQueuePageCount = issueQueuePageSize === "all"
    ? 1
    : Math.max(
        1,
        Math.ceil((issueQueueMatchedTotalExact ? issueQueueMatchedTotal : issueQueueAllRows.length) / issueQueuePageSize)
      );
  const issueQueueCurrentPage = issueQueuePageSize === "all" ? 0 : Math.min(issueQueuePage, issueQueuePageCount - 1);
  const issueQueueRows = issueQueuePageSize === "all"
    ? issueQueueAllRows
    : issueQueueAllRows.slice(
        issueQueueCurrentPage * issueQueuePageSize,
        (issueQueueCurrentPage + 1) * issueQueuePageSize
      );
  const issueQueueScopeSignature = issueScopeInstances
    .map((instance) => [instance.scope.baseUrl, instance.key].join("\u0000"))
    .sort()
    .join("\u0001");
  const issueQueueFilterKey = JSON.stringify({
    q: debouncedIssueQuery,
    scopes: issueQueueScopeSignature,
    severity: filters.severity,
    status: issueQueueStatus,
    pageSize: issueQueuePageSize
  });
  const signalInstances = issueScopeInstances;
  const signalRows = useMemo(() => {
    const linkedIssueRows = buildIssueRows(signalInstances, ruleByID);
    return filterSignalRows(buildSignalRows(signalInstances, linkedIssueRows), deferredFilters).slice(0, 500);
  }, [deferredFilters, ruleByID, signalInstances]);
  const browserScriptRows = useMemo(() => buildBrowserScriptRows(visibleInstances), [visibleInstances]);
  const allowlistRows = useMemo(() => buildAllowlistRows(visibleInstances), [visibleInstances]);
  const deploymentTargets = useMemo(() => uniqueDeploymentTargets(issueScopeInstances), [issueScopeInstances]);
  const deploymentTargetSignature = deploymentTargets.map((instance) => deploymentScopeKey(instance.scope)).sort().join("\u0001");
  const trafficTargets = useMemo(() => uniqueTrafficTargets(issueScopeInstances), [issueScopeInstances]);
  const trafficTargetSignature = trafficTargets.map((instance) => trafficScopeKey(instance.scope)).sort().join("\u0001");
  const selectedIssue = allIssueRows.find((row) => row.finding.id === selectedIssueID) ??
    issueQueueAllRows.find((row) => row.finding.id === selectedIssueID) ??
    (view === "issue" ? undefined : issueQueueRows[0] ?? issueRows[0]);
  const dashboardStats = useMemo(
    () => summarizeEstate(visibleInstances, issueRows, signalRows, deferredFilters),
    [deferredFilters, issueRows, signalRows, visibleInstances]
  );
  const visibleOpenIssueCountState = useMemo(
    () => summarizeVisibleOpenFindings(visibleInstances, issueRows, deferredFilters),
    [deferredFilters, issueRows, visibleInstances]
  );
  const visibleOpenIssueCount = visibleOpenIssueCountState.count;

  useEffect(() => {
    setDeploymentRows([]);
  }, [deploymentTargetSignature]);

  useEffect(() => {
    trafficIPDetailAbortController.current?.abort();
    trafficIPDetailAbortController.current = null;
    trafficUserAgentDetailAbortController.current?.abort();
    trafficUserAgentDetailAbortController.current = null;
    setTrafficIPDetail(null);
    setTrafficIPDetailLoading(false);
    setTrafficIPDetailError("");
    setTrafficUserAgentDetail(null);
    setTrafficUserAgentDetailLoading(false);
    setTrafficUserAgentDetailError("");
  }, [trafficTargetSignature, trafficTimeframe]);

  useEffect(() => {
    if (authLoading || !auth?.authenticated || view !== "deployments") {
      return;
    }
    let cancelled = false;
    setDeploymentLoading(true);
    setDeploymentError("");
    Promise.all(deploymentTargets.map(async (instance) => {
      try {
        return { deployments: await loadDeployments(instance.scope), instance };
      } catch (error) {
        return { error: error instanceof Error ? error.message : String(error), instance };
      }
    }))
      .then((results) => {
        if (cancelled) return;
        const successfulScopeKeys = new Set(results.flatMap((result) => result.deployments !== undefined
          ? [deploymentScopeKey(result.instance.scope)]
          : []));
        const freshRows = results.flatMap(({ deployments, instance }) => (deployments ?? []).map((deployment) => ({ deployment, instance })));
        setDeploymentRows((current) => {
          const seen = new Set<string>();
          return [
            ...freshRows,
            ...current.filter((row) => !successfulScopeKeys.has(deploymentScopeKey(row.instance.scope)))
          ]
            .filter((row) => {
              if (seen.has(row.deployment.id)) return false;
              seen.add(row.deployment.id);
              return true;
            })
            .sort((left, right) => new Date(right.deployment.started_at).getTime() - new Date(left.deployment.started_at).getTime());
        });
        setDeploymentError(Array.from(new Set(results.flatMap((result) => result.error
          ? [`${result.instance.companyName} / ${result.instance.projectName}: ${result.error}`]
          : []))).join(" "));
      })
      .catch((error) => {
        if (!cancelled) setDeploymentError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (!cancelled) setDeploymentLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [auth?.authenticated, authLoading, deploymentTargetSignature, lastLoadedAt, view]);

  useEffect(() => {
    if (authLoading || !auth?.authenticated || (view !== "traffic" && view !== "bots")) {
      return;
    }
    const abortController = new AbortController();
    const loadBots = view === "bots";
    const range = trafficTimeRange(trafficTimeframe);
    trafficWindowRef.current = range;
    if (loadBots) {
      setTrafficBotsLoading(true);
      setTrafficBotsError("");
    } else {
      setTrafficLoading(true);
      setTrafficError("");
    }

    Promise.all(trafficTargets.map(async (instance) => {
      try {
        const data = loadBots
          ? await loadTrafficBots(instance.scope, range, abortController.signal)
          : await loadTraffic(instance.scope, range, abortController.signal);
        return { data, instance };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : String(error),
          instance
        };
      }
    }))
      .then((results) => {
        if (abortController.signal.aborted) {
          return;
        }
        const errors = results.flatMap((result) => result.error
          ? [`${result.instance.companyName} / ${result.instance.projectName}: ${result.error}`]
          : []);
        if (loadBots) {
          setTrafficBotsScopes(results.flatMap((result) => result.data
            ? [{ instance: result.instance, traffic: result.data as TrafficBotsScopeData["traffic"] }]
            : []));
          setTrafficBotsError(Array.from(new Set(errors)).join(" "));
        } else {
          setTrafficScopes(results.flatMap((result) => result.data
            ? [{ instance: result.instance, traffic: result.data as TrafficScopeData["traffic"] }]
            : []));
          setTrafficError(Array.from(new Set(errors)).join(" "));
        }
      })
      .finally(() => {
        if (abortController.signal.aborted) {
          return;
        }
        if (loadBots) {
          setTrafficBotsLoading(false);
        } else {
          setTrafficLoading(false);
        }
      });

    return () => abortController.abort();
  }, [auth?.authenticated, authLoading, lastLoadedAt, trafficTargetSignature, trafficTimeframe, view]);

  useEffect(() => {
    if (authLoading || !auth?.authenticated || view !== "issues") {
      return;
    }
    const reset = issueQueueRequestKey.current !== issueQueueFilterKey;
    issueQueueRequestKey.current = issueQueueFilterKey;
    const targetPage = reset ? 0 : issueQueueCurrentPage;
    if (reset) {
      issueQueueGeneration.current += 1;
      setIssueQueueByInstance({});
      setIssueQueueProgressByInstance({});
      setIssueQueueError("");
      setIssueQueuePage(0);
    }
    void reloadIssueQueue(targetPage, !reset);
    return () => {
      issueQueueGeneration.current += 1;
      issueQueueAbortController.current?.abort();
      issueQueueAbortController.current = null;
    };
  }, [auth?.authenticated, authLoading, issueQueueFilterKey, issueQueueRefreshVersion, view]);

  useEffect(() => {
    if (issueQueueMatchedTotalExact && issueQueuePage >= issueQueuePageCount) {
      setIssueQueuePage(issueQueuePageCount - 1);
    }
  }, [issueQueueMatchedTotalExact, issueQueuePage, issueQueuePageCount]);

  useEffect(() => {
    if (view !== "issue" || !selectedIssueID || selectedIssue || loading || estate.instances.length === 0) {
      if (selectedIssue) {
        setIssueLookupLoading(false);
        setIssueLookupError("");
      }
      return;
    }
    const lookupKey = `${selectedIssueID}\u0000${estate.instances.map((instance) => instance.key).join("\u0001")}`;
    if (issueLookupKey.current === lookupKey) {
      return;
    }
    issueLookupKey.current = lookupKey;
    let cancelled = false;
    setIssueLookupLoading(true);
    setIssueLookupError("");

    Promise.all(estate.instances.map(async (instance) => {
      try {
        return { finding: await loadFinding(instance.scope, selectedIssueID), instanceKey: instance.key };
      } catch (error) {
        return {
          error: error instanceof Error ? error.message : String(error),
          instanceKey: instance.key
        };
      }
    }))
      .then((results) => {
        if (cancelled) {
          return;
        }
        const match = results.find(
          (result): result is { finding: HubFinding; instanceKey: string } =>
            "finding" in result && Boolean(result.finding)
        );
        if (!match) {
          const errors = results.flatMap((result) => result?.error ? [result.error] : []);
          const allNotFound = errors.length > 0 && errors.every((message) => /(?:\b404\b|not found)/i.test(message));
          setIssueLookupError(allNotFound
            ? "The issue was not found in any visible environment."
            : `The issue lookup failed${errors.length ? `: ${Array.from(new Set(errors)).join(" ")}` : "."}`);
          // Permit the next dashboard refresh to retry transient transport,
          // authentication, or server failures for this same deep link.
          issueLookupKey.current = "";
          return;
        }
        setEstate((current) => buildEstateModel(current.instances.map((instance) => {
          if (instance.key !== match.instanceKey) {
            return instance.snapshot;
          }
          return snapshotWithFinding(instance.snapshot, match.finding);
        })));
      })
      .finally(() => {
        if (!cancelled) {
          setIssueLookupLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [estate.instances, loading, selectedIssue, selectedIssueID, view]);

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
    setIssueQueuePage(0);
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

  function updateIssueQueueStatus(status: string) {
    setIssueQueuePage(0);
    setIssueQueueStatus(status);
  }

  function updateIssueQueuePageSize(pageSize: IssueQueuePageSize) {
    if (pageSize === issueQueuePageSize) {
      return;
    }
    issueQueueGeneration.current += 1;
    issueQueueAbortController.current?.abort();
    issueQueueAbortController.current = null;
    setIssueQueueLoading(false);
    setIssueQueueByInstance({});
    setIssueQueueProgressByInstance({});
    setIssueQueueError("");
    setIssueQueuePage(0);
    setIssueQueuePageSize(pageSize);
  }

  function selectCompany(company: CompanyModel) {
    updateFilters({ company: company.companySlug });
    go("nodes");
  }

  function selectIssue(row: IssueRow) {
    setSelectedIssueID(row.finding.id);
    go("issue", row.finding.id);
  }

  async function reloadIssueQueue(targetPage: number, preserveOnError: boolean) {
    const generation = ++issueQueueGeneration.current;
    issueQueueAbortController.current?.abort();
    const abortController = new AbortController();
    issueQueueAbortController.current = abortController;
    const targetCount = issueQueuePageSize === "all"
      ? Number.POSITIVE_INFINITY
      : (targetPage + 1) * issueQueuePageSize;
    const requestLimit = issueQueuePageSize === "all" ? issueQueueAllBatchSize : issueQueuePageSize;
    const previous = issueQueueByInstance;
    setIssueQueueLoading(true);
    setIssueQueueError("");
    if (issueQueuePageSize === "all") {
      setIssueQueueProgressByInstance({});
    }
    try {
      const results: Array<{ error?: string; instanceKey: string; state?: FilteredFindingsPage }> = await Promise.all(
        issueScopeInstances.map(async (instance) => {
          try {
            const query = issueFindingsQuery(instance, issueQueueStatus, filters.severity, debouncedIssueQuery, requestLimit);
            const state = await loadIssueQueueScopeFromStart(
              instance.scope,
              query,
              targetCount,
              abortController.signal,
              issueQueuePageSize === "all"
                ? (progress) => {
                    if (generation !== issueQueueGeneration.current) {
                      return;
                    }
                    setIssueQueueProgressByInstance((current) => ({
                      ...current,
                      [instance.key]: {
                        loaded: progress.data.length,
                        matchedTotal: progress.matchedTotal,
                        matchedTotalExact: progress.matchedTotalExact
                      }
                    }));
                  }
                : undefined
            );
            return { instanceKey: instance.key, state };
          } catch (error) {
            return {
              error: error instanceof Error ? error.message : String(error),
              instanceKey: instance.key,
              state: preserveOnError ? previous[instance.key] : undefined
            };
          }
        })
      );
      if (generation !== issueQueueGeneration.current) {
        return;
      }
      const next: Record<string, FilteredFindingsPage> = {};
      for (const result of results) {
        if (result.state) {
          next[result.instanceKey] = result.state;
        }
      }
      setIssueQueueByInstance(next);
      const errors = results.flatMap((result) => result.error ? [result.error] : []);
      if (errors.length > 0) {
        setIssueQueueError(Array.from(new Set(errors)).join(" "));
      }
    } finally {
      if (generation === issueQueueGeneration.current) {
        setIssueQueueLoading(false);
        if (issueQueueAbortController.current === abortController) {
          issueQueueAbortController.current = null;
        }
      }
    }
  }

  async function nextIssueQueuePage() {
    if (
      issueQueuePageSize === "all" ||
      issueQueueLoading ||
      (issueQueueMatchedTotalExact && issueQueueCurrentPage >= issueQueuePageCount - 1)
    ) {
      return;
    }
    const generation = ++issueQueueGeneration.current;
    issueQueueAbortController.current?.abort();
    const abortController = new AbortController();
    issueQueueAbortController.current = abortController;
    const nextPage = issueQueueCurrentPage + 1;
    const targetCount = (nextPage + 1) * issueQueuePageSize;
    const previous = issueQueueByInstance;
    setIssueQueueLoading(true);
    setIssueQueueError("");
    try {
      const results: Array<{ error?: string; instanceKey: string; state: FilteredFindingsPage }> = await Promise.all(
        issueScopeInstances.map(async (instance) => {
          try {
            const query = issueFindingsQuery(instance, issueQueueStatus, filters.severity, debouncedIssueQuery, issueQueuePageSize);
            const initial = previous[instance.key] ?? await loadFilteredFindingsPage(
              instance.scope,
              query,
              "",
              abortController.signal
            );
            return {
              instanceKey: instance.key,
              state: await loadIssueQueueScopeThrough(
                instance.scope,
                query,
                initial,
                targetCount,
                abortController.signal
              )
            };
          } catch (error) {
            return {
              error: error instanceof Error ? error.message : String(error),
              instanceKey: instance.key,
              state: previous[instance.key] ?? emptyFilteredFindingsPage()
            };
          }
        })
      );
      if (generation !== issueQueueGeneration.current) {
        return;
      }
      const errors = results.flatMap((result) => result.error ? [result.error] : []);
      setIssueQueueByInstance(Object.fromEntries(results.map((result) => [result.instanceKey, result.state])));
      if (errors.length > 0) {
        setIssueQueueError(Array.from(new Set(errors)).join(" "));
        return;
      }
      setIssueQueuePage(nextPage);
    } finally {
      if (generation === issueQueueGeneration.current) {
        setIssueQueueLoading(false);
        if (issueQueueAbortController.current === abortController) {
          issueQueueAbortController.current = null;
        }
      }
    }
  }

  function previousIssueQueuePage() {
    if (!issueQueueLoading) {
      setIssueQueuePage((current) => Math.max(0, current - 1));
    }
  }

  async function setIssueStatus(row: IssueRow, status: string) {
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
      const updated = await updateFindingStatus(
        row.instance.scope,
        row.finding,
        status,
        actor,
        actionState.reason.trim() || defaultStatusReason(status),
        actionState.note.trim() || defaultStatusNote(status)
      );
      const updates = [{ finding: updated, instanceKey: row.instance.key, previous: row.finding }];
      applyFindingUpdates(setEstate, updates);
      applyIssueQueueUpdates(setIssueQueueByInstance, updates, issueQueueStatus);
      if (issueQueuePageSizeRef.current !== "all") {
        issueQueueGeneration.current += 1;
        issueQueueAbortController.current?.abort();
        issueQueueAbortController.current = null;
        setIssueQueueRefreshVersion((current) => current + 1);
      }
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setActionLoading(false);
    }
  }

  async function setIssueStatuses(rows: IssueRow[], status: string) {
    if (rows.length === 0) {
      return;
    }
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    const updates: Array<{ finding: HubFinding; instanceKey: string; previous: HubFinding }> = [];
    try {
      const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
      const reason = actionState.reason.trim() || defaultStatusReason(status);
      const note = actionState.note.trim() || defaultStatusNote(status);
      for (const row of rows) {
        const finding = await updateFindingStatus(row.instance.scope, row.finding, status, actor, reason, note);
        updates.push({ finding, instanceKey: row.instance.key, previous: row.finding });
      }
      applyFindingUpdates(setEstate, updates);
      applyIssueQueueUpdates(setIssueQueueByInstance, updates, issueQueueStatus);
      if (issueQueuePageSizeRef.current !== "all") {
        issueQueueGeneration.current += 1;
        issueQueueAbortController.current?.abort();
        issueQueueAbortController.current = null;
        setIssueQueueRefreshVersion((current) => current + 1);
      }
      setActionMessage(`Updated ${rows.length} issue${rows.length === 1 ? "" : "s"}.`);
    } catch (error) {
      applyFindingUpdates(setEstate, updates);
      if (updates.length > 0) {
        applyIssueQueueUpdates(setIssueQueueByInstance, updates, issueQueueStatus);
        if (issueQueuePageSizeRef.current !== "all") {
          issueQueueGeneration.current += 1;
          issueQueueAbortController.current?.abort();
          issueQueueAbortController.current = null;
          setIssueQueueRefreshVersion((current) => current + 1);
        }
      }
      setActionError(error instanceof Error ? error.message : String(error));
      throw error;
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

  async function allowBrowserScript(row: BrowserScriptRow) {
    const script = row.script;
    const kind = script.domain ? "domain" : script.sha256 ? "inline_hash" : script.tag_manager_ids?.length ? "tag_manager_id" : "";
    const value = script.domain ?? script.sha256 ?? script.tag_manager_ids?.[0] ?? "";
    if (!kind || !value) {
      throw new Error("Cannot infer an allowlist value for this script.");
    }
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
      const reason = actionState.reason.trim() || "approved_browser_script";
      await createBrowserScriptAllowlistEntry(row.instance.scope, {
        approved_by: actor,
        kind,
        page_url: script.page_url || script.final_url || "",
        reason,
        value
      });
      setActionMessage(`Allow-listed ${value}.`);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
      throw error;
    } finally {
      setActionLoading(false);
    }
  }

  async function allowBrowserScripts(rows: BrowserScriptRow[]) {
    const pending = rows.filter((row) => !row.allowlisted);
    if (pending.length === 0) {
      return;
    }
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
      const reason = actionState.reason.trim() || "approved_browser_script";
      let created = 0;
      const seen = new Set<string>();
      for (const row of pending) {
        const script = row.script;
        const kind = script.domain ? "domain" : script.sha256 ? "inline_hash" : script.tag_manager_ids?.length ? "tag_manager_id" : "";
        const value = script.domain ?? script.sha256 ?? script.tag_manager_ids?.[0] ?? "";
        if (!kind || !value) {
          continue;
        }
        const pageURL = script.page_url || script.final_url || "";
        const key = [row.instance.scope.org, row.instance.scope.project, row.instance.scope.environment, row.instance.scope.app, kind, value, pageURL].join("\u0000");
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        await createBrowserScriptAllowlistEntry(row.instance.scope, {
          approved_by: actor,
          kind,
          page_url: pageURL,
          reason,
          value
        });
        created += 1;
      }
      setActionMessage(`Allow-listed ${created} browser script${created === 1 ? "" : "s"}.`);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
      throw error;
    } finally {
      setActionLoading(false);
    }
  }

  async function updateAllowlistEntry(row: AllowlistRow, status: string) {
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
      const reason = actionState.reason.trim() || "operator_updated_allowlist";
      await updateBrowserAllowlistEntryStatus(row.instance.scope, row.entry, status, reason, actor);
      setActionMessage(`${status === "active" ? "Reinstated" : "Revoked"} ${row.entry.value}.`);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
      throw error;
    } finally {
      setActionLoading(false);
    }
  }

  async function updateAllowlistEntries(rows: AllowlistRow[], status: string) {
    if (rows.length === 0) {
      return;
    }
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
      const reason = actionState.reason.trim() || "operator_updated_allowlist";
      for (const row of rows) {
        await updateBrowserAllowlistEntryStatus(row.instance.scope, row.entry, status, reason, actor);
      }
      setActionMessage(`${status === "active" ? "Reinstated" : "Revoked"} ${rows.length} allowlist entr${rows.length === 1 ? "y" : "ies"}.`);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
      throw error;
    } finally {
      setActionLoading(false);
    }
  }

  async function recordDeployment(input: {
    commitSha: string;
    instance: DeploymentRow["instance"];
    version: string;
  }) {
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const result = await createDeployment(input.instance.scope, {
        commit_sha: input.commitSha,
        version: input.version
      });
      setDeploymentRows((current) => [
        { deployment: result.deployment, instance: input.instance },
        ...current.filter((row) => row.deployment.id !== result.deployment.id)
      ]);
      setActionMessage(`Recorded ${input.version} as deployment context. Findings remain visible for review.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
      throw error;
    } finally {
      setActionLoading(false);
    }
  }

  async function openTrafficIPDetail(instance: InstanceModel, ip: string) {
    trafficIPDetailAbortController.current?.abort();
    const abortController = new AbortController();
    trafficIPDetailAbortController.current = abortController;
    setTrafficIPDetail(null);
    setTrafficIPDetailLoading(true);
    setTrafficIPDetailError("");
    try {
      const detail = await loadTrafficIPDetail(instance.scope, ip, trafficWindowRef.current, abortController.signal);
      if (!abortController.signal.aborted) {
        setTrafficIPDetail({ detail, instance });
      }
    } catch (error) {
      if (!abortController.signal.aborted) {
        setTrafficIPDetailError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (!abortController.signal.aborted) {
        setTrafficIPDetailLoading(false);
      }
      if (trafficIPDetailAbortController.current === abortController) {
        trafficIPDetailAbortController.current = null;
      }
    }
  }

  function closeTrafficIPDetail() {
    trafficIPDetailAbortController.current?.abort();
    trafficIPDetailAbortController.current = null;
    setTrafficIPDetail(null);
    setTrafficIPDetailLoading(false);
    setTrafficIPDetailError("");
  }

  async function openTrafficUserAgentDetail(instance: InstanceModel, hash: string) {
    trafficUserAgentDetailAbortController.current?.abort();
    const abortController = new AbortController();
    trafficUserAgentDetailAbortController.current = abortController;
    setTrafficUserAgentDetail(null);
    setTrafficUserAgentDetailLoading(true);
    setTrafficUserAgentDetailError("");
    try {
      const detail = await loadTrafficUserAgentDetail(instance.scope, hash, trafficWindowRef.current, abortController.signal);
      if (!abortController.signal.aborted) {
        setTrafficUserAgentDetail({ detail, instance });
      }
    } catch (error) {
      if (!abortController.signal.aborted) {
        setTrafficUserAgentDetailError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (!abortController.signal.aborted) {
        setTrafficUserAgentDetailLoading(false);
      }
      if (trafficUserAgentDetailAbortController.current === abortController) {
        trafficUserAgentDetailAbortController.current = null;
      }
    }
  }

  function closeTrafficUserAgentDetail() {
    trafficUserAgentDetailAbortController.current?.abort();
    trafficUserAgentDetailAbortController.current = null;
    setTrafficUserAgentDetail(null);
    setTrafficUserAgentDetailLoading(false);
    setTrafficUserAgentDetailError("");
  }

  function setTrafficTimeframe(timeframe: TrafficTimeframe) {
    if (timeframe === trafficTimeframe) return;
    setTrafficScopes([]);
    setTrafficBotsScopes([]);
    closeTrafficIPDetail();
    closeTrafficUserAgentDetail();
    setTrafficTimeframeState(timeframe);
  }

  async function setTrafficIPPolicy(
    instance: InstanceModel,
    ip: string,
    policy: "neutral" | "trusted" | "blocked",
    reason: string
  ) {
    setTrafficPolicyLoading(true);
    setTrafficIPDetailError("");
    try {
      const saved = await saveTrafficIPPolicy(instance.scope, ip, policy, reason);
      setTrafficScopes((current) => current.map((entry) => {
        if (trafficOrganizationKey(entry.instance.scope) !== trafficOrganizationKey(instance.scope)) {
          return entry;
        }
        return {
          ...entry,
          traffic: {
            ...entry.traffic,
            top_ips: entry.traffic.top_ips.map((summary) => summary.ip === ip ? {
              ...summary,
              blocked: saved.policy === "blocked",
              manual_policy: saved.policy,
              trusted: saved.policy === "trusted"
            } : summary)
          }
        };
      }));
      setTrafficIPDetail((current) => current && current.detail.ip === ip &&
        trafficScopeKey(current.instance.scope) === trafficScopeKey(instance.scope)
        ? {
            ...current,
            detail: {
              ...current.detail,
              blocked: saved.policy === "blocked",
              policy: saved,
              trusted: saved.policy === "trusted"
            }
          }
        : current);
      return saved;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setTrafficIPDetailError(message);
      throw error;
    } finally {
      setTrafficPolicyLoading(false);
    }
  }

  async function ignoreFilePath(row: IssueRow) {
    const candidate = fileIgnorePathCandidate(row.finding.metadata);
    const path = window.prompt("Ignore future file findings under this directory?", candidate);
    if (!path || !path.trim()) {
      return;
    }
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const actor = actionState.actor.trim() || auth?.user?.email || "dashboard";
      const reason = actionState.reason.trim() || "operator_ignored_file_path";
      await ignoreFilePathFromFinding(row.instance.scope, row.finding, path.trim(), actor, reason);
      setActionMessage(`Ignored future file findings under ${path.trim()}.`);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setActionLoading(false);
    }
  }

  async function generateAnalysis(row: IssueRow) {
    setActionError("");
    setActionMessage("");
    setActionLoading(true);
    try {
      const report = await generateModelAnalysisFromFinding(row.instance.scope, row.finding, {
        max_events: 8,
        max_metadata_depth: 4,
        max_string_length: 500,
        model: actionState.model || undefined
      });
      setActionMessage(`Generated ${report.status} model analysis for ${row.finding.title}.`);
      return report;
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
      return undefined;
    } finally {
      setActionLoading(false);
    }
  }

  async function acceptCurrentBaseline() {
    const openRows = issueRows.filter((row) => row.finding.status === "open");
    const baselineRows = openRows.filter((row) => !requiresManualAcknowledgement(row));
    const skippedManualRows = openRows.length - baselineRows.length;
    if (baselineRows.length === 0) {
      setActionMessage(skippedManualRows > 0 ? "High and Critical issues require manual acknowledgement." : "No open issues in the current view.");
      return;
    }
    const skipMessage = skippedManualRows > 0 ? `\n\n${skippedManualRows} High/Critical issue(s) will stay open for manual acknowledgement.` : "";
    const confirmMessage = `Accept ${baselineRows.length} open issue(s) in the current view as the safe baseline?${skipMessage}\n\nExisting evidence stays available, but these issues stop counting as active. New future issues will still open.`;
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
        for (const row of baselineRows) {
          await updateFindingStatus(row.instance.scope, row.finding, "acknowledged", actor, "baseline_accepted", note);
          updated += 1;
        }
      } else {
        const instancesByKey = new Map(baselineRows.map((row) => [row.instance.key, row.instance]));
        for (const instance of instancesByKey.values()) {
          const result = await acceptFindingsBaseline(instance.scope, {
            actor,
            note,
            reason: "baseline_accepted"
          });
          updated += result.updated;
        }
      }
      setActionMessage(`Accepted ${updated} current issue(s) as baseline.${skippedManualRows > 0 ? ` Left ${skippedManualRows} High/Critical issue(s) open.` : ""}`);
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
    allowlistRows,
    allSites,
    applyScope,
    auth,
    authError,
    authLoading,
    dashboardStats,
    deploymentError,
    deploymentLoading,
    deploymentRows,
    deploymentTargets,
    deferredQuery,
    draftScope,
    estate,
    filters,
    go,
    handleAuthenticated,
    inventory,
    issueQueueError,
    issueQueueKey: issueQueueFilterKey,
    issueQueueLoading,
    issueQueueMatchedTotal,
    issueQueueMatchedTotalExact,
    issueQueueLoadedCount,
    issueQueuePage: issueQueueCurrentPage,
    issueQueuePageCount,
    issueQueuePageSize,
    issueQueueRows,
    issueQueueStatus,
    issueRows,
    issueLookupError,
    issueLookupLoading,
    lastLoadedAt,
    loading,
    nextIssueQueuePage,
    previousIssueQueuePage,
    refresh: () => void refresh(),
    browserScriptRows,
    ruleByID,
    scope,
    selectedIssue,
    selectCompany,
    selectIssue,
    setActionState,
    setDraftScope,
    setFilters,
    setIssueStatus,
    setIssueStatuses,
    setIssueQueuePageSize: updateIssueQueuePageSize,
    setIssueQueueStatus: updateIssueQueueStatus,
    setSelectedIssueID,
    signalRows,
    signOut: () => void signOut(),
    allowBrowserScript,
    allowBrowserScripts,
    allowScript,
    generateAnalysis,
    ignoreFilePath,
    recordDeployment,
    closeTrafficIPDetail,
    closeTrafficUserAgentDetail,
    openTrafficIPDetail,
    openTrafficUserAgentDetail,
    setTrafficIPPolicy,
    setTrafficTimeframe,
    trafficBotsError,
    trafficBotsLoading,
    trafficBotsScopes,
    trafficError,
    trafficIPDetail,
    trafficIPDetailError,
    trafficIPDetailLoading,
    trafficLoading,
    trafficPolicyLoading,
    trafficScopes,
    trafficTargetSignature,
    trafficTimeframe,
    trafficUserAgentDetail,
    trafficUserAgentDetailError,
    trafficUserAgentDetailLoading,
    updateAllowlistEntry,
    updateAllowlistEntries,
    updateFilters,
    view,
    visibleOpenIssueCount,
    visibleOpenIssueCountExact: visibleOpenIssueCountState.exact,
    visibleInstances
  };
}

function mergeRefreshedSnapshots(current: EstateModel, incoming: DashboardInstanceSnapshot[]) {
  const previousByScope = new Map(current.instances.map((instance) => [snapshotScopeKey(instance.snapshot), instance.snapshot]));
  return incoming.map((snapshot) => {
    const previous = previousByScope.get(snapshotScopeKey(snapshot));
    if (!previous) {
      return snapshot;
    }
    return {
      ...snapshot,
      data: {
        ...snapshot.data,
        findings: mergeRefreshedFindings(previous.data.findings, snapshot.data.findings)
      }
    };
  });
}

function mergeRefreshedFindings(previous: FindingsRequestState, fresh: FindingsRequestState): FindingsRequestState {
  if (fresh.error) {
    return { ...previous, error: fresh.error };
  }
  const freshIDs = new Set(fresh.data.map((finding) => finding.id));
  const data = [...fresh.data, ...previous.data.filter((finding) => !freshIDs.has(finding.id))];
  const total = fresh.totalExact ? fresh.total : previous.totalExact ? previous.total : Math.max(data.length, fresh.total, previous.total);
  const totalExact = fresh.totalExact || previous.totalExact;
  const complete = totalExact
    ? data.length >= total
    : fresh.complete && previous.complete;
  return {
    complete,
    data,
    nextCursor: complete ? undefined : previous.complete ? fresh.nextCursor : previous.nextCursor ?? fresh.nextCursor,
    summary: fresh.summary ?? previous.summary,
    total,
    totalExact
  };
}

async function loadIssueQueueScopeFromStart(
  scope: ApiScope,
  query: FindingsQuery,
  targetCount: number,
  signal?: AbortSignal,
  onProgress?: (state: FilteredFindingsPage) => void
) {
  const first = await loadFilteredFindingsPage(scope, query, "", signal);
  onProgress?.(first);
  return loadIssueQueueScopeThrough(scope, query, first, targetCount, signal, onProgress);
}

async function loadIssueQueueScopeThrough(
  scope: ApiScope,
  query: FindingsQuery,
  initial: FilteredFindingsPage,
  targetCount: number,
  signal?: AbortSignal,
  onProgress?: (state: FilteredFindingsPage) => void
) {
  let current = initial;
  const cursors = new Set<string>();
  while (current.data.length < targetCount && current.nextCursor) {
    const cursor = current.nextCursor;
    if (cursors.has(cursor)) {
      throw new Error("The Hub returned a repeated findings cursor.");
    }
    cursors.add(cursor);
    const page = await loadFilteredFindingsPage(scope, query, cursor, signal);
    current = appendFilteredFindingsPage(current, page);
    onProgress?.(current);
  }
  return current;
}

function appendFilteredFindingsPage(current: FilteredFindingsPage, page: FilteredFindingsPage): FilteredFindingsPage {
  const seen = new Set<string>();
  const data = [...current.data, ...page.data].filter((finding) => {
    if (seen.has(finding.id)) {
      return false;
    }
    seen.add(finding.id);
    return true;
  });
  return {
    complete: page.complete,
    data,
    matchedTotal: current.matchedTotalExact ? current.matchedTotal : page.matchedTotal,
    matchedTotalExact: current.matchedTotalExact || page.matchedTotalExact,
    nextCursor: page.nextCursor
  };
}

function emptyFilteredFindingsPage(): FilteredFindingsPage {
  return {
    complete: false,
    data: [],
    matchedTotalExact: false
  };
}

function issueFindingsQuery(
  instance: InstanceModel,
  status: string,
  severity: string,
  value: string,
  limit: number
): FindingsQuery {
  const q = value.trim();
  const normalized = q.toLowerCase();
  const serviceLabels = instance.snapshot.app?.services?.flatMap((service) => [service.name, service.slug, service.role]) ?? [];
  const structuralMatch = normalized !== "" && [
    instance.companyName,
    instance.companySlug,
    instance.projectName,
    instance.projectSlug,
    instance.environmentName,
    instance.environmentSlug,
    instance.appName,
    instance.appSlug,
    instance.appKind,
    nodeLabel(instance),
    ...serviceLabels
  ].some((candidate) => candidate.toLowerCase().includes(normalized));
  return {
    limit,
    q: structuralMatch ? "" : q,
    severities: severity === "all" ? [] : [severity],
    statuses: status === "all" ? [] : [status]
  };
}

function compareIssueQueueRows(left: IssueRow, right: IssueRow) {
  const createdDiff = new Date(right.finding.created_at).getTime() - new Date(left.finding.created_at).getTime();
  if (createdDiff !== 0) {
    return createdDiff;
  }
  const fractionDiff = rfc3339FractionNanos(right.finding.created_at) - rfc3339FractionNanos(left.finding.created_at);
  if (fractionDiff !== 0) {
    return fractionDiff;
  }
  const findingIDDiff = right.finding.id.localeCompare(left.finding.id);
  return findingIDDiff !== 0 ? findingIDDiff : right.instance.key.localeCompare(left.instance.key);
}

function rfc3339FractionNanos(value: string) {
  const fraction = value.match(/\.(\d+)(?:Z|[+-]\d{2}:\d{2})$/)?.[1] ?? "";
  return Number(fraction.padEnd(9, "0").slice(0, 9));
}

function snapshotScopeKey(snapshot: DashboardInstanceSnapshot) {
  const scope = snapshot.scope;
  return [scope.baseUrl, scope.org, scope.project, scope.environment, scope.app].join("\u0000");
}

function snapshotWithFinding(
  snapshot: DashboardInstanceSnapshot,
  finding: HubFinding,
  knownPrevious?: HubFinding
): DashboardInstanceSnapshot {
  const current = snapshot.data.findings;
  const existingIndex = current.data.findIndex((item) => item.id === finding.id);
  const previousFinding = existingIndex >= 0 ? current.data[existingIndex] : knownPrevious;
  const data = existingIndex >= 0
    ? current.data.map((item) => item.id === finding.id ? finding : item)
    : [finding, ...current.data];
  return {
    ...snapshot,
    data: {
      ...snapshot.data,
      findings: {
        ...current,
        data,
        summary: previousFinding
          ? replaceFindingInSummary(current.summary, previousFinding, finding)
          : current.summary
      }
    }
  };
}

function applyFindingUpdates(
  setEstate: (update: (current: EstateModel) => EstateModel) => void,
  updates: Array<{ finding: HubFinding; instanceKey: string; previous?: HubFinding }>
) {
  if (updates.length === 0) {
    return;
  }
  const updatesByInstance = new Map<string, Array<{ finding: HubFinding; previous?: HubFinding }>>();
  for (const update of updates) {
    updatesByInstance.set(update.instanceKey, [...(updatesByInstance.get(update.instanceKey) ?? []), update]);
  }
  setEstate((current) => buildEstateModel(current.instances.map((instance) => {
    let snapshot = instance.snapshot;
    for (const update of updatesByInstance.get(instance.key) ?? []) {
      snapshot = snapshotWithFinding(snapshot, update.finding, update.previous);
    }
    return snapshot;
  })));
}

function applyIssueQueueUpdates(
  setQueue: (update: (current: Record<string, FilteredFindingsPage>) => Record<string, FilteredFindingsPage>) => void,
  updates: Array<{ finding: HubFinding; instanceKey: string }>,
  statusFilter: string
) {
  if (updates.length === 0) {
    return;
  }
  setQueue((current) => {
    const next = { ...current };
    for (const update of updates) {
      const state = next[update.instanceKey];
      if (!state) {
        continue;
      }
      const index = state.data.findIndex((finding) => finding.id === update.finding.id);
      if (index < 0) {
        continue;
      }
      const staysInQueue = statusFilter === "all" || normalizedFindingStatus(update.finding) === statusFilter;
      const data = staysInQueue
        ? state.data.map((finding) => finding.id === update.finding.id ? update.finding : finding)
        : state.data.filter((finding) => finding.id !== update.finding.id);
      next[update.instanceKey] = {
        ...state,
        data,
        matchedTotal: !staysInQueue && state.matchedTotal !== undefined
          ? Math.max(0, state.matchedTotal - 1)
          : state.matchedTotal
      };
    }
    return next;
  });
}

function replaceFindingInSummary(
  summary: HubFindingSummary | undefined,
  previous: HubFinding,
  current: HubFinding
) {
  if (!summary) {
    return summary;
  }
  const statusCounts = adjustedFindingCountMap(summary.statusCounts, normalizedFindingStatus(previous), normalizedFindingStatus(current));
  const severityCounts = adjustedFindingCountMap(summary.severityCounts, previous.severity, current.severity);
  const openSeverityCounts = summary.openSeverityCounts ? { ...summary.openSeverityCounts } : undefined;
  if (openSeverityCounts) {
    if (normalizedFindingStatus(previous) === "open") {
      openSeverityCounts[previous.severity] = Math.max(0, (openSeverityCounts[previous.severity] ?? 0) - 1);
    }
    if (normalizedFindingStatus(current) === "open") {
      openSeverityCounts[current.severity] = (openSeverityCounts[current.severity] ?? 0) + 1;
    }
  }
  return {
    openSeverityCounts,
    severityCounts,
    statusCounts
  };
}

function adjustedFindingCountMap(
  counts: Record<string, number> | undefined,
  previousKey: string,
  currentKey: string
) {
  if (!counts || previousKey === currentKey) {
    return counts;
  }
  return {
    ...counts,
    [previousKey]: Math.max(0, (counts[previousKey] ?? 0) - 1),
    [currentKey]: (counts[currentKey] ?? 0) + 1
  };
}

function normalizedFindingStatus(finding: HubFinding) {
  return finding.status?.trim() || "open";
}

function summarizeVisibleOpenFindings(instances: InstanceModel[], issueRows: IssueRow[], filters: FilterState) {
  const allPagesLoaded = instances.every((instance) => instance.data.findings.complete);
  if (!filters.query.trim()) {
    const property = {
      all: "openFindings",
      critical: "criticalFindings",
      high: "highFindings",
      medium: "mediumFindings"
    }[filters.severity] as "openFindings" | "criticalFindings" | "highFindings" | "mediumFindings" | undefined;
    if (property) {
      return {
        count: instances.reduce((total, instance) => total + instance[property], 0),
        exact: allPagesLoaded || instances.every((instance) => instance.findingCountsExact)
      };
    }
  }
  return {
    count: issueRows.filter((row) => row.finding.status === "open").length,
    exact: allPagesLoaded
  };
}

function useDebouncedValue(value: string, delay: number) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timeout = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timeout);
  }, [delay, value]);
  return debounced;
}

function uniqueDeploymentTargets(instances: InstanceModel[]) {
  const targets = new Map<string, InstanceModel>();
  for (const instance of instances) {
    const key = deploymentScopeKey(instance.scope);
    if (!targets.has(key)) targets.set(key, instance);
  }
  return Array.from(targets.values()).sort((left, right) =>
    left.companyName.localeCompare(right.companyName) ||
    left.projectName.localeCompare(right.projectName) ||
    left.environmentName.localeCompare(right.environmentName) ||
    left.appName.localeCompare(right.appName)
  );
}

function deploymentScopeKey(scope: ApiScope) {
  return [scope.baseUrl, scope.org, scope.project, scope.environment, scope.app].join("\u0000");
}

function uniqueTrafficTargets(instances: InstanceModel[]) {
  const targets = new Map<string, InstanceModel>();
  for (const instance of instances) {
    const key = trafficScopeKey(instance.scope);
    if (!targets.has(key)) targets.set(key, instance);
  }
  return Array.from(targets.values()).sort((left, right) =>
    left.companyName.localeCompare(right.companyName) ||
    left.projectName.localeCompare(right.projectName) ||
    left.environmentName.localeCompare(right.environmentName) ||
    left.appName.localeCompare(right.appName)
  );
}

function trafficScopeKey(scope: ApiScope) {
  return [scope.baseUrl, scope.org, scope.project, scope.environment, scope.app].join("\u0000");
}

function trafficOrganizationKey(scope: ApiScope) {
  return [scope.baseUrl, scope.org].join("\u0000");
}

function requiresManualAcknowledgement(row: IssueRow) {
  return (severityRank[row.finding.severity] ?? 0) >= severityRank.high;
}

function defaultStatusReason(status: string) {
  switch (status) {
    case "acknowledged": return "operator_acknowledged";
    case "resolved": return "operator_resolved";
    case "false_positive": return "operator_false_positive";
    default: return "operator_updated";
  }
}

function defaultStatusNote(status: string) {
  switch (status) {
    case "acknowledged": return "Reviewed and accepted as expected for now.";
    case "resolved": return "Reviewed and fixed or cleaned up.";
    case "false_positive": return "Reviewed and marked as noise or irrelevant.";
    default: return "Status updated from dashboard.";
  }
}
