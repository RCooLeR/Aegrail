import { Activity, lazy, Suspense, useEffect, useState } from "react";
import { AuthGate } from "./dashboard/components/AuthGate";
import { LoadingBlock } from "./dashboard/components/common";
import { DashboardShell } from "./dashboard/components/DashboardShell";
import { initialFilters } from "./dashboard/config/navigation";
import { useDashboardController } from "./dashboard/controllers/useDashboardController";
import type { ViewKey } from "./dashboard/types";

const BrowserScriptsPage = lazy(() => import("./dashboard/pages/BrowserScriptsPage").then(({ BrowserScriptsPage }) => ({ default: BrowserScriptsPage })));
const BotsPage = lazy(() => import("./dashboard/pages/BotsPage").then(({ BotsPage }) => ({ default: BotsPage })));
const DeploymentsPage = lazy(() => import("./dashboard/pages/DeploymentsPage").then(({ DeploymentsPage }) => ({ default: DeploymentsPage })));
const IssueDetailPage = lazy(() => import("./dashboard/pages/IssueDetailPage").then(({ IssueDetailPage }) => ({ default: IssueDetailPage })));
const IssuesPage = lazy(() => import("./dashboard/pages/IssuesPage").then(({ IssuesPage }) => ({ default: IssuesPage })));
const NodesPage = lazy(() => import("./dashboard/pages/NodesPage").then(({ NodesPage }) => ({ default: NodesPage })));
const OverviewPage = lazy(() => import("./dashboard/pages/OverviewPage").then(({ OverviewPage }) => ({ default: OverviewPage })));
const SettingsPage = lazy(() => import("./dashboard/pages/SettingsPage").then(({ SettingsPage }) => ({ default: SettingsPage })));
const SignalsPage = lazy(() => import("./dashboard/pages/SignalsPage").then(({ SignalsPage }) => ({ default: SignalsPage })));
const TrafficPage = lazy(() => import("./dashboard/pages/TrafficPage").then(({ TrafficPage }) => ({ default: TrafficPage })));

export default function App() {
  const dashboard = useDashboardController();
  const [visitedViews, setVisitedViews] = useState<ReadonlySet<ViewKey>>(
    () => new Set([dashboard.view])
  );

  useEffect(() => {
    setVisitedViews((current) => {
      if (current.has(dashboard.view)) {
        return current;
      }
      const next = new Set(current);
      next.add(dashboard.view);
      return next;
    });
  }, [dashboard.view]);

  const hasVisited = (view: ViewKey) => dashboard.view === view || visitedViews.has(view);

  if (dashboard.authLoading || !dashboard.auth?.authenticated || !dashboard.auth.dashboard_ready) {
    return (
      <AuthGate
        auth={dashboard.auth}
        error={dashboard.authError}
        loading={dashboard.authLoading}
        onAuthenticated={dashboard.handleAuthenticated}
        scope={dashboard.scope}
      />
    );
  }

  return (
    <DashboardShell
      actionError={dashboard.actionError}
      actionLoading={dashboard.actionLoading}
      actionMessage={dashboard.actionMessage}
      allSites={dashboard.allSites}
      estate={dashboard.estate}
      filters={dashboard.filters}
      lastLoadedAt={dashboard.lastLoadedAt}
      loading={dashboard.loading}
      onAcceptBaseline={dashboard.acceptCurrentBaseline}
      onFilterChange={dashboard.updateFilters}
      onFilterReset={() => dashboard.setFilters(initialFilters)}
      onRefresh={dashboard.refresh}
      onSignOut={dashboard.signOut}
      onView={dashboard.go}
      user={dashboard.auth.user}
      visibleOpenIssueCount={dashboard.visibleOpenIssueCount}
      visibleOpenIssueCountExact={dashboard.visibleOpenIssueCountExact}
      view={dashboard.view}
    >
      <Suspense fallback={<LoadingBlock title="Loading dashboard view" />}>
        {hasVisited("overview") && (
          <Activity mode={dashboard.view === "overview" ? "visible" : "hidden"}>
            <OverviewPage
              onCompany={dashboard.selectCompany}
              stats={dashboard.dashboardStats}
              visibleInstances={dashboard.visibleInstances}
            />
          </Activity>
        )}
        {hasVisited("nodes") && (
          <Activity mode={dashboard.view === "nodes" ? "visible" : "hidden"}>
            <NodesPage
              actionLoading={dashboard.actionLoading}
              instances={dashboard.visibleInstances}
              issueRows={dashboard.issueRows}
              onIssue={dashboard.selectIssue}
              onStatus={dashboard.setIssueStatus}
            />
          </Activity>
        )}
        {hasVisited("issues") && (
          <Activity mode={dashboard.view === "issues" ? "visible" : "hidden"}>
            <IssuesPage
              actionLoading={dashboard.actionLoading}
              error={dashboard.issueQueueError}
              issueRows={dashboard.issueQueueRows}
              loadedCount={dashboard.issueQueueLoadedCount}
              loading={dashboard.issueQueueLoading}
              matchedTotal={dashboard.issueQueueMatchedTotal}
              matchedTotalExact={dashboard.issueQueueMatchedTotalExact}
              onNext={dashboard.nextIssueQueuePage}
              onPrevious={dashboard.previousIssueQueuePage}
              onIssue={dashboard.selectIssue}
              onBulkStatus={dashboard.setIssueStatuses}
              onPageSize={dashboard.setIssueQueuePageSize}
              onStatus={dashboard.setIssueStatus}
              onStatusFilter={dashboard.setIssueQueueStatus}
              page={dashboard.issueQueuePage}
              pageCount={dashboard.issueQueuePageCount}
              pageSize={dashboard.issueQueuePageSize}
              queueKey={dashboard.issueQueueKey}
              ruleByID={dashboard.ruleByID}
              selectedIssue={dashboard.selectedIssue}
              status={dashboard.issueQueueStatus}
            />
          </Activity>
        )}
        {hasVisited("issue") && (
          <Activity mode={dashboard.view === "issue" ? "visible" : "hidden"}>
            <IssueDetailPage
              key={dashboard.selectedIssue?.finding.id ?? "issue-loading"}
              actionLoading={dashboard.actionLoading}
              issueRows={dashboard.issueRows}
              onAllowScript={dashboard.allowScript}
              onBack={() => dashboard.go("issues")}
              onGenerateAnalysis={dashboard.generateAnalysis}
              onIgnoreFilePath={dashboard.ignoreFilePath}
              onIssue={dashboard.selectIssue}
              onStatus={dashboard.setIssueStatus}
              row={dashboard.selectedIssue}
              rowLookupError={dashboard.issueLookupError}
              rowLoading={dashboard.issueLookupLoading || dashboard.loading}
              rule={dashboard.selectedIssue ? dashboard.ruleByID.get(dashboard.selectedIssue.finding.rule_id) : undefined}
              selectedModel={dashboard.actionState.model}
              signalRows={dashboard.signalRows}
            />
          </Activity>
        )}
        {hasVisited("signals") && (
          <Activity mode={dashboard.view === "signals" ? "visible" : "hidden"}>
            <SignalsPage rows={dashboard.signalRows} />
          </Activity>
        )}
        {hasVisited("traffic") && (
          <Activity mode={dashboard.view === "traffic" ? "visible" : "hidden"}>
            <TrafficPage
              key={`traffic:${dashboard.trafficTargetSignature}:${dashboard.trafficTimeframe}`}
              canManagePolicy={["owner", "admin", "operator"].includes(dashboard.auth.user?.access_level ?? "")}
              data={dashboard.trafficScopes}
              error={dashboard.trafficError}
              ipDetail={dashboard.trafficIPDetail}
              ipDetailError={dashboard.trafficIPDetailError}
              ipDetailLoading={dashboard.trafficIPDetailLoading}
              loading={dashboard.trafficLoading}
              onCloseIP={dashboard.closeTrafficIPDetail}
              onCloseUserAgent={dashboard.closeTrafficUserAgentDetail}
              onIP={dashboard.openTrafficIPDetail}
              onPolicy={dashboard.setTrafficIPPolicy}
              onTimeframe={dashboard.setTrafficTimeframe}
              onUserAgent={dashboard.openTrafficUserAgentDetail}
              policyLoading={dashboard.trafficPolicyLoading}
              query={dashboard.deferredQuery}
              timeframe={dashboard.trafficTimeframe}
              userAgentDetail={dashboard.trafficUserAgentDetail}
              userAgentDetailError={dashboard.trafficUserAgentDetailError}
              userAgentDetailLoading={dashboard.trafficUserAgentDetailLoading}
            />
          </Activity>
        )}
        {hasVisited("bots") && (
          <Activity mode={dashboard.view === "bots" ? "visible" : "hidden"}>
            <BotsPage
              key={`bots:${dashboard.trafficTargetSignature}:${dashboard.trafficTimeframe}`}
              data={dashboard.trafficBotsScopes}
              detail={dashboard.trafficUserAgentDetail}
              detailError={dashboard.trafficUserAgentDetailError}
              detailLoading={dashboard.trafficUserAgentDetailLoading}
              error={dashboard.trafficBotsError}
              loading={dashboard.trafficBotsLoading}
              onClose={dashboard.closeTrafficUserAgentDetail}
              onTimeframe={dashboard.setTrafficTimeframe}
              onUserAgent={dashboard.openTrafficUserAgentDetail}
              query={dashboard.deferredQuery}
              timeframe={dashboard.trafficTimeframe}
            />
          </Activity>
        )}
        {hasVisited("browser") && (
          <Activity mode={dashboard.view === "browser" ? "visible" : "hidden"}>
            <BrowserScriptsPage
              actionLoading={dashboard.actionLoading}
              allowlistRows={dashboard.allowlistRows}
              onAllowScript={dashboard.allowBrowserScript}
              onAllowScripts={dashboard.allowBrowserScripts}
              onUpdateEntries={dashboard.updateAllowlistEntries}
              onUpdateEntry={dashboard.updateAllowlistEntry}
              scriptRows={dashboard.browserScriptRows}
            />
          </Activity>
        )}
        {hasVisited("deployments") && (
          <Activity mode={dashboard.view === "deployments" ? "visible" : "hidden"}>
            <DeploymentsPage
              deploymentRows={dashboard.deploymentRows}
              error={dashboard.deploymentError}
              loading={dashboard.deploymentLoading || dashboard.actionLoading}
              onCreate={dashboard.recordDeployment}
              visibleInstances={dashboard.deploymentTargets}
            />
          </Activity>
        )}
        {hasVisited("settings") && (
          <Activity mode={dashboard.view === "settings" ? "visible" : "hidden"}>
            <SettingsPage
              actionState={dashboard.actionState}
              allInstances={dashboard.estate.instances}
              allSites={dashboard.allSites}
              draftScope={dashboard.draftScope}
              inventory={dashboard.inventory}
              loading={dashboard.loading}
              onActionChange={dashboard.setActionState}
              onRefresh={dashboard.refresh}
              onScopeChange={dashboard.setDraftScope}
              onScopeSubmit={dashboard.applyScope}
              scope={dashboard.scope}
              user={dashboard.auth.user}
            />
          </Activity>
        )}
      </Suspense>
    </DashboardShell>
  );
}
