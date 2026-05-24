import { AuthGate } from "./dashboard/components/AuthGate";
import { DashboardShell } from "./dashboard/components/DashboardShell";
import { initialFilters } from "./dashboard/config/navigation";
import { useDashboardController } from "./dashboard/controllers/useDashboardController";
import { BrowserScriptsPage } from "./dashboard/pages/BrowserScriptsPage";
import { CompaniesPage } from "./dashboard/pages/CompaniesPage";
import { DeploymentsPage } from "./dashboard/pages/DeploymentsPage";
import { IssueDetailPage } from "./dashboard/pages/IssueDetailPage";
import { IssuesPage } from "./dashboard/pages/IssuesPage";
import { NodesPage } from "./dashboard/pages/NodesPage";
import { OverviewPage } from "./dashboard/pages/OverviewPage";
import { ReportsPage } from "./dashboard/pages/ReportsPage";
import { SettingsPage } from "./dashboard/pages/SettingsPage";
import { SignalsPage } from "./dashboard/pages/SignalsPage";
import { SitesPage } from "./dashboard/pages/SitesPage";

export default function App() {
  const dashboard = useDashboardController();

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
      view={dashboard.view}
    >
      {dashboard.view === "overview" && (
        <OverviewPage
          onCompany={dashboard.selectCompany}
          stats={dashboard.dashboardStats}
          visibleInstances={dashboard.visibleInstances}
        />
      )}
      {dashboard.view === "companies" && (
        <CompaniesPage companies={dashboard.visibleCompanies} onCompany={dashboard.selectCompany} />
      )}
      {dashboard.view === "sites" && (
        <SitesPage onSite={dashboard.selectSite} sites={dashboard.visibleSites} />
      )}
      {dashboard.view === "nodes" && (
        <NodesPage
          actionLoading={dashboard.actionLoading}
          instances={dashboard.visibleInstances}
          issueRows={dashboard.issueRows}
          onIssue={dashboard.selectIssue}
          onStatus={dashboard.setIssueStatus}
        />
      )}
      {dashboard.view === "issues" && (
        <IssuesPage
          actionLoading={dashboard.actionLoading}
          issueRows={dashboard.issueRows}
          onIssue={dashboard.selectIssue}
          onBulkStatus={dashboard.setIssueStatuses}
          onStatus={dashboard.setIssueStatus}
          ruleByID={dashboard.ruleByID}
          selectedIssue={dashboard.selectedIssue}
        />
      )}
      {dashboard.view === "issue" && (
        <IssueDetailPage
          actionLoading={dashboard.actionLoading}
          issueRows={dashboard.issueRows}
          onAllowScript={dashboard.allowScript}
          onBack={() => dashboard.go("issues")}
          onGenerateAnalysis={dashboard.generateAnalysis}
          onIgnoreFilePath={dashboard.ignoreFilePath}
          onIssue={dashboard.selectIssue}
          onStatus={dashboard.setIssueStatus}
          reportRows={dashboard.reportRows}
          row={dashboard.selectedIssue}
          rule={dashboard.selectedIssue ? dashboard.ruleByID.get(dashboard.selectedIssue.finding.rule_id) : undefined}
          selectedModel={dashboard.actionState.model}
          signalRows={dashboard.signalRows}
        />
      )}
      {dashboard.view === "signals" && <SignalsPage rows={dashboard.signalRows} />}
      {dashboard.view === "browser" && (
        <BrowserScriptsPage
          actionLoading={dashboard.actionLoading}
          allowlistRows={dashboard.allowlistRows}
          onAllowScript={dashboard.allowBrowserScript}
          onAllowScripts={dashboard.allowBrowserScripts}
          onUpdateEntries={dashboard.updateAllowlistEntries}
          onUpdateEntry={dashboard.updateAllowlistEntry}
          scriptRows={dashboard.browserScriptRows}
        />
      )}
      {dashboard.view === "deployments" && (
        <DeploymentsPage
          actor={dashboard.actionState.actor || dashboard.auth.user?.email || "dashboard"}
          deploymentRows={dashboard.deploymentRows}
          issueRows={dashboard.deploymentIssueRows}
          loading={dashboard.loading || dashboard.actionLoading}
          onCreate={dashboard.recordDeployment}
          visibleInstances={dashboard.visibleInstances}
        />
      )}
      {dashboard.view === "reports" && (
        <ReportsPage issueRows={dashboard.issueRows} reports={dashboard.reportRows} visibleInstances={dashboard.visibleInstances} />
      )}
      {dashboard.view === "settings" && (
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
      )}
    </DashboardShell>
  );
}
