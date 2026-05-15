import { Activity, AlertTriangle, Bell, Building2, ListChecks, TerminalSquare, type LucideIcon } from "lucide-react";
import type { CompanyModel, InstanceModel } from "../../estate";
import { buildSiteRows, companiesFromInstances } from "../model/viewModels";
import type { DashboardStats } from "../types";
import { formatRelative } from "../utils/time";
import { EmptyState, StatusPill } from "../components/common";

export function OverviewPage({
  onCompany,
  stats,
  visibleInstances
}: {
  onCompany: (company: CompanyModel) => void;
  stats: DashboardStats;
  visibleInstances: InstanceModel[];
}) {
  const companies = [...companiesFromInstances(visibleInstances)].sort(compareCompaniesBySeverity);
  const visibleCompanies = companies.slice(0, 6);
  const showCompanyMenu = companies.length > 6;
  const chips: Array<{ icon: LucideIcon; label: string; tone: string; value: number }> = [
    { icon: AlertTriangle, label: "Critical", tone: "danger", value: stats.criticalIssues },
    { icon: Bell, label: "High", tone: "warning", value: stats.highIssues },
    { icon: Building2, label: "Affected companies", tone: "neutral", value: stats.affectedCompanies },
    { icon: TerminalSquare, label: "Offline agents", tone: stats.offlineNodes > 0 ? "warning" : "ok", value: stats.offlineNodes },
    { icon: ListChecks, label: "Coverage gaps", tone: stats.coverageProblems > 0 ? "warning" : "ok", value: stats.coverageProblems },
    { icon: Activity, label: "Signals today", tone: "neutral", value: stats.signals }
  ];

  return (
    <div className="overview-stack">
      <section className="overview-chips" aria-label="Dashboard status">
        {chips.map((chip) => {
          const Icon = chip.icon;
          return (
            <div className={`overview-chip ${chip.tone}`} key={chip.label}>
              <Icon size={16} />
              <span>{chip.label}</span>
              <strong>{chip.value}</strong>
            </div>
          );
        })}
      </section>
      <div className={`overview-company-layout ${showCompanyMenu ? "with-menu" : ""}`}>
        <section className="overview-company-grid" aria-label="Company summaries">
          {visibleCompanies.map((company) => {
            const activeAgents = company.instances.reduce((sum, instance) => sum + instance.activeAgentCount, 0);
            const agentCount = company.instances.reduce((sum, instance) => sum + instance.agentCount, 0);
            const sites = [...buildSiteRows(company.instances)].sort(compareSitesBySeverity).slice(0, 5);
            return (
              <button className={`overview-company-card ${company.status}`} key={company.companySlug} type="button" onClick={() => onCompany(company)}>
                <header>
                  <span className={`status-dot ${company.status}`} />
                  <strong>{company.companyName}</strong>
                  <StatusPill value={company.status} />
                </header>
                <p>{company.statusReason}</p>
                <div className="overview-company-metrics">
                  <span><b>{company.openFindings}</b> open</span>
                  <span><b>{company.criticalFindings}</b> critical</span>
                  <span><b>{company.siteCount}</b> sites</span>
                  <span><b>{company.instances.length}</b> nodes</span>
                  <span><b>{activeAgents}/{agentCount}</b> agents</span>
                  <span><b>{formatRelative(company.lastSignalAt)}</b> last signal</span>
                </div>
                <div className="overview-site-list" aria-label={`${company.companyName} sites`}>
                  <div className="overview-site-list-head">
                    <span>Name</span>
                    <span>Status</span>
                    <span>Nodes</span>
                    <span>Agents</span>
                    <span>Issues</span>
                  </div>
                  {sites.map((site) => (
                    <div className="overview-site-row" key={site.key}>
                      <strong>{site.projectName}</strong>
                      <StatusPill value={site.status} />
                      <span>{site.instances.length}</span>
                      <span>{site.agentActive}/{site.agentCount}</span>
                      <span>{site.openIssues}</span>
                    </div>
                  ))}
                </div>
              </button>
            );
          })}
          {companies.length === 0 && <EmptyState title="No companies match the current filters" />}
        </section>
        {showCompanyMenu && (
          <aside className="overview-company-menu" aria-label="Companies">
            <strong>Companies</strong>
            {companies.map((company) => (
              <button key={company.companySlug} type="button" onClick={() => onCompany(company)}>
                <span className={`status-dot ${company.status}`} />
                <span>
                  <b>{company.companyName}</b>
                  <small>{company.siteCount} sites / {company.instances.length} nodes</small>
                </span>
                <StatusPill value={company.status} />
              </button>
            ))}
          </aside>
        )}
      </div>
    </div>
  );
}

function compareCompaniesBySeverity(left: CompanyModel, right: CompanyModel) {
  return severityRank(right.status) - severityRank(left.status) ||
    right.criticalFindings - left.criticalFindings ||
    right.openFindings - left.openFindings ||
    left.companyName.localeCompare(right.companyName);
}

function severityRank(status: string) {
  switch (status) {
    case "critical": return 3;
    case "warning": return 2;
    case "healthy": return 1;
    default: return 0;
  }
}

function compareSitesBySeverity(left: ReturnType<typeof buildSiteRows>[number], right: ReturnType<typeof buildSiteRows>[number]) {
  return severityRank(right.status) - severityRank(left.status) ||
    right.criticalIssues - left.criticalIssues ||
    right.openIssues - left.openIssues ||
    left.projectName.localeCompare(right.projectName);
}
