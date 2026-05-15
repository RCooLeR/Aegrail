import { Filter, Search } from "lucide-react";
import type { EstateModel } from "../../estate";
import { filterInstances, nodeLabel } from "../model/viewModels";
import type { FilterState, SiteRow } from "../types";

export function GlobalFilters({
  allSites,
  estate,
  filters,
  onChange,
  onReset
}: {
  allSites: SiteRow[];
  estate: EstateModel;
  filters: FilterState;
  onChange: (patch: Partial<FilterState>) => void;
  onReset: () => void;
}) {
  const sites = filters.company === "all" ? allSites : allSites.filter((site) => site.companySlug === filters.company);
  const nodes = filterInstances(estate.instances, { ...filters, site: filters.site, node: "all", severity: "all", query: "" });
  const active = [filters.company, filters.site, filters.node, filters.severity].some((value) => value !== "all") || filters.query.trim() !== "";
  return (
    <section className="filters">
      <label>
        Company
        <select value={filters.company} onChange={(event) => onChange({ company: event.target.value })}>
          <option value="all">All companies</option>
          {estate.companies.map((company) => <option key={company.companySlug} value={company.companySlug}>{company.companyName}</option>)}
        </select>
      </label>
      <label>
        Site
        <select value={filters.site} onChange={(event) => onChange({ site: event.target.value })}>
          <option value="all">All sites</option>
          {sites.map((site) => <option key={site.key} value={site.key}>{site.projectName}</option>)}
        </select>
      </label>
      <label>
        Node
        <select value={filters.node} onChange={(event) => onChange({ node: event.target.value })}>
          <option value="all">All nodes</option>
          {nodes.map((instance) => <option key={instance.key} value={instance.key}>{nodeLabel(instance)}</option>)}
        </select>
      </label>
      <label>
        Severity
        <select value={filters.severity} onChange={(event) => onChange({ severity: event.target.value })}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </label>
      <label className="search-filter">
        Search
        <span>
          <Search size={15} />
          <input value={filters.query} onChange={(event) => onChange({ query: event.target.value })} placeholder="Project, issue, signal" />
        </span>
      </label>
      <button className="ghost-button" type="button" disabled={!active} onClick={onReset}>
        <Filter size={15} />
        Reset
      </button>
    </section>
  );
}
