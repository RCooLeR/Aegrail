import { Building2 } from "lucide-react";
import type { CompanyModel } from "../../estate";
import { formatRelative } from "../utils/time";
import { Panel, ResponsiveTable, StatusPill } from "../components/common";

export function CompaniesPage({ companies, onCompany }: { companies: CompanyModel[]; onCompany: (company: CompanyModel) => void }) {
  return (
    <Panel title="Companies" icon={Building2}>
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Company</th>
            <th>Status</th>
            <th>Open issues</th>
            <th>Critical</th>
            <th>Sites</th>
            <th>Nodes</th>
            <th>Agents</th>
            <th>Last signal</th>
          </tr>
        </thead>
        <tbody>
          {companies.map((company) => (
            <tr key={company.companySlug} onClick={() => onCompany(company)}>
              <td><strong>{company.companyName}</strong><small>{company.statusReason}</small></td>
              <td><StatusPill value={company.status} /></td>
              <td>{company.openFindings}</td>
              <td>{company.criticalFindings}</td>
              <td>{company.siteCount}</td>
              <td>{company.instances.length}</td>
              <td>{company.instances.reduce((sum, instance) => sum + instance.activeAgentCount, 0)}/{company.instances.reduce((sum, instance) => sum + instance.agentCount, 0)}</td>
              <td>{formatRelative(company.lastSignalAt)}</td>
            </tr>
          ))}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}
