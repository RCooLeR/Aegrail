import { Boxes } from "lucide-react";
import type { SiteRow } from "../types";
import { formatRelative } from "../utils/time";
import { Panel, ResponsiveTable, StatusPill } from "../components/common";

export function SitesPage({ onSite, sites }: { onSite: (site: SiteRow) => void; sites: SiteRow[] }) {
  return (
    <Panel title="Sites" icon={Boxes}>
      <ResponsiveTable>
        <thead>
          <tr>
            <th>Site</th>
            <th>Company</th>
            <th>Status</th>
            <th>Open issues</th>
            <th>Critical</th>
            <th>Nodes</th>
            <th>Agents</th>
            <th>Last signal</th>
          </tr>
        </thead>
        <tbody>
          {sites.map((site) => (
            <tr key={site.key} onClick={() => onSite(site)}>
              <td><strong>{site.projectName}</strong><small>{site.statusReason}</small></td>
              <td>{site.companyName}</td>
              <td><StatusPill value={site.status} /></td>
              <td>{site.openIssues}</td>
              <td>{site.criticalIssues}</td>
              <td>{site.instances.length}</td>
              <td>{site.agentActive}/{site.agentCount}</td>
              <td>{formatRelative(site.lastSignalAt)}</td>
            </tr>
          ))}
        </tbody>
      </ResponsiveTable>
    </Panel>
  );
}
