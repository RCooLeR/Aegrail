import type { InstanceModel } from "../../estate";
import type { RuleDefinition } from "../../types";
import { issueStatusLabel, nodeLabel, recommendedAction } from "../model/viewModels";
import type { IssueRow } from "../types";
import { firstMetadataString, metadataNumber, metadataStringList } from "./metadata";
import { formatDate } from "./time";

export function exportIssueBrief(row: IssueRow, rule?: RuleDefinition) {
  const account = firstMetadataString(row.finding.metadata, ["email", "account_display", "login", "email_masked", "login_masked"]);
  const changedFiles = metadataStringList(row.finding.metadata, "files");
  const omittedFiles = metadataNumber(row.finding.metadata, "omitted_file_count");
  const visibleEventIDs = row.finding.event_ids.slice(0, 50);
  const omittedEventIDs = Math.max(0, row.finding.event_ids.length - visibleEventIDs.length);
  const lines = [
    "# Aegrail Issue Brief",
    "",
    `Issue: ${row.finding.title}`,
    `Severity: ${row.finding.severity}`,
    `Status: ${issueStatusLabel(row.finding.status, row.finding.status_reason)}`,
    `Company: ${row.instance.companyName}`,
    `Site: ${row.instance.projectName}`,
    `Node: ${nodeLabel(row.instance)}`,
    `Service: ${row.service}`,
    ...(account ? [`Account: ${account}`] : []),
    `First seen: ${formatDate(row.finding.first_event_at)}`,
    `Last seen: ${formatDate(row.finding.last_event_at)}`,
    "",
    "## Summary",
    row.finding.summary || row.finding.description || rule?.title || "No summary was returned.",
    "",
    "## Recommended Action",
    recommendedAction(row, rule),
    "",
    ...(changedFiles.length ? [
      "## Changed Files",
      ...changedFiles.map((file) => `- ${file}`),
      ...(omittedFiles > 0 ? [`- + ${omittedFiles} more file(s) in this group`] : []),
      ""
    ] : []),
    "## Evidence",
    ...(visibleEventIDs.length ? visibleEventIDs.map((id) => `- ${id}`) : ["- No linked signal IDs."]),
    ...(omittedEventIDs > 0 ? [`- + ${omittedEventIDs} more linked signal(s)`] : [])
  ];
  downloadText(`aegrail-issue-${safeFileName(row.finding.title)}.md`, lines.join("\n"));
}

export function exportDashboardBrief(instances: InstanceModel[], issueRows: IssueRow[]) {
  const openRows = issueRows.filter((row) => row.finding.status === "open");
  const lines = [
    "# Aegrail Dashboard Brief",
    "",
    `Generated: ${formatDate(new Date().toISOString())}`,
    `Companies: ${new Set(instances.map((instance) => instance.companySlug)).size}`,
    `Sites: ${new Set(instances.map((instance) => `${instance.companySlug}:${instance.projectSlug}`)).size}`,
    `Nodes: ${instances.length}`,
    `Open issues: ${openRows.length}`,
    "",
    "## Issues",
    ...(openRows.length ? openRows.slice(0, 30).map((row) => `- ${row.finding.severity.toUpperCase()} / ${row.instance.companyName} / ${row.instance.projectName} / ${nodeLabel(row.instance)}: ${row.finding.title}`) : ["- No open issues."])
  ];
  downloadText("aegrail-dashboard-brief.md", lines.join("\n"));
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function safeFileName(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "brief";
}
