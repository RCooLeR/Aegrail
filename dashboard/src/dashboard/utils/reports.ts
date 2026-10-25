import type { ModelAnalysisReport, RuleDefinition } from "../../types";
import { issueStatusLabel, nodeLabel, recommendedAction } from "../model/viewModels";
import type { IssueRow } from "../types";
import { firstMetadataString, metadataNumber, metadataStringList, operatorActionGuidance } from "./metadata";
import { formatDate } from "./time";

export function buildIssueBrief(row: IssueRow, rule?: RuleDefinition, report?: ModelAnalysisReport) {
  const account = firstMetadataString(row.finding.metadata, ["email", "account_display", "login", "email_masked", "login_masked"]);
  const changedFiles = metadataStringList(row.finding.metadata, "files");
  const omittedFiles = metadataNumber(row.finding.metadata, "omitted_file_count");
  const guidance = operatorActionGuidance(row.finding);
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
    ...(guidance.safeToAcknowledgeWhen ? ["", `Safe to acknowledge when: ${guidance.safeToAcknowledgeWhen}`] : []),
    ...(guidance.escalateWhen ? [`Escalate when: ${guidance.escalateWhen}`] : []),
    ...(guidance.actions.length ? ["", "## Operator Checklist", ...guidance.actions.map((action) => `- ${action}`)] : []),
    "",
    ...(changedFiles.length ? [
      "## Changed Files",
      ...changedFiles.map((file) => `- ${file}`),
      ...(omittedFiles > 0 ? [`- + ${omittedFiles} more file(s) in this group`] : []),
      ""
    ] : []),
    "## Evidence",
    ...(visibleEventIDs.length ? visibleEventIDs.map((id) => `- ${id}`) : ["- No linked signal IDs."]),
    ...(omittedEventIDs > 0 ? [`- + ${omittedEventIDs} more linked signal(s)`] : []),
    ...(report?.analysis ? ["", "## Latest LLM Analysis", report.analysis] : [])
  ];
  return lines.join("\n");
}

export function exportIssueBrief(row: IssueRow, rule?: RuleDefinition, report?: ModelAnalysisReport) {
  downloadText(`aegrail-issue-${safeFileName(row.finding.title)}.md`, buildIssueBrief(row, rule, report));
}

export async function copyIssueBrief(row: IssueRow, rule?: RuleDefinition, report?: ModelAnalysisReport) {
  if (!navigator.clipboard?.writeText) {
    throw new Error("Clipboard is unavailable in this browser context.");
  }
  await navigator.clipboard.writeText(buildIssueBrief(row, rule, report));
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
