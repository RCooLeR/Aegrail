export type AnalysisSection = {
  title: string;
  lines: AnalysisLine[];
};

export type AnalysisLine =
  | { kind: "text"; content: string }
  | { kind: "list"; content: string }
  | { kind: "kv"; key: string; value: string };

const headerRegex = /^##\s*(.+?)\s*$/;
const bulletRegex = /^([\-*]|(\d+\.)\s)\s+/;
const keyValueRegex = /^\s*-\s*([^:]+):\s*(.+)$/;

export function parseModelAnalysisSections(value: string): AnalysisSection[] {
  const text = (value || "").trim();
  if (!text) {
    return [{ title: "No analysis", lines: [{ kind: "text", content: "No analysis text was returned." }] }];
  }

  const lines = text.split(/\r?\n/).map((line) => line.trimEnd());
  const sections: AnalysisSection[] = [];
  let current: AnalysisSection = { title: "Summary", lines: [] };

  for (const line of lines) {
    const headerMatch = line.match(headerRegex);
    if (headerMatch) {
      if (current.lines.length > 0 || sections.length > 0) {
        sections.push(current);
      }
      current = { title: headerMatch[1], lines: [] };
      continue;
    }
    if (line.trim() === "") {
      continue;
    }

    const keyValueMatch = line.match(keyValueRegex);
    if (keyValueMatch) {
      current.lines.push({
        kind: "kv",
        key: keyValueMatch[1].trim(),
        value: keyValueMatch[2].trim()
      });
      continue;
    }

    if (isBulletLine(line)) {
      const content = line.replace(/^([\-*]|\d+\.\s)\s+/, "");
      current.lines.push({ kind: "list", content });
      continue;
    }
    current.lines.push({ kind: "text", content: line });
  }

  if (current.lines.length > 0 || sections.length === 0) {
    sections.push(current);
  }
  return sections;
}

export function isBulletLine(line: string): boolean {
  return bulletRegex.test(line);
}

export function splitCodeTokens(content: string): string[] {
  const parts = content.split(/(`[^`]+`)/g);
  return parts;
}

export function isModelAnalysisHTML(content: string): boolean {
  return /^\s*<div\s+class=["']model-analysis-report["']/.test(content || "");
}
