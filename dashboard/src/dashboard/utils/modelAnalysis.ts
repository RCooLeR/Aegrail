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

const allowedAnalysisTags = new Set([
  "A",
  "BR",
  "CODE",
  "DIV",
  "EM",
  "H4",
  "H5",
  "LI",
  "OL",
  "P",
  "PRE",
  "SECTION",
  "SPAN",
  "STRONG",
  "TABLE",
  "TBODY",
  "TD",
  "TH",
  "THEAD",
  "TR",
  "UL"
]);

export function sanitizeModelAnalysisHTML(content: string): string {
  if (typeof document === "undefined") {
    return "";
  }
  const template = document.createElement("template");
  template.innerHTML = content || "";
  sanitizeNode(template.content);
  return template.innerHTML;
}

function sanitizeNode(parent: ParentNode) {
  for (const node of Array.from(parent.childNodes)) {
    if (node.nodeType === Node.COMMENT_NODE) {
      node.remove();
      continue;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) {
      continue;
    }
    const element = node as HTMLElement;
    if (["IFRAME", "OBJECT", "SCRIPT", "STYLE"].includes(element.tagName)) {
      element.remove();
      continue;
    }
    if (!allowedAnalysisTags.has(element.tagName)) {
      const fragment = document.createDocumentFragment();
      while (element.firstChild) {
        fragment.appendChild(element.firstChild);
      }
      element.replaceWith(fragment);
      sanitizeNode(parent);
      continue;
    }
    sanitizeElementAttributes(element);
    sanitizeNode(element);
  }
}

function sanitizeElementAttributes(element: HTMLElement) {
  for (const attribute of Array.from(element.attributes)) {
    const name = attribute.name.toLowerCase();
    const value = attribute.value;
    if (name.startsWith("on") || name === "style") {
      element.removeAttribute(attribute.name);
      continue;
    }
    if (name === "class") {
      if (!/^[a-z0-9 _-]+$/i.test(value)) {
        element.removeAttribute(attribute.name);
      }
      continue;
    }
    if (element.tagName === "A" && name === "href") {
      if (!isSafeAnalysisURL(value)) {
        element.removeAttribute(attribute.name);
      }
      continue;
    }
    if (element.tagName === "A" && (name === "target" || name === "rel")) {
      continue;
    }
    element.removeAttribute(attribute.name);
  }
  if (element.tagName === "A") {
    element.setAttribute("rel", "noreferrer");
  }
}

function isSafeAnalysisURL(value: string): boolean {
  try {
    const url = new URL(value, window.location.origin);
    return ["http:", "https:", "mailto:"].includes(url.protocol);
  } catch {
    return false;
  }
}
