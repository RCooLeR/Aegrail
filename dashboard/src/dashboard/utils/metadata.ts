export function metadataString(metadata: Record<string, unknown>, key: string) {
  const value = metadata[key];
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

export function firstMetadataString(metadata: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = metadataString(metadata, key);
    if (value) return value;
  }
  return "";
}

export function metadataNumber(metadata: Record<string, unknown>, key: string) {
  const value = metadata[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export function metadataStringList(metadata: Record<string, unknown>, key: string) {
  const value = metadata[key];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

export function fileIgnorePathCandidate(metadata: Record<string, unknown>) {
  const files = metadataStringList(metadata, "files");
  const commonParent = commonFileParent(files);
  if (commonParent) return commonParent;

  const eventPath = firstFileEventTarget(metadata);
  if (eventPath) return parentFilePath(eventPath);

  return metadataString(metadata, "file_group_root");
}

function firstFileEventTarget(metadata: Record<string, unknown>) {
  const events = metadata.events;
  if (!Array.isArray(events)) return "";
  for (const event of events) {
    if (!event || typeof event !== "object") continue;
    const record = event as Record<string, unknown>;
    const type = typeof record.type === "string" ? record.type : "";
    if (!type.startsWith("file.")) continue;
    const target = typeof record.target === "string" ? record.target : "";
    if (target.trim()) return target.trim();
  }
  return "";
}

function commonFileParent(files: string[]) {
  let parts: string[] = [];
  for (const file of files) {
    const parent = parentFilePath(file);
    if (!parent) continue;
    const current = normalizePath(parent).split("/");
    if (!parts.length) {
      parts = current;
      continue;
    }
    const limit = Math.min(parts.length, current.length);
    let index = 0;
    while (index < limit && parts[index] === current[index]) index += 1;
    parts = parts.slice(0, index);
  }
  return parts.join("/");
}

function parentFilePath(value: string) {
  const normalized = normalizePath(value);
  const index = normalized.lastIndexOf("/");
  if (index <= 0) return normalized;
  return normalized.slice(0, index);
}

function normalizePath(value: string) {
  return value
    .trim()
    .replace(/\\/g, "/")
    .replace(/\/+/g, "/")
    .replace(/^\.\//, "")
    .replace(/^\/+|\/+$/g, "")
    .toLowerCase();
}
