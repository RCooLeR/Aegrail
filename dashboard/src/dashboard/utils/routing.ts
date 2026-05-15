import { basePath, viewKeys } from "../config/navigation";
import type { ViewKey } from "../types";

export function viewFromLocation(): ViewKey {
  const relativePath = window.location.pathname.startsWith(basePath) ? window.location.pathname.slice(basePath.length) : "";
  const pathView = relativePath.split("/").filter(Boolean)[0];
  const hashView = window.location.hash.replace("#", "");
  const candidate = pathView || hashView || "overview";
  return viewKeys.has(candidate as ViewKey) ? candidate as ViewKey : "overview";
}

export function issueIDFromLocation() {
  const relativePath = window.location.pathname.startsWith(basePath) ? window.location.pathname.slice(basePath.length) : "";
  const [pathView, issueID] = relativePath.split("/").filter(Boolean);
  if (pathView !== "issue" || !issueID) {
    return "";
  }
  try {
    return decodeURIComponent(issueID);
  } catch {
    return issueID;
  }
}
