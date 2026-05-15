import type { ActionState } from "../types";

export function loadActionDefaults(): ActionState {
  const fallback = { actor: "dashboard", reason: "reviewed", note: "" };
  const raw = localStorage.getItem("aegrail.dashboard.triage");
  if (!raw) return fallback;
  try {
    return { ...fallback, ...JSON.parse(raw) };
  } catch {
    return fallback;
  }
}

export function saveActionDefaults(actionState: ActionState) {
  localStorage.setItem("aegrail.dashboard.triage", JSON.stringify(actionState));
}
