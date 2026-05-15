import type { HubUser } from "../../types";

export function upsertUser(users: HubUser[], user: HubUser) {
  const next = users.filter((item) => item.id !== user.id);
  next.push(user);
  return next.sort((left, right) => left.email.localeCompare(right.email));
}

export function userInitials(user?: HubUser) {
  const source = user?.display_name || user?.email || "U";
  return source.split(/[\s@._-]+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "U";
}
