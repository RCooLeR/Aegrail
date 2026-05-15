export function newest(values: Array<string | undefined>) {
  const latest = values.reduce((max, value) => Math.max(max, value ? new Date(value).getTime() : 0), 0);
  return latest > 0 ? new Date(latest).toISOString() : undefined;
}

export function formatDate(value?: string) {
  if (!value) return "unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { day: "numeric", hour: "2-digit", hourCycle: "h23", minute: "2-digit", month: "short" }).format(date);
}

export function formatRelative(value?: string) {
  if (!value) return "unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [unit, amount] of units) {
    if (abs >= amount) return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(Math.round(seconds / amount), unit);
  }
  return "just now";
}

export function titleCase(value: string) {
  return value.split(" ").filter(Boolean).map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`).join(" ");
}
