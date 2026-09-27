// What the window shows, decided without touching the page: wording for the
// header, each program's status chip and button, and the traffic scale.

export interface Row {
  path: string;
  name: string;
  publisher: string;
  icon: string;
  blocked: boolean;
  enforced: boolean;
  connected: boolean;
  lastSeen: number | null;
  needsConfirmation: boolean;
  cannotBlock: boolean;
  warning: string;
  /** Null while the VirusTotal check is off. */
  virustotal: VtRow | null;
}

/** One program's VirusTotal answer. */
export interface VtRow {
  state: "pending" | "found" | "unknown" | "unreadable";
  malicious: number;
  suspicious: number;
  engines: number;
  names: string[];
  sha256: string;
  checkedAt: number | null;
}

export interface VtSummary {
  enabled: boolean;
  hasKey: boolean;
  perMinute: number;
  perDay: number;
  checked: number;
  total: number;
  status: string;
  tone: Tone;
}

export interface AppState {
  blocked: Row[];
  seen: Row[];
  suspended: boolean;
  hasRules: boolean;
  warnings: string[];
  autostart: boolean;
  autostartAvailable: boolean;
  autostartReason: string;
  elevated: boolean;
  /** Block All: every program is cut off from the network. */
  blockAll: boolean;
  virustotal: VtSummary;
}

/** The `traffic` event, once a second. */
export interface Traffic {
  sending: string;
  receiving: string;
  sendingPerSecond: number;
  receivingPerSecond: number;
}

export type Tone = "ok" | "bad" | "warn" | "muted";

export interface Label {
  tone: Tone;
  text: string;
  title: string;
}

/** One line under the app name saying whether blocks are in force. */
export function headline(state: AppState): Label {
  if (!state.elevated) {
    return { tone: "bad", text: "Not running as administrator", title: "WattWall can list programs but cannot change blocks." };
  }
  if (state.blockAll) {
    return { tone: "bad", text: "All internet access blocked", title: "Block all is on: no program on this PC can use the network." };
  }
  if (state.suspended) {
    return { tone: "warn", text: "All blocks are off", title: "Every WattWall rule is turned off until you turn them back on." };
  }
  const on = state.blocked.filter((row) => row.enforced).length;
  if (on === 0) return { tone: "muted", text: "Nothing blocked yet", title: "" };
  return {
    tone: "ok",
    text: on === 1 ? "Blocking 1 program" : `Blocking ${on} programs`,
    title: "Outbound and inbound rules are on in Windows Firewall.",
  };
}

/** "just now", "5 min ago", "3 h ago", "2 d ago"; empty when never seen. */
export function lastSeenText(lastSeen: number | null, nowSeconds: number): string {
  if (lastSeen == null) return "";
  const minutes = Math.floor(Math.max(0, nowSeconds - lastSeen) / 60);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return `${Math.floor(hours / 24)} d ago`;
}

/** The chip beside a program. */
export function rowStatus(row: Row, nowSeconds: number): Label {
  if (row.cannotBlock) return { tone: "muted", text: "Cannot block", title: row.warning };
  if (row.blocked && !row.enforced) {
    return { tone: "warn", text: "Paused", title: "All blocks are off. This block comes back when they are turned on." };
  }
  if (row.blocked) return { tone: "bad", text: "Blocked", title: "Outbound and inbound traffic are blocked in Windows Firewall." };
  if (row.connected) return { tone: "ok", text: "Connected", title: "Has a connection or an open port now." };
  const seen = lastSeenText(row.lastSeen, nowSeconds);
  return { tone: "muted", text: seen, title: seen ? `Last used the network ${seen}` : "" };
}

export function toggleLabel(row: Row, busy: boolean): string {
  if (row.cannotBlock) return "Can't block";
  if (busy) return row.blocked ? "Allowing…" : "Blocking…";
  return row.blocked ? "Allow" : "Block";
}

/**
 * Height of the traffic graph from 0 to 1. Logarithmic from 1 KB/s to
 * 10 MB/s, the same scale as the tray bars, so light traffic still shows.
 */
export function meterLevel(bytesPerSecond: number): number {
  if (!(bytesPerSecond >= 512)) return 0;
  const low = Math.log10(1024);
  const high = Math.log10(10 * 1024 * 1024);
  return Math.min(1, Math.max(0.04, (Math.log10(bytesPerSecond) - low) / (high - low)));
}

/** The VirusTotal chip on a row; null while the check is off. */
export function vtLabel(vt: VtRow | null): Label | null {
  if (!vt) return null;
  switch (vt.state) {
    case "pending":
      return { tone: "muted", text: "Waiting", title: "Waiting for its VirusTotal lookup." };
    case "unknown":
      return { tone: "muted", text: "Unknown", title: "VirusTotal has no record of this file." };
    case "unreadable":
      return { tone: "muted", text: "n/a", title: "WattWall could not read this file to hash it." };
    case "found": {
      const tone: Tone = vt.malicious >= 3 ? "bad" : vt.malicious > 0 || vt.suspicious > 0 ? "warn" : "ok";
      return { tone, text: `${vt.malicious}/${vt.engines}`, title: vtVerdict(vt) };
    }
  }
}

/** One sentence about a VirusTotal answer. */
export function vtVerdict(vt: VtRow): string {
  if (vt.state === "unknown") return "VirusTotal has no record of this file.";
  const engines = `${vt.engines} security engine${vt.engines === 1 ? "" : "s"}`;
  if (vt.malicious === 0 && vt.suspicious === 0) return `None of ${engines} flag this file.`;
  const parts = [];
  if (vt.malicious > 0) parts.push(`${vt.malicious} of ${engines} flag this file as malicious`);
  if (vt.suspicious > 0) parts.push(`${vt.suspicious} as suspicious`);
  return `${parts.join(" and ")}.`;
}

/** The report page for a hash, or null if it is not a SHA-256. */
export function vtLink(sha256: string): string | null {
  return /^[0-9a-f]{64}$/.test(sha256) ? `https://www.virustotal.com/gui/file/${sha256}` : null;
}

/** Limits typed into the setup dialog, or a reason they are not usable. */
export function vtLimits(perMinute: string, perDay: string): { perMinute: number; perDay: number } | string {
  const minute = Number(perMinute);
  const day = Number(perDay);
  if (!Number.isInteger(minute) || !Number.isInteger(day)) return "Enter whole numbers for the limits.";
  if (minute < 1 || day < 1) return "Both limits must be at least 1.";
  return { perMinute: minute, perDay: day };
}
