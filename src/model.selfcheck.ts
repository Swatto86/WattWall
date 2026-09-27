import assert from "node:assert/strict";
import {
  headline,
  lastSeenText,
  meterLevel,
  rowStatus,
  toggleLabel,
  vtLabel,
  vtLimits,
  vtLink,
  vtVerdict,
  type AppState,
  type Row,
  type VtRow,
} from "./model.ts";

const row = (over: Partial<Row>): Row => ({
  path: "C:\\Windows\\System32\\curl.exe",
  name: "curl.exe",
  publisher: "",
  icon: "",
  blocked: false,
  enforced: false,
  connected: false,
  lastSeen: null,
  needsConfirmation: false,
  cannotBlock: false,
  warning: "",
  virustotal: null,
  ...over,
});
const vt = (over: Partial<VtRow>): VtRow => ({
  state: "found",
  malicious: 0,
  suspicious: 0,
  engines: 70,
  names: [],
  sha256: "ab".repeat(32),
  checkedAt: 0,
  ...over,
});
const state = (over: Partial<AppState>): AppState => ({
  blocked: [],
  seen: [],
  suspended: false,
  hasRules: false,
  warnings: [],
  autostart: false,
  autostartAvailable: false,
  autostartReason: "",
  elevated: true,
  virustotal: { enabled: false, hasKey: false, perMinute: 4, perDay: 500, checked: 0, total: 0, status: "", tone: "muted" },
  ...over,
});

assert.equal(lastSeenText(null, 1000), "");
assert.equal(lastSeenText(990, 1000), "just now");
assert.equal(lastSeenText(1000 - 5 * 60, 1000), "5 min ago");
assert.equal(lastSeenText(1000 - 3 * 3600, 1000), "3 h ago");
assert.equal(lastSeenText(1000 - 2 * 86400, 1000), "2 d ago");
assert.equal(lastSeenText(2000, 1000), "just now", "a clock that moved back is not the future");

assert.equal(rowStatus(row({ blocked: true, enforced: true }), 0).text, "Blocked");
assert.equal(rowStatus(row({ blocked: true, enforced: false }), 0).text, "Paused");
assert.equal(rowStatus(row({ connected: true }), 0).text, "Connected");
assert.equal(rowStatus(row({ lastSeen: 0 }), 600).text, "10 min ago");
assert.equal(rowStatus(row({ cannotBlock: true, warning: "System has no file" }), 0).title, "System has no file");

assert.equal(toggleLabel(row({}), false), "Block");
assert.equal(toggleLabel(row({ blocked: true }), false), "Allow");
assert.equal(toggleLabel(row({}), true), "Blocking…");
assert.equal(toggleLabel(row({ cannotBlock: true }), true), "Can't block");

assert.equal(headline(state({ elevated: false, suspended: true })).tone, "bad");
assert.equal(headline(state({ suspended: true })).text, "All blocks are off");
assert.equal(headline(state({})).text, "Nothing blocked yet");
const on = row({ blocked: true, enforced: true });
assert.equal(headline(state({ blocked: [on] })).text, "Blocking 1 program");
assert.equal(headline(state({ blocked: [on, on, row({ blocked: true })] })).text, "Blocking 2 programs");

assert.equal(meterLevel(0), 0);
assert.equal(meterLevel(Number.NaN), 0);
assert.equal(meterLevel(100), 0);
assert.ok(meterLevel(600) > 0, "light traffic still shows");
assert.equal(meterLevel(10 * 1024 * 1024), 1);
assert.equal(meterLevel(1e12), 1);
assert.ok(meterLevel(1e5) < meterLevel(1e6), "more traffic draws higher");

assert.equal(vtLabel(null), null, "no chip while the check is off");
assert.equal(vtLabel(vt({}))?.text, "VT 0/70");
assert.equal(vtLabel(vt({}))?.tone, "ok");
assert.equal(vtLabel(vt({ malicious: 1 }))?.tone, "warn", "one engine is often a false alarm");
assert.equal(vtLabel(vt({ suspicious: 2 }))?.tone, "warn");
assert.equal(vtLabel(vt({ malicious: 3 }))?.tone, "bad");
assert.equal(vtLabel(vt({ state: "pending" }))?.tone, "muted");
assert.equal(vtLabel(vt({ state: "unknown" }))?.text, "VT unknown");
assert.equal(vtVerdict(vt({})), "None of 70 security engines flag this file.");
assert.equal(vtVerdict(vt({ malicious: 3, suspicious: 1 })), "3 of 70 security engines flag this file as malicious and 1 as suspicious.");
assert.equal(vtLink("ab".repeat(32)), `https://www.virustotal.com/gui/file/${"ab".repeat(32)}`);
assert.equal(vtLink("javascript:alert(1)"), null, "only a real hash becomes a link");
assert.equal(vtLink("AB".repeat(32)), null);
assert.deepEqual(vtLimits("4", "500"), { perMinute: 4, perDay: 500 });
assert.equal(typeof vtLimits("4.5", "500"), "string");
assert.equal(typeof vtLimits("", "500"), "string");
assert.equal(typeof vtLimits("0", "500"), "string");

console.log("model self-check ok");
