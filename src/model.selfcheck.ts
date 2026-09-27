import assert from "node:assert/strict";
import { headline, lastSeenText, meterLevel, rowStatus, toggleLabel, type AppState, type Row } from "./model.ts";

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

console.log("model self-check ok");
