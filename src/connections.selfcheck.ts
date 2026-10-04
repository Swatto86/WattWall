import assert from "node:assert/strict";
import {
  ago,
  canBlock,
  connectionMatches,
  explain,
  filterConnections,
  localLines,
  notes,
  phaseText,
  remoteLines,
  remoteTitle,
  stateLine,
  type Connection,
  type Look,
} from "./connections.ts";

const conn = (over: Partial<Connection>): Connection => ({
  key: "tcp|192.168.1.20:50123|93.184.216.34:443|7",
  path: "C:\\Tools\\curl.exe",
  name: "curl.exe",
  pid: 7,
  protocol: "tcp",
  direction: "outgoing",
  phase: "connected",
  localAddress: "192.168.1.20",
  localPort: 50123,
  remoteAddress: "93.184.216.34",
  remotePort: 443,
  remoteName: "example.net",
  reach: "internet",
  firstSeen: 100,
  closedAt: null,
  ...over,
});
const listener = (over: Partial<Connection>): Connection =>
  conn({
    key: "tcp|0.0.0.0:3389||8",
    path: "C:\\Windows\\System32\\svchost.exe",
    name: "svchost.exe",
    pid: 8,
    direction: "listening",
    phase: "listening",
    localAddress: "0.0.0.0",
    localPort: 3389,
    remoteAddress: null,
    remotePort: null,
    remoteName: null,
    ...over,
  });

// How long ago.
assert.equal(ago(0), "just now");
assert.equal(ago(1), "just now");
assert.equal(ago(-5), "just now");
assert.equal(ago(2), "2 s ago");
assert.equal(ago(59), "59 s ago");
assert.equal(ago(60), "1 min ago");
assert.equal(ago(3599), "59 min ago");
assert.equal(ago(7200), "2 h ago");

// State wording.
assert.equal(phaseText(conn({}), 200), "Connected");
assert.equal(phaseText(conn({ phase: "connecting" }), 200), "Connecting");
assert.equal(phaseText(conn({ phase: "closing" }), 200), "Closing");
assert.equal(phaseText(listener({}), 200), "Waiting");
assert.equal(phaseText(listener({ protocol: "udp" }), 200), "Open");
assert.equal(phaseText(conn({ phase: "closed", closedAt: 190 }), 200), "Closed 10 s ago");
assert.equal(phaseText(conn({ phase: "closed", closedAt: null }), 200), "Closed");
assert.equal(stateLine(conn({}), 200), "TCP · Connected");
assert.equal(stateLine(listener({ protocol: "udp" }), 200), "UDP · Open");

// The far end: the name leads when there is one, else the address.
assert.deepEqual(remoteLines(conn({})), { host: "example.net", detail: "93.184.216.34 · port 443 · internet" });
assert.deepEqual(remoteLines(conn({ remoteName: null })), { host: "93.184.216.34", detail: "port 443 · internet" });
assert.deepEqual(remoteLines(conn({ remoteName: null, remoteAddress: "192.168.1.9", reach: "local-network", remotePort: 445 })), {
  host: "192.168.1.9",
  detail: "port 445 · local network",
});
assert.deepEqual(remoteLines(listener({})), { host: "Waiting for connections", detail: "" });
assert.deepEqual(remoteLines(listener({ protocol: "udp" })), { host: "Open to incoming datagrams", detail: "" });

// The tooltip never presents a name as proof.
assert.match(remoteTitle(conn({})), /^example\.net is the reverse DNS name of 93\.184\.216\.34\..*not proof/);
assert.equal(remoteTitle(conn({ remoteName: null })), "93.184.216.34");
assert.equal(remoteTitle(listener({})), "Waiting for connections");

// This PC's end.
assert.deepEqual(localLines(conn({})), { port: "50123", detail: "192.168.1.20" });
assert.deepEqual(localLines(listener({})), { port: "3389", detail: "every address" });
assert.deepEqual(localLines(listener({ localAddress: "::" })), { port: "3389", detail: "every address" });
assert.deepEqual(localLines(listener({ localAddress: "127.0.0.1" })), { port: "3389", detail: "this PC only" });
assert.deepEqual(localLines(listener({ localAddress: "::1" })), { port: "3389", detail: "this PC only" });
assert.deepEqual(localLines(listener({ localAddress: "192.168.1.20" })), { port: "3389", detail: "192.168.1.20" });

// The tooltip says which way it goes.
assert.equal(explain(conn({})), "curl.exe connected to example.net on port 443.");
assert.equal(
  explain(conn({ direction: "incoming", localPort: 3389, remoteName: null, remoteAddress: "203.0.113.9", remotePort: 51234 })),
  "curl.exe accepted a connection from 203.0.113.9 (port 51234) on its port 3389.",
);
assert.equal(explain(listener({})), "svchost.exe is listening on TCP port 3389 (every address).");

// Which programs can be blocked.
assert.equal(canBlock(conn({})), true);
assert.equal(canBlock(conn({ path: "System" })), false);
assert.equal(canBlock(conn({ path: "system" })), false);
assert.equal(canBlock(conn({ path: "" })), false);

// The search box looks at everything written on the line.
for (const found of ["curl", "EXAMPLE.NET", "93.184", "443", "50123", "tcp", "outgoing", "internet", "7", "tools"]) {
  assert.equal(connectionMatches(conn({}), found), true, found);
}
assert.equal(connectionMatches(conn({}), "notepad"), false);
assert.equal(connectionMatches(conn({}), "incoming"), false);
assert.equal(connectionMatches(listener({}), "incoming"), false);
assert.equal(connectionMatches(listener({}), "3389"), true);
assert.equal(connectionMatches(conn({}), "   "), true);
assert.equal(connectionMatches(listener({}), "null"), false, "an absent name must not match the word null");

// Filters and the counts on the chips.
const out = conn({});
const inc = conn({ key: "i", direction: "incoming", name: "srv.exe", path: "C:\\Tools\\srv.exe", localPort: 3389, remoteAddress: "203.0.113.9", remotePort: 51234, remoteName: null });
const loop = conn({ key: "l", reach: "this-pc", remoteAddress: "127.0.0.1", remotePort: 8080, remoteName: null, name: "dev.exe", path: "C:\\Tools\\dev.exe" });
const wait = listener({});
const all = [out, inc, loop, wait];
const base = { direction: "all" as const, thisPc: false, query: "" };
let shown = filterConnections(all, base);
assert.deepEqual(shown.rows, [out, inc, wait], "this PC's own connections are hidden unless asked for");
assert.deepEqual(shown.counts, { all: 3, incoming: 1, outgoing: 1, listening: 1 });
shown = filterConnections(all, { ...base, thisPc: true });
assert.deepEqual(shown.counts, { all: 4, incoming: 1, outgoing: 2, listening: 1 });
shown = filterConnections(all, { ...base, direction: "outgoing" });
assert.deepEqual(shown.rows, [out]);
assert.deepEqual(shown.counts, { all: 3, incoming: 1, outgoing: 1, listening: 1 }, "counts ignore the direction chosen");
shown = filterConnections(all, { ...base, direction: "incoming", query: "curl" });
assert.deepEqual(shown.rows, []);
assert.deepEqual(shown.counts, { all: 1, incoming: 0, outgoing: 1, listening: 0 }, "counts follow the search");

// Notes under the list.
const look = (over: Partial<Look>): Look => ({ connections: [], truncated: false, names: true, pendingNames: 0, now: 0, ...over });
assert.deepEqual(notes(look({})), []);
assert.deepEqual(notes(look({ pendingNames: 1 })), ["Looking up 1 host name…"]);
assert.deepEqual(notes(look({ pendingNames: 3 })), ["Looking up 3 host names…"]);
assert.deepEqual(notes(look({ names: false, pendingNames: 0 })), ["Host names are off, so only addresses are shown. Turn them on in Settings."]);
assert.equal(notes(look({ truncated: true, connections: [out, inc] }))[0], "Only the first 2 connections are shown.");

console.log("connections self-check ok");
