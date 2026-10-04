// What the Connections view shows, decided without touching the page: the
// shape of one look at the network, the wording of each column, and the
// filters. `monitor.ts` draws it.

export type Direction = "incoming" | "outgoing" | "listening";
export type Phase = "listening" | "connecting" | "connected" | "closing" | "closed";
export type Reach = "this-pc" | "local-network" | "internet";

/** One connection, or one port waiting for connections. */
export interface Connection {
  /** The same from one look to the next, so a line is updated in place. */
  key: string;
  /** The program's full path; "System" for process 4; empty when Windows would not say. */
  path: string;
  name: string;
  pid: number;
  protocol: "tcp" | "udp";
  direction: Direction;
  phase: Phase;
  localAddress: string;
  localPort: number;
  /** Null for a port that is waiting: Windows does not record who a UDP socket talks to. */
  remoteAddress: string | null;
  remotePort: number | null;
  /** The host name DNS gave for the far address, once it has. */
  remoteName: string | null;
  reach: Reach;
  firstSeen: number;
  closedAt: number | null;
}

/** The `monitor_snapshot` answer. `now` is the PC's clock, in seconds. */
export interface Look {
  connections: Connection[];
  truncated: boolean;
  names: boolean;
  pendingNames: number;
  now: number;
}

export type DirectionFilter = "all" | Direction;

export interface Filters {
  direction: DirectionFilter;
  /** Show connections between programs on this PC (loopback). */
  thisPc: boolean;
  query: string;
}

export const DIRECTION_FILTERS: { id: DirectionFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "incoming", label: "Incoming" },
  { id: "outgoing", label: "Outgoing" },
  { id: "listening", label: "Listening" },
];

export function directionText(direction: Direction): string {
  return direction === "incoming" ? "Incoming" : direction === "outgoing" ? "Outgoing" : "Listening";
}

export function reachText(reach: Reach): string {
  return reach === "this-pc" ? "this PC" : reach === "local-network" ? "local network" : "internet";
}

/** "just now", "12 s ago", "3 min ago", "2 h ago". */
export function ago(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 2) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  return `${Math.floor(s / 3600)} h ago`;
}

export function phaseText(connection: Connection, now: number): string {
  switch (connection.phase) {
    case "listening":
      return connection.protocol === "tcp" ? "Waiting" : "Open";
    case "connecting":
      return "Connecting";
    case "connected":
      return "Connected";
    case "closing":
      return "Closing";
    case "closed":
      return connection.closedAt === null ? "Closed" : `Closed ${ago(now - connection.closedAt)}`;
  }
}

/** "TCP · Connected": what the second line of the direction column says. */
export function stateLine(connection: Connection, now: number): string {
  return `${connection.protocol.toUpperCase()} · ${phaseText(connection, now)}`;
}

/** The far end: its name, or its address when there is no name, and the rest on a second line. */
export function remoteLines(connection: Connection): { host: string; detail: string } {
  if (connection.remoteAddress === null) {
    return { host: connection.protocol === "tcp" ? "Waiting for connections" : "Open to incoming datagrams", detail: "" };
  }
  const detail = [
    ...(connection.remoteName ? [connection.remoteAddress] : []),
    `port ${connection.remotePort}`,
    reachText(connection.reach),
  ];
  return { host: connection.remoteName ?? connection.remoteAddress, detail: detail.join(" · ") };
}

/**
 * The tooltip of the far end. A host name is only what the owner of the
 * address says it is called, so it is never offered as proof of who is there.
 */
export function remoteTitle(connection: Connection): string {
  if (connection.remoteAddress === null) return remoteLines(connection).host;
  if (!connection.remoteName) return connection.remoteAddress;
  return `${connection.remoteName} is the reverse DNS name of ${connection.remoteAddress}. Whoever owns an address chooses its name, so it is not proof of who is there.`;
}

const isAnyAddress = (address: string): boolean => address === "0.0.0.0" || address === "::";
const isLoopback = (address: string): boolean => address.startsWith("127.") || address === "::1";

/** This PC's end: the port, and which address it is on or who can reach it. */
export function localLines(connection: Connection): { port: string; detail: string } {
  let detail = connection.localAddress;
  if (connection.direction === "listening") {
    if (isAnyAddress(connection.localAddress)) detail = "every address";
    else if (isLoopback(connection.localAddress)) detail = "this PC only";
  }
  return { port: String(connection.localPort), detail };
}

/** One sentence saying what the line is, for its tooltip. */
export function explain(connection: Connection): string {
  const remote = connection.remoteName ?? connection.remoteAddress;
  const port = connection.localPort;
  switch (connection.direction) {
    case "incoming":
      return `${connection.name} accepted a connection from ${remote} (port ${connection.remotePort}) on its port ${port}.`;
    case "outgoing":
      return `${connection.name} connected to ${remote} on port ${connection.remotePort}.`;
    case "listening": {
      const where = localLines(connection).detail;
      return `${connection.name} is listening on ${connection.protocol.toUpperCase()} port ${port} (${where}).`;
    }
  }
}

/** A program WattWall can put a block on: it has a file, and is not System. */
export function canBlock(connection: Connection): boolean {
  return connection.path !== "" && connection.path.toLowerCase() !== "system";
}

/** Whether a search box should keep this line: any of what is written on it. */
export function connectionMatches(connection: Connection, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const text = [
    connection.name,
    connection.path,
    connection.remoteName,
    connection.remoteAddress,
    connection.remotePort,
    connection.localAddress,
    connection.localPort,
    connection.protocol,
    directionText(connection.direction),
    connection.phase,
    reachText(connection.reach),
    connection.pid,
  ];
  return text.some((part) => part !== null && String(part).toLowerCase().includes(needle));
}

/**
 * The lines to show, and how many each direction chip counts. The counts
 * ignore the direction chosen, so each chip says what choosing it would show.
 */
export function filterConnections(
  all: Connection[],
  filters: Filters,
): { rows: Connection[]; counts: Record<DirectionFilter, number> } {
  const base = all.filter(
    (connection) => (filters.thisPc || connection.reach !== "this-pc") && connectionMatches(connection, filters.query),
  );
  const count = (direction: Direction): number => base.filter((connection) => connection.direction === direction).length;
  return {
    rows: filters.direction === "all" ? base : base.filter((connection) => connection.direction === filters.direction),
    counts: { all: base.length, incoming: count("incoming"), outgoing: count("outgoing"), listening: count("listening") },
  };
}

/** Lines under the list about what is not shown or not finished. */
export function notes(look: Look): string[] {
  const lines: string[] = [];
  if (look.truncated) lines.push(`Only the first ${look.connections.length} connections are shown.`);
  if (!look.names) lines.push("Host names are off, so only addresses are shown. Turn them on in Settings.");
  else if (look.pendingNames > 0) {
    lines.push(`Looking up ${look.pendingNames} host name${look.pendingNames === 1 ? "" : "s"}…`);
  }
  return lines;
}
