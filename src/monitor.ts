// The Connections view: the tab strip, the filter chips, and the list of
// connections, looked at again every two seconds while the view is open.
// Everything written on a line came from outside the program (a program's
// name, a host name from DNS), so it goes into the page as text only.
import { invoke } from "@tauri-apps/api/core";
import {
  DIRECTION_FILTERS,
  canBlock,
  directionText,
  explain,
  filterConnections,
  localLines,
  notes,
  remoteLines,
  remoteTitle,
  stateLine,
  type Connection,
  type Direction,
  type DirectionFilter,
  type Filters,
  type Look,
} from "./connections";
import { icon } from "./icons";
import type { AppState, Row } from "./model";
import { pathKey } from "./view";

export interface MonitorContext {
  $: <T extends HTMLElement>(selector: string) => T;
  state(): AppState | null;
  update(next: AppState): void;
  say(message: string): void;
  /** Paths being blocked or allowed right now, lower-cased. */
  busy(): ReadonlySet<string>;
  toggle(path: string, blocked: boolean): void;
}

export interface MonitorView {
  paint(): void;
}

type View = "programs" | "connections";

const LOOK_EVERY_MS = 2000;
const DIRECTION_ICON: Record<Direction, string> = { incoming: icon.down, outgoing: icon.up, listening: icon.radio };

function element<K extends keyof HTMLElementTagNameMap>(tag: K, className: string): HTMLElementTagNameMap[K] {
  const made = document.createElement(tag);
  made.className = className;
  return made;
}

function setText(target: HTMLElement, text: string): void {
  if (target.textContent !== text) target.textContent = text;
}

interface Line {
  root: HTMLElement;
  picture: HTMLElement;
  name: HTMLElement;
  where: HTMLElement;
  direction: HTMLElement;
  directionText: HTMLElement;
  stateLine: HTMLElement;
  host: HTMLElement;
  remoteDetail: HTMLElement;
  port: HTMLElement;
  localDetail: HTMLElement;
  button: HTMLButtonElement;
  connection: Connection;
  iconSource: string;
}

function createLine(onToggle: (connection: Connection) => void): Line {
  const root = element("article", "row conn");
  const picture = element("div", "picture");
  const info = element("div", "info");
  const name = element("span", "name");
  const nameLine = element("div", "line");
  nameLine.append(name);
  const where = element("div", "path");
  info.append(nameLine, where);

  const direction = element("span", "dir");
  const directionIcon = element("span", "dir-icon");
  const directionText = element("span", "dir-text");
  direction.append(directionIcon, directionText);
  const stateLine = element("div", "sub");
  const directionCell = element("div", "cell-dir");
  directionCell.append(direction, stateLine);

  const host = element("div", "host");
  const remoteDetail = element("div", "sub");
  const remoteCell = element("div", "cell-remote");
  remoteCell.append(host, remoteDetail);

  const port = element("div", "port");
  const localDetail = element("div", "sub");
  const localCell = element("div", "cell-local");
  localCell.append(port, localDetail);

  const button = element("button", "toggle conn-toggle");
  button.type = "button";
  root.append(picture, info, directionCell, remoteCell, localCell, button);
  const line: Line = {
    root,
    picture,
    name,
    where,
    direction,
    directionText,
    stateLine,
    host,
    remoteDetail,
    port,
    localDetail,
    button,
    connection: {} as Connection,
    iconSource: "\u0000",
  };
  button.addEventListener("click", () => onToggle(line.connection));
  return line;
}

export function setUpMonitor(ctx: MonitorContext): MonitorView {
  const { $ } = ctx;
  const search = $<HTMLInputElement>("#search");
  const tabs: Record<View, HTMLButtonElement> = { programs: $("#tab-programs"), connections: $("#tab-connections") };
  const panels: Record<View, HTMLElement> = { programs: $("#panel-programs"), connections: $("#panel-connections") };
  const host = $<HTMLDivElement>("#connections");
  const noteBox = $<HTMLDivElement>("#monitor-note");
  const thisPc = $<HTMLInputElement>("#include-this-pc");
  const resolveNames = $<HTMLInputElement>("#resolve-names");
  const chips = $<HTMLDivElement>("#direction-filter");

  const filters: Filters = { direction: "all", thisPc: false, query: "" };
  const lines = new Map<string, Line>();
  const empty = element("div", "empty");
  empty.innerHTML = `${icon.network}<p class="empty-title"></p><p class="empty-hint"></p>`;
  let view: View = "programs";
  let look: Look | null = null;
  let failure = "";
  let inFlight = false;
  let timer: number | undefined;

  const chipCounts = new Map<DirectionFilter, HTMLElement>();
  const chipButtons = new Map<DirectionFilter, HTMLButtonElement>();
  for (const { id, label } of DIRECTION_FILTERS) {
    const chip = element("button", "seg-btn");
    chip.type = "button";
    chip.dataset.filter = id;
    const count = element("span", "count");
    chip.append(document.createTextNode(label), count);
    chip.addEventListener("click", () => {
      filters.direction = id;
      paint();
    });
    chips.append(chip);
    chipButtons.set(id, chip);
    chipCounts.set(id, count);
  }

  function onToggle(connection: Connection): void {
    if (!canBlock(connection)) return;
    const program = programs().get(pathKey(connection.path));
    ctx.toggle(connection.path, !(program?.blocked ?? false));
  }

  /** Every program the window knows, by path, for its icon and whether it is blocked. */
  function programs(): Map<string, Row> {
    const state = ctx.state();
    const known = new Map<string, Row>();
    for (const row of [...(state?.seen ?? []), ...(state?.blocked ?? [])]) known.set(pathKey(row.path), row);
    return known;
  }

  function show(next: View, focus: boolean): void {
    const left = view === "connections" && next !== "connections";
    view = next;
    for (const id of ["programs", "connections"] as const) {
      const selected = id === next;
      tabs[id].setAttribute("aria-selected", String(selected));
      tabs[id].tabIndex = selected ? 0 : -1;
      panels[id].classList.toggle("hidden", !selected);
    }
    const what = next === "programs" ? "Search programs" : "Search connections";
    search.placeholder = what;
    search.setAttribute("aria-label", what);
    if (focus) tabs[next].focus();
    if (next === "connections") void refresh();
    else window.clearTimeout(timer);
    // Leaving the view stops what is read and asked on its behalf, at once.
    if (left) closeOnRust();
    paint();
  }

  function closeOnRust(): void {
    invoke("monitor_close").catch((error) => console.error(`monitor_close failed: ${error}`));
  }

  async function refresh(): Promise<void> {
    window.clearTimeout(timer);
    if (view !== "connections" || inFlight) return;
    inFlight = true;
    try {
      // Null: the window is hidden in the tray, so nothing was read.
      const next = await invoke<Look | null>("monitor_snapshot");
      if (next) look = next;
      failure = "";
    } catch (error) {
      failure = String(error);
    } finally {
      inFlight = false;
    }
    if (view !== "connections") {
      // The view was left while this look ran, and the look may have queued lookups after the
      // close that came with leaving: close again, now that it is over.
      closeOnRust();
      return;
    }
    paint();
    if (view === "connections" && !document.hidden) timer = window.setTimeout(() => void refresh(), LOOK_EVERY_MS);
  }

  function paint(): void {
    resolveNames.checked = ctx.state()?.resolveNames ?? true;
    if (view !== "connections") return;
    filters.query = search.value;
    filters.thisPc = thisPc.checked;
    const now = look?.now ?? Date.now() / 1000;
    const shown = filterConnections(look?.connections ?? [], filters);
    for (const [id, count] of chipCounts) setText(count, String(shown.counts[id]));
    for (const [id, chip] of chipButtons) chip.setAttribute("aria-pressed", String(id === filters.direction));
    draw(shown.rows, now);
    noteBox.replaceChildren(
      ...[...(failure ? [failure] : []), ...(look ? notes(look) : [])].map((text) => {
        const paragraph = element("p", failure && text === failure ? "form-error" : "hint");
        paragraph.textContent = text;
        return paragraph;
      }),
    );
  }

  function draw(rows: Connection[], now: number): void {
    const wanted = new Set(rows.map((connection) => connection.key));
    for (const [key, line] of lines) {
      if (!wanted.has(key)) {
        line.root.remove();
        lines.delete(key);
      }
    }
    if (rows.length === 0) {
      const reading = look === null && failure === "";
      setText(empty.querySelector<HTMLElement>(".empty-title")!, reading ? "Reading connections…" : "No connections to show");
      setText(
        empty.querySelector<HTMLElement>(".empty-hint")!,
        reading
          ? ""
          : look && look.connections.length > 0
            ? "Nothing matches the search and filters above."
            : "Nothing is connected or listening right now.",
      );
      if (empty.parentElement !== host) host.append(empty);
      return;
    }
    empty.remove();
    const known = programs();
    const busy = ctx.busy();
    let cursor = host.firstElementChild;
    for (const connection of rows) {
      const line = lines.get(connection.key) ?? addLine(connection.key);
      update(line, connection, known.get(pathKey(connection.path)), busy.has(pathKey(connection.path)), now);
      if (line.root === cursor) cursor = cursor.nextElementSibling;
      else host.insertBefore(line.root, cursor);
    }
  }

  function addLine(key: string): Line {
    const line = createLine(onToggle);
    lines.set(key, line);
    return line;
  }

  function update(line: Line, connection: Connection, program: Row | undefined, busy: boolean, now: number): void {
    line.connection = connection;
    const root = line.root;
    root.dataset.direction = connection.direction;
    root.dataset.phase = connection.phase;
    root.dataset.reach = connection.reach;
    root.title = explain(connection);

    const source = program?.icon ?? "";
    if (line.iconSource !== source) {
      line.iconSource = source;
      if (source) {
        const image = document.createElement("img");
        image.alt = "";
        image.src = source;
        line.picture.replaceChildren(image);
        line.picture.classList.remove("mark");
      } else {
        line.picture.replaceChildren(document.createTextNode(connection.name.slice(0, 1).toUpperCase()));
        line.picture.classList.add("mark");
      }
    }
    setText(line.name, connection.name);
    const where = connection.path ? `pid ${connection.pid} · ${connection.path}` : `pid ${connection.pid}`;
    setText(line.where, where);
    line.where.title = where;

    line.direction.dataset.direction = connection.direction;
    if (line.direction.dataset.drawn !== connection.direction) {
      line.direction.dataset.drawn = connection.direction;
      line.direction.firstElementChild!.innerHTML = DIRECTION_ICON[connection.direction];
    }
    setText(line.directionText, directionText(connection.direction));
    setText(line.stateLine, stateLine(connection, now));

    const remote = remoteLines(connection);
    setText(line.host, remote.host);
    line.host.title = remoteTitle(connection);
    setText(line.remoteDetail, remote.detail);
    line.remoteDetail.title = remote.detail;
    const local = localLines(connection);
    setText(line.port, local.port);
    setText(line.localDetail, local.detail);
    line.localDetail.title = local.detail;

    const blocked = program?.blocked ?? false;
    line.button.dataset.path = connection.path;
    line.button.dataset.action = blocked ? "allow" : "block";
    line.button.setAttribute("aria-pressed", String(blocked));
    line.button.setAttribute("aria-label", `${blocked ? "Allow" : "Block"} ${connection.name}`);
    setText(line.button, !canBlock(connection) ? "Can't block" : busy ? (blocked ? "Allowing…" : "Blocking…") : blocked ? "Allow" : "Block");
    line.button.disabled = !canBlock(connection) || busy;
  }

  for (const id of ["programs", "connections"] as const) {
    tabs[id].addEventListener("click", () => show(id, false));
  }
  $("#views").addEventListener("keydown", (event) => {
    const keys: Record<string, View> = { ArrowLeft: "programs", Home: "programs", ArrowRight: "connections", End: "connections" };
    const next = keys[event.key];
    if (!next || !(event.target instanceof HTMLElement) || !event.target.matches("[role=tab]")) return;
    event.preventDefault();
    show(next, true);
  });
  thisPc.addEventListener("change", paint);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) void refresh();
  });

  resolveNames.addEventListener("change", async () => {
    try {
      ctx.update(await invoke<AppState>("set_resolve_names", { enabled: resolveNames.checked }));
      ctx.say(resolveNames.checked ? "Host names are on." : "Host names are off. Connections show addresses only.");
      void refresh();
    } catch (error) {
      ctx.say(String(error));
      resolveNames.checked = ctx.state()?.resolveNames ?? true;
    }
  });

  return { paint };
}
