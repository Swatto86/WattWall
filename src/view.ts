// The window's markup and the program lists. Lists update rows in place, so
// the three-second refresh does not steal keyboard focus or reload icons.
import logo from "../src-tauri/icons/source/wattwall.svg";
import { icon } from "./icons";
import { rowStatus, toggleLabel, vtLabel, type Label, type Row } from "./model";

export const SHELL = `
  <div class="app">
    <header class="top">
      <div class="brand">
        <img class="logo" src="${logo}" alt="" width="30" height="30" />
        <div class="brand-text">
          <span class="brand-name">WattWall</span>
          <span id="status" class="status" data-tone="muted"><i class="dot"></i><span id="status-text">Starting</span></span>
        </div>
      </div>
      <div class="traffic" title="Traffic through this PC's network adapters, updated every second">
        <svg class="spark" viewBox="0 0 120 30" preserveAspectRatio="none" aria-hidden="true">
          <polygon id="area-receive" class="area-receive" points="" />
          <polygon id="area-send" class="area-send" points="" />
          <polyline id="spark-send" class="spark-send" points="" />
          <polyline id="spark-receive" class="spark-receive" points="" />
        </svg>
        <div class="rates">
          <span class="rate send">${icon.up}<span class="sr">Sending</span><span id="rate-send">…</span></span>
          <span class="rate receive">${icon.down}<span class="sr">Receiving</span><span id="rate-receive">…</span></span>
        </div>
      </div>
      <button id="settings" class="icon-btn" type="button" aria-label="Settings" title="Settings">${icon.settings}</button>
    </header>
    <div id="update-banner" class="banner info hidden" role="status">${icon.download}<span id="update-text"></span></div>
    <div id="warnings"></div>
    <div class="toolbar">
      <label class="search">
        ${icon.search}
        <input id="search" type="search" placeholder="Search programs" aria-label="Search programs" autocomplete="off" spellcheck="false" />
        <kbd>Ctrl F</kbd>
      </label>
      <button id="block-all" class="btn block-all" type="button" data-on="false" title="Cut every program off the network">${icon.ban}<span id="block-all-text">Block all</span></button>
      <button id="suspend" class="btn" type="button" data-suspended="false">${icon.pause}${icon.play}<span id="suspend-text">Turn all blocks off</span></button>
      <button id="block-program" class="btn primary" type="button">${icon.plus}<span>Block a program…</span></button>
    </div>
    <main class="list">
      <section aria-labelledby="blocked-title">
        <h2 id="blocked-title">Blocked <span id="blocked-count" class="count">0</span></h2>
        <div class="rows"><div class="thead" aria-hidden="true"><span></span><span>Program</span><span class="th-vt">VirusTotal</span><span>Status</span><span></span></div><div id="blocked" class="tbody"></div></div>
      </section>
      <section aria-labelledby="seen-title">
        <h2 id="seen-title">Seen using the network <span id="seen-count" class="count">0</span></h2>
        <div class="rows"><div class="thead" aria-hidden="true"><span></span><span>Program</span><span class="th-vt">VirusTotal</span><span>Status</span><span></span></div><div id="seen" class="tbody"></div></div>
      </section>
    </main>
  </div>
  <div id="settings-overlay" class="overlay hidden">
    <div class="panel" role="dialog" aria-modal="true" aria-labelledby="settings-title">
      <div class="panel-head">
        <h3 id="settings-title">Settings</h3>
        <button id="settings-x" class="icon-btn" type="button" aria-label="Close">${icon.close}</button>
      </div>
      <label class="setting">
        <span class="setting-text"><span class="setting-name">Start with Windows</span><span id="autostart-reason" class="hint"></span></span>
        <input id="autostart" class="switch" type="checkbox" role="switch" />
      </label>
      <div class="setting">
        <span class="setting-text"><span class="setting-name">Updates</span><span class="hint">WattWall checks at start and every four hours, then installs and restarts by itself.</span></span>
        <button id="check-updates" class="btn" type="button">Check now</button>
      </div>
      <div class="setting">
        <span class="setting-text"><span class="setting-name">Check programs with VirusTotal</span><span class="hint">Sends each program's SHA-256 hash, never the file, using your own API key.</span></span>
        <input id="vt-enabled" class="switch" type="checkbox" role="switch" aria-label="Check programs with VirusTotal" />
      </div>
      <div id="vt-configured" class="vt-configured hidden">
        <span id="vt-limits" class="hint"></span>
        <span id="vt-status" class="vt-status" data-tone="muted" role="status"></span>
        <div class="vt-actions">
          <button id="vt-change" class="btn small" type="button">Change key or limits</button>
          <button id="vt-remove" class="btn small" type="button">Remove key</button>
        </div>
      </div>
      <p id="settings-msg" class="settings-msg" role="status"></p>
      <div class="about">
        <img src="${logo}" alt="" width="36" height="36" />
        <div><strong>WattWall</strong> <span id="about-version"></span><span class="hint">MIT licence. Source: github.com/Swatto86/WattWall</span></div>
      </div>
      <div class="actions"><button id="settings-close" class="btn" type="button">Close</button></div>
    </div>
  </div>
  <div id="confirm-overlay" class="overlay hidden">
    <div class="panel" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-text">
      <div class="panel-head warn">${icon.warning}<h3 id="confirm-title">Block this program?</h3></div>
      <p id="confirm-text"></p>
      <div class="actions">
        <button id="confirm-no" class="btn" type="button">Cancel</button>
        <button id="confirm-yes" class="btn danger" type="button">Block it</button>
      </div>
    </div>
  </div>
  <div id="notice-overlay" class="overlay hidden">
    <div class="panel" role="alertdialog" aria-modal="true" aria-labelledby="notice-title" aria-describedby="notice-text">
      <div class="panel-head">${icon.info}<h3 id="notice-title">WattWall</h3></div>
      <p id="notice-text"></p>
      <div class="actions"><button id="notice-ok" class="btn primary" type="button">OK</button></div>
    </div>
  </div>
  <div id="vt-setup-overlay" class="overlay hidden">
    <form id="vt-form" class="panel" role="dialog" aria-modal="true" aria-labelledby="vt-setup-title" novalidate>
      <div class="panel-head">${icon.shield}<h3 id="vt-setup-title">Check programs with VirusTotal</h3></div>
      <p>WattWall sends each program's SHA-256 hash, never the file, to VirusTotal and shows how many security engines flag it. This tells VirusTotal which programs you run. It uses your own API key under VirusTotal's Terms of Service.</p>
      <label class="field"><span>API key</span><input id="vt-key" type="password" autocomplete="off" spellcheck="false" /></label>
      <div class="field-row">
        <label class="field"><span>Lookups per minute</span><input id="vt-per-minute" type="number" min="1" step="1" inputmode="numeric" /></label>
        <label class="field"><span>Lookups per day</span><input id="vt-per-day" type="number" min="1" step="1" inputmode="numeric" /></label>
      </div>
      <div class="quota-row">
        <button id="vt-read-limits" class="btn small" type="button">Read limits from VirusTotal</button>
        <span id="vt-quota-note" class="hint" role="status"></span>
      </div>
      <p class="hint">VirusTotal reports each key's real limits (asking does not use any lookups). The free Public API documents 4 a minute and 500 a day. WattWall also waits by itself when VirusTotal says the quota is used up.</p>
      <p id="vt-error" class="form-error" role="alert"></p>
      <div class="actions">
        <button id="vt-cancel" class="btn" type="button">Cancel</button>
        <button id="vt-save" class="btn primary" type="submit">Save and turn on</button>
      </div>
    </form>
  </div>
  <div id="vt-details-overlay" class="overlay hidden">
    <div class="panel" role="dialog" aria-modal="true" aria-labelledby="vt-details-title">
      <div class="panel-head">${icon.shield}<h3 id="vt-details-title">VirusTotal</h3></div>
      <p id="vt-details-summary"></p>
      <ul id="vt-details-names" class="vt-names"></ul>
      <p id="vt-details-checked" class="hint"></p>
      <code id="vt-details-sha" class="sha"></code>
      <p id="vt-details-msg" class="hint" role="status"></p>
      <div class="actions">
        <button id="vt-copy" class="btn" type="button">Copy report link</button>
        <button id="vt-details-close" class="btn primary" type="button">Close</button>
      </div>
    </div>
  </div>
`;

export function applyLabel(element: HTMLElement, text: HTMLElement, label: Label): void {
  element.dataset.tone = label.tone;
  element.title = label.title;
  text.textContent = label.text;
}

export function banner(tone: "warn" | "bad" | "info", text: string): HTMLElement {
  const line = document.createElement("div");
  line.className = `banner ${tone}`;
  line.setAttribute("role", "status");
  line.innerHTML = tone === "info" ? icon.info : icon.warning;
  const words = document.createElement("span");
  words.textContent = text;
  line.append(words);
  return line;
}

interface RowParts {
  root: HTMLElement;
  picture: HTMLElement;
  name: HTMLElement;
  publisher: HTMLElement;
  path: HTMLElement;
  chip: HTMLElement;
  chipText: HTMLElement;
  vt: HTMLButtonElement;
  button: HTMLButtonElement;
  row: Row;
  iconSource: string;
}

export const pathKey = (path: string): string => path.toLowerCase();

/** One of the two program lists. */
export class RowList {
  private readonly parts = new Map<string, RowParts>();
  private readonly empty: HTMLElement;

  constructor(
    private readonly host: HTMLElement,
    private readonly onToggle: (row: Row) => void,
    private readonly onDetails: (row: Row) => void,
  ) {
    this.empty = document.createElement("div");
    this.empty.className = "empty";
    this.empty.innerHTML = `${icon.wall}<p class="empty-title"></p><p class="empty-hint"></p>`;
  }

  render(rows: Row[], emptyTitle: string, emptyHint: string, busy: ReadonlySet<string>, nowSeconds: number): void {
    const wanted = new Set(rows.map((row) => pathKey(row.path)));
    for (const [key, part] of this.parts) {
      if (!wanted.has(key)) {
        part.root.remove();
        this.parts.delete(key);
      }
    }
    if (rows.length === 0) {
      this.empty.querySelector(".empty-title")!.textContent = emptyTitle;
      this.empty.querySelector(".empty-hint")!.textContent = emptyHint;
      if (this.empty.parentElement !== this.host) this.host.append(this.empty);
      return;
    }
    this.empty.remove();
    let cursor = this.host.firstElementChild;
    for (const row of rows) {
      const key = pathKey(row.path);
      const part = this.parts.get(key) ?? this.create(key);
      this.update(part, row, busy.has(key), nowSeconds);
      if (part.root === cursor) {
        cursor = cursor.nextElementSibling;
      } else {
        this.host.insertBefore(part.root, cursor);
      }
    }
  }

  private create(key: string): RowParts {
    const root = document.createElement("article");
    root.className = "row";
    const picture = document.createElement("div");
    picture.className = "picture";
    const info = document.createElement("div");
    info.className = "info";
    const line = document.createElement("div");
    line.className = "line";
    const name = document.createElement("span");
    name.className = "name";
    const publisher = document.createElement("span");
    publisher.className = "publisher";
    line.append(name, publisher);
    const path = document.createElement("div");
    path.className = "path";
    info.append(line, path);
    const chip = document.createElement("span");
    chip.className = "chip";
    const dot = document.createElement("i");
    dot.className = "dot";
    const chipText = document.createElement("span");
    chip.append(dot, chipText);
    const vt = document.createElement("button");
    vt.className = "vt-chip";
    vt.type = "button";
    const vtCell = document.createElement("div");
    vtCell.className = "cell-vt";
    vtCell.append(vt);
    const statusCell = document.createElement("div");
    statusCell.className = "cell-status";
    statusCell.append(chip);
    const button = document.createElement("button");
    button.className = "toggle";
    button.type = "button";
    root.append(picture, info, vtCell, statusCell, button);
    const part: RowParts = { root, picture, name, publisher, path, chip, chipText, vt, button, row: {} as Row, iconSource: "\u0000" };
    button.addEventListener("click", () => this.onToggle(part.row));
    vt.addEventListener("click", () => this.onDetails(part.row));
    this.parts.set(key, part);
    return part;
  }

  private update(part: RowParts, row: Row, busy: boolean, nowSeconds: number): void {
    part.row = row;
    if (part.iconSource !== row.icon) {
      part.iconSource = row.icon;
      if (row.icon) {
        const img = document.createElement("img");
        img.alt = "";
        img.src = row.icon;
        part.picture.replaceChildren(img);
        part.picture.classList.remove("mark");
      } else {
        part.picture.replaceChildren(document.createTextNode(row.name.slice(0, 1).toUpperCase()));
        part.picture.classList.add("mark");
      }
    }
    setText(part.name, row.name);
    setText(part.publisher, row.publisher);
    setText(part.path, row.path);
    part.path.title = row.path;
    const status = rowStatus(row, nowSeconds);
    applyLabel(part.chip, part.chipText, status);
    part.chip.hidden = status.text === "";
    part.root.dataset.state = status.tone;
    const vt = vtLabel(row.virustotal);
    part.vt.hidden = vt === null;
    if (vt) {
      setText(part.vt, vt.text);
      part.vt.dataset.tone = vt.tone;
      part.vt.dataset.path = row.path;
      part.vt.title = vt.title;
      const state = row.virustotal?.state;
      part.vt.disabled = state !== "found" && state !== "unknown";
      part.vt.setAttribute("aria-label", `VirusTotal for ${row.name}: ${vt.title}`);
    }
    part.button.dataset.path = row.path;
    part.button.dataset.action = row.blocked ? "allow" : "block";
    part.button.setAttribute("aria-pressed", row.blocked ? "true" : "false");
    part.button.setAttribute("aria-label", `${row.blocked ? "Allow" : "Block"} ${row.name}`);
    setText(part.button, toggleLabel(row, busy));
    part.button.disabled = row.cannotBlock || busy;
  }
}

function setText(element: HTMLElement, text: string): void {
  if (element.textContent !== text) element.textContent = text;
}
