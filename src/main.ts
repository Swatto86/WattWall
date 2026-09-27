import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open } from "@tauri-apps/plugin-dialog";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { matches } from "./filter";

interface Row {
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
}

interface AppState {
  blocked: Row[];
  seen: Row[];
  suspended: boolean;
  hasRules: boolean;
  warnings: string[];
  autostart: boolean;
  autostartAvailable: boolean;
  autostartReason: string;
  elevated: boolean;
}

const app = document.querySelector<HTMLDivElement>("#app")!;
let state: AppState | null = null;
let query = "";
let pending: { path: string; blocked: boolean } | null = null;
let pendingUpdate: Update | null = null;
let busy = false;
const UPDATE_EVERY_MS = 4 * 60 * 60 * 1000;

app.innerHTML = `
  <div class="app">
    <div id="update-banner" class="banner hidden"><span id="update-text"></span></div>
    <div id="warnings"></div>
    <div class="toolbar">
      <span class="brand">WattWall</span>
      <input id="search" type="search" placeholder="Search programs" aria-label="Search programs" />
      <span class="grow"></span>
      <button id="suspend" class="btn" type="button">Turn all blocks off</button>
      <button id="block-program" class="btn primary" type="button">Block a program…</button>
      <button id="settings" class="btn" type="button" aria-label="Settings">Settings</button>
    </div>
    <div class="list">
      <section>
        <h2>Blocked</h2>
        <div id="blocked"></div>
      </section>
      <section>
        <h2>Seen using the network</h2>
        <div id="seen"></div>
      </section>
    </div>
  </div>
  <div id="settings-overlay" class="overlay hidden">
    <div class="panel" role="dialog" aria-modal="true" aria-labelledby="settings-title">
      <h3 id="settings-title">Settings</h3>
      <label class="rowline">
        <span>Start with Windows<span id="autostart-reason" class="hint"></span></span>
        <input id="autostart" type="checkbox" />
      </label>
      <div class="rowline">
        <span>About<span id="about-version" class="hint"></span></span>
        <button id="check-updates" class="btn" type="button">Check for updates</button>
      </div>
      <p id="settings-msg" class="hint" role="status"></p>
      <div class="actions"><button id="settings-close" class="btn" type="button">Close</button></div>
    </div>
  </div>
  <div id="confirm-overlay" class="overlay hidden">
    <div class="panel" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <h3 id="confirm-title">Block this program?</h3>
      <p id="confirm-text"></p>
      <div class="actions">
        <button id="confirm-no" class="btn" type="button">Cancel</button>
        <button id="confirm-yes" class="btn primary" type="button">Block it</button>
      </div>
    </div>
  </div>
  <div id="notice-overlay" class="overlay hidden">
    <div class="panel" role="dialog" aria-modal="true" aria-labelledby="notice-title">
      <h3 id="notice-title">WattWall</h3>
      <p id="notice-text"></p>
      <div class="actions"><button id="notice-ok" class="btn" type="button">OK</button></div>
    </div>
  </div>
`;

const search = app.querySelector<HTMLInputElement>("#search")!;
const blockedEl = app.querySelector<HTMLDivElement>("#blocked")!;
const seenEl = app.querySelector<HTMLDivElement>("#seen")!;
const warningsEl = app.querySelector<HTMLDivElement>("#warnings")!;
const suspendBtn = app.querySelector<HTMLButtonElement>("#suspend")!;
const updateBanner = app.querySelector<HTMLDivElement>("#update-banner")!;
const updateText = app.querySelector<HTMLSpanElement>("#update-text")!;
const settingsOverlay = app.querySelector<HTMLDivElement>("#settings-overlay")!;
const confirmOverlay = app.querySelector<HTMLDivElement>("#confirm-overlay")!;
const noticeOverlay = app.querySelector<HTMLDivElement>("#notice-overlay")!;
const autostart = app.querySelector<HTMLInputElement>("#autostart")!;
const autostartReason = app.querySelector<HTMLSpanElement>("#autostart-reason")!;
const settingsMsg = app.querySelector<HTMLParagraphElement>("#settings-msg")!;

function when(row: Row): string {
  if (row.connected) return "Connected";
  if (row.lastSeen == null) return "";
  const minutes = Math.floor(Date.now() / 1000 - row.lastSeen) / 60;
  if (minutes < 1) return "Last seen just now";
  if (minutes < 60) return `Last seen ${Math.floor(minutes)} min ago`;
  const hours = minutes / 60;
  if (hours < 24) return `Last seen ${Math.floor(hours)} h ago`;
  return `Last seen ${Math.floor(hours / 24)} d ago`;
}

function fill(host: HTMLElement, rows: Row[], empty: string): void {
  host.replaceChildren();
  const visible = rows.filter((row) => matches(row.name, row.path, row.publisher, query));
  if (visible.length === 0) {
    const note = document.createElement("p");
    note.className = "empty";
    note.textContent = empty;
    host.append(note);
    return;
  }
  for (const row of visible) host.append(renderRow(row));
}

function renderRow(row: Row): HTMLElement {
  const article = document.createElement("article");
  article.className = "row";
  if (row.icon) {
    const img = document.createElement("img");
    img.alt = "";
    img.src = row.icon;
    article.append(img);
  } else {
    const mark = document.createElement("div");
    mark.className = "mark";
    mark.textContent = row.name.slice(0, 1).toUpperCase();
    article.append(mark);
  }
  const text = document.createElement("div");
  const name = document.createElement("div");
  name.className = "name";
  name.textContent = row.name;
  const publisher = document.createElement("div");
  publisher.className = "meta";
  publisher.textContent = row.publisher;
  const path = document.createElement("div");
  path.className = "path";
  path.textContent = row.path;
  path.title = row.path;
  const seen = document.createElement("div");
  seen.className = "when";
  const paused = row.blocked && !row.enforced ? "Block paused — " : "";
  seen.textContent = paused + when(row);
  text.append(name, publisher, path, seen);
  const button = document.createElement("button");
  button.className = "toggle";
  button.type = "button";
  button.dataset.path = row.path;
  button.setAttribute("aria-pressed", row.blocked ? "true" : "false");
  button.textContent = row.cannotBlock ? "Can't block" : row.blocked ? "Allow" : "Block";
  button.disabled = row.cannotBlock;
  button.addEventListener("click", () => void onToggle(row));
  article.append(text, button);
  return article;
}

function paint(): void {
  if (!state) return;
  warningsEl.replaceChildren();
  for (const warning of state.warnings) {
    const line = document.createElement("div");
    line.className = "banner warn";
    line.textContent = warning;
    warningsEl.append(line);
  }
  if (state.suspended) {
    const line = document.createElement("div");
    line.className = "banner";
    line.textContent = "All WattWall blocks are off. Turn them back on when you have finished checking.";
    warningsEl.prepend(line);
  }
  suspendBtn.textContent = state.suspended ? "Turn all blocks on" : "Turn all blocks off";
  suspendBtn.disabled = !state.hasRules;
  fill(blockedEl, state.blocked, query ? "Nothing blocked matches." : "Nothing is blocked.");
  fill(seenEl, state.seen, query ? "Nothing matches." : "No programs have been seen on the network yet.");
  autostart.checked = state.autostart;
  autostart.disabled = !state.autostartAvailable;
  autostartReason.textContent = state.autostartReason;
}

async function refresh(): Promise<void> {
  state = await invoke<AppState>("app_state");
  paint();
}

async function onToggle(row: Row): Promise<void> {
  if (row.cannotBlock) {
    notice(row.warning);
    return;
  }
  await apply(row.path, !row.blocked, false, row.warning);
}

async function apply(path: string, blocked: boolean, confirmed: boolean, warning: string): Promise<void> {
  busy = true;
  try {
    state = await invoke<AppState>("set_blocked", { path, blocked, confirmed });
    paint();
  } catch (error) {
    const message = String(error);
    if (message.startsWith("confirm:")) {
      pending = { path, blocked: true };
      app.querySelector<HTMLParagraphElement>("#confirm-text")!.textContent = message.slice("confirm:".length);
      confirmOverlay.classList.remove("hidden");
      app.querySelector<HTMLButtonElement>("#confirm-no")!.focus();
    } else if (message.startsWith("impossible:")) {
      notice(message.slice("impossible:".length));
    } else {
      notice(warning && message === "" ? warning : message);
    }
  } finally {
    busy = false;
  }
}

function notice(text: string): void {
  app.querySelector<HTMLParagraphElement>("#notice-text")!.textContent = text;
  noticeOverlay.classList.remove("hidden");
  app.querySelector<HTMLButtonElement>("#notice-ok")!.focus();
}

search.addEventListener("input", () => {
  query = search.value;
  paint();
});

suspendBtn.addEventListener("click", async () => {
  if (!state) return;
  busy = true;
  try {
    state = await invoke<AppState>("set_suspended", { suspended: !state.suspended });
    paint();
  } catch (error) {
    notice(String(error));
  } finally {
    busy = false;
  }
});

app.querySelector("#block-program")!.addEventListener("click", async () => {
  const picked = await open({ multiple: false, filters: [{ name: "Programs", extensions: ["exe"] }] });
  if (typeof picked !== "string") return;
  await apply(picked, true, false, "");
});

app.querySelector("#settings")!.addEventListener("click", () => {
  settingsMsg.textContent = "";
  settingsOverlay.classList.remove("hidden");
});
app.querySelector("#settings-close")!.addEventListener("click", () => settingsOverlay.classList.add("hidden"));

autostart.addEventListener("change", async () => {
  const enabled = autostart.checked;
  try {
    state = await invoke<AppState>("set_autostart", { enabled });
    paint();
    settingsMsg.textContent = enabled ? "WattWall will start hidden at logon." : "WattWall will not start at logon.";
  } catch (error) {
    settingsMsg.textContent = String(error);
    if (state) autostart.checked = state.autostart;
  }
});

app.querySelector("#confirm-no")!.addEventListener("click", () => {
  pending = null;
  confirmOverlay.classList.add("hidden");
});
app.querySelector("#confirm-yes")!.addEventListener("click", async () => {
  const choice = pending;
  pending = null;
  confirmOverlay.classList.add("hidden");
  if (choice) await apply(choice.path, true, true, "");
});
app.querySelector("#notice-ok")!.addEventListener("click", () => noticeOverlay.classList.add("hidden"));

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    confirmOverlay.classList.add("hidden");
    noticeOverlay.classList.add("hidden");
    settingsOverlay.classList.add("hidden");
    pending = null;
  }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
    event.preventDefault();
    search.focus();
  }
});

async function checkForUpdates(): Promise<void> {
  if (pendingUpdate) return;
  try {
    const update = await check();
    if (update) await startUpdate(update);
  } catch {
    /* offline, or no published update yet */
  }
}

async function startUpdate(update: Update): Promise<void> {
  if (pendingUpdate) return;
  pendingUpdate = update;
  updateBanner.classList.remove("hidden");
  updateText.textContent = `WattWall ${update.version} is available — downloading and restarting…`;
  try {
    await update.download();
    while (busy) {
      updateText.textContent = `WattWall ${update.version} downloaded — restarting once the current change is done…`;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    updateText.textContent = `WattWall ${update.version} downloaded — installing and restarting…`;
    await update.install();
    await relaunch();
  } catch (error) {
    updateBanner.classList.add("bad");
    updateText.textContent = `Update failed: ${error}`;
    pendingUpdate = null;
  }
}

app.querySelector("#check-updates")!.addEventListener("click", () => void checkForUpdates());

void listen<AppState>("state", (event) => {
  state = event.payload;
  paint();
});

void invoke<boolean>("started_hidden")
  .then((hidden) => {
    if (!hidden) void getCurrentWindow().show();
  })
  .catch(() => void getCurrentWindow().show());

void getVersion()
  .then((version) => {
    app.querySelector("#about-version")!.textContent = `Version ${version}. Source: github.com/Swatto86/WattWall`;
  })
  .catch(() => {});

void refresh().catch((error) => notice(String(error)));
void checkForUpdates();
setInterval(() => void checkForUpdates(), UPDATE_EVERY_MS);
