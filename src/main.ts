import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open } from "@tauri-apps/plugin-dialog";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { matches } from "./filter";
import { headline, meterLevel, type AppState, type Row, type Traffic } from "./model";
import { applyLabel, banner, pathKey, RowList, SHELL } from "./view";

const app = document.querySelector<HTMLDivElement>("#app")!;
app.innerHTML = SHELL;
const $ = <T extends HTMLElement>(selector: string): T => app.querySelector<T>(selector)!;

const shell = $<HTMLDivElement>(".app");
const search = $<HTMLInputElement>("#search");
const warningsEl = $<HTMLDivElement>("#warnings");
const suspendBtn = $<HTMLButtonElement>("#suspend");
const statusEl = $<HTMLSpanElement>("#status");
const updateBanner = $<HTMLDivElement>("#update-banner");
const updateText = $<HTMLSpanElement>("#update-text");
const settingsOverlay = $<HTMLDivElement>("#settings-overlay");
const confirmOverlay = $<HTMLDivElement>("#confirm-overlay");
const noticeOverlay = $<HTMLDivElement>("#notice-overlay");
const autostart = $<HTMLInputElement>("#autostart");
const settingsMsg = $<HTMLParagraphElement>("#settings-msg");

let state: AppState | null = null;
let pending: string | null = null;
let pendingUpdate: Update | null = null;
let working = 0;
const busyPaths = new Set<string>();
const UPDATE_EVERY_MS = 4 * 60 * 60 * 1000;

const blockedList = new RowList($("#blocked"), (row) => void onToggle(row));
const seenList = new RowList($("#seen"), (row) => void onToggle(row));

function paint(): void {
  if (!state) return;
  const query = search.value;
  const visible = (rows: Row[]) => rows.filter((row) => matches(row.name, row.path, row.publisher, query));
  const now = Date.now() / 1000;
  const blocked = visible(state.blocked);
  const seen = visible(state.seen);

  applyLabel(statusEl, $("#status-text"), headline(state));
  warningsEl.replaceChildren();
  if (state.suspended) {
    warningsEl.append(banner("warn", "All WattWall blocks are off. Turn them back on when you have finished checking."));
  }
  for (const warning of state.warnings) warningsEl.append(banner("bad", warning));

  suspendBtn.dataset.suspended = String(state.suspended);
  $("#suspend-text").textContent = state.suspended ? "Turn all blocks on" : "Turn all blocks off";
  suspendBtn.disabled = !state.hasRules;
  $("#blocked-count").textContent = String(blocked.length);
  $("#seen-count").textContent = String(seen.length);

  blockedList.render(
    blocked,
    query ? "Nothing blocked matches" : "Nothing is blocked",
    query ? "Clear the search to see every block." : "Choose Block beside a program below, or Block a program to pick any .exe file.",
    busyPaths,
    now,
  );
  seenList.render(
    seen,
    query ? "Nothing matches" : "No programs seen yet",
    query ? "Try part of the name, the folder or the publisher." : "Programs appear here as soon as they use the network.",
    busyPaths,
    now,
  );

  autostart.checked = state.autostart;
  autostart.disabled = !state.autostartAvailable;
  $("#autostart-reason").textContent =
    state.autostartReason || "Opens hidden in the tray when you sign in, with no administrator prompt.";
}

async function onToggle(row: Row): Promise<void> {
  if (row.cannotBlock) {
    notice(row.warning);
    return;
  }
  await apply(row.path, !row.blocked, false);
}

async function apply(path: string, blocked: boolean, confirmed: boolean): Promise<void> {
  const key = pathKey(path);
  const focused = document.activeElement;
  const refocus = focused instanceof HTMLButtonElement && pathKey(focused.dataset.path ?? "") === key;
  busyPaths.add(key);
  working += 1;
  paint();
  try {
    state = await invoke<AppState>("set_blocked", { path, blocked, confirmed });
  } catch (error) {
    const message = String(error);
    if (message.startsWith("confirm:")) {
      pending = path;
      $("#confirm-text").textContent = message.slice("confirm:".length);
      openDialog(confirmOverlay, $("#confirm-no"));
    } else {
      notice(message.startsWith("impossible:") ? message.slice("impossible:".length) : message);
    }
  } finally {
    busyPaths.delete(key);
    working -= 1;
    paint();
  }
  if (refocus && !isOpen()) {
    app.querySelector<HTMLButtonElement>(`button.toggle[data-path="${CSS.escape(path)}"]`)?.focus();
  }
}

// Dialogs: the rest of the window is inert while one is open, and focus
// returns to where it was when the last one closes.
let returnFocus: HTMLElement | null = null;
const overlays = [noticeOverlay, confirmOverlay, settingsOverlay];
const isOpen = () => overlays.some((overlay) => !overlay.classList.contains("hidden"));

function openDialog(overlay: HTMLElement, focus: HTMLElement): void {
  if (!isOpen() && document.activeElement instanceof HTMLElement) returnFocus = document.activeElement;
  overlay.classList.remove("hidden");
  shell.inert = true;
  focus.focus();
}

function closeDialog(overlay: HTMLElement): void {
  overlay.classList.add("hidden");
  if (overlay === confirmOverlay) pending = null;
  if (isOpen()) return;
  shell.inert = false;
  returnFocus?.focus();
  returnFocus = null;
}

function notice(text: string): void {
  $("#notice-text").textContent = text;
  openDialog(noticeOverlay, $("#notice-ok"));
}

for (const overlay of overlays) {
  overlay.addEventListener("mousedown", (event) => {
    if (event.target === overlay) closeDialog(overlay);
  });
}

search.addEventListener("input", paint);

suspendBtn.addEventListener("click", async () => {
  if (!state) return;
  working += 1;
  try {
    state = await invoke<AppState>("set_suspended", { suspended: !state.suspended });
    paint();
  } catch (error) {
    notice(String(error));
  } finally {
    working -= 1;
  }
});

$("#block-program").addEventListener("click", async () => {
  const picked = await open({ multiple: false, filters: [{ name: "Programs", extensions: ["exe"] }] });
  if (typeof picked !== "string") return;
  await apply(picked, true, false);
});

$("#settings").addEventListener("click", () => {
  settingsMsg.textContent = "";
  openDialog(settingsOverlay, $("#settings-close"));
});
$("#settings-close").addEventListener("click", () => closeDialog(settingsOverlay));
$("#settings-x").addEventListener("click", () => closeDialog(settingsOverlay));

autostart.addEventListener("change", async () => {
  const enabled = autostart.checked;
  try {
    state = await invoke<AppState>("set_autostart", { enabled });
    paint();
    settingsMsg.textContent = enabled
      ? "WattWall will start hidden in the tray when you sign in."
      : "WattWall will not start when you sign in.";
  } catch (error) {
    settingsMsg.textContent = String(error);
    if (state) autostart.checked = state.autostart;
  }
});

$("#confirm-no").addEventListener("click", () => closeDialog(confirmOverlay));
$("#confirm-yes").addEventListener("click", async () => {
  const path = pending;
  closeDialog(confirmOverlay);
  if (path) await apply(path, true, true);
});
$("#notice-ok").addEventListener("click", () => closeDialog(noticeOverlay));

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    const top = overlays.find((overlay) => !overlay.classList.contains("hidden"));
    if (top) {
      event.preventDefault();
      closeDialog(top);
    }
    return;
  }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f" && !isOpen()) {
    event.preventDefault();
    search.focus();
    search.select();
  }
});

// Traffic: the header shows this second's rates and the last minute as a graph.
const HISTORY = 60;
const sent: number[] = new Array(HISTORY).fill(0);
const received: number[] = new Array(HISTORY).fill(0);

function drawGraph(values: number[], line: string, area: string): void {
  const step = 120 / (HISTORY - 1);
  const points = values
    .map((value, index) => `${(index * step).toFixed(1)},${(29 - meterLevel(value) * 27).toFixed(1)}`)
    .join(" ");
  app.querySelector(line)!.setAttribute("points", points);
  app.querySelector(area)!.setAttribute("points", `0,30 ${points} 120,30`);
}

void listen<Traffic>("traffic", (event) => {
  const traffic = event.payload;
  $("#rate-send").textContent = traffic.sending;
  $("#rate-receive").textContent = traffic.receiving;
  sent.push(traffic.sendingPerSecond);
  received.push(traffic.receivingPerSecond);
  sent.shift();
  received.shift();
  drawGraph(received, "#spark-receive", "#area-receive");
  drawGraph(sent, "#spark-send", "#area-send");
});
drawGraph(received, "#spark-receive", "#area-receive");
drawGraph(sent, "#spark-send", "#area-send");

// Updates: checked at start and every four hours, installed without asking.
async function checkForUpdates(manual: boolean): Promise<void> {
  if (pendingUpdate) {
    if (manual) settingsMsg.textContent = `WattWall ${pendingUpdate.version} is already downloading.`;
    return;
  }
  if (manual) settingsMsg.textContent = "Checking for updates…";
  try {
    const update = await check();
    if (update) await startUpdate(update);
    else if (manual) settingsMsg.textContent = "WattWall is up to date.";
  } catch (error) {
    if (manual) settingsMsg.textContent = `Could not check for updates: ${error}`;
  }
}

async function startUpdate(update: Update): Promise<void> {
  if (pendingUpdate) return;
  pendingUpdate = update;
  updateBanner.classList.remove("hidden", "bad");
  updateText.textContent = `WattWall ${update.version} is available. Downloading, then restarting…`;
  try {
    await update.download();
    while (working > 0) {
      updateText.textContent = `WattWall ${update.version} is ready. Restarting once the current change is done…`;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    updateText.textContent = `WattWall ${update.version} is ready. Installing and restarting…`;
    await update.install();
    await relaunch();
  } catch (error) {
    updateBanner.classList.add("bad");
    updateText.textContent = `Update failed: ${error}`;
    pendingUpdate = null;
  }
}

$("#check-updates").addEventListener("click", () => void checkForUpdates(true));

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
    $("#about-version").textContent = `version ${version}`;
  })
  .catch(() => {});

void invoke<AppState>("app_state")
  .then((fresh) => {
    state = fresh;
    paint();
  })
  .catch((error) => notice(String(error)));
void checkForUpdates(false);
setInterval(() => void checkForUpdates(false), UPDATE_EVERY_MS);
