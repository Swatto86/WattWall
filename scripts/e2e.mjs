// Desktop end-to-end journey. Drives the real debug binary through its real
// webview on an isolated profile, with a file-backed firewall so the suite
// does not change this PC's Windows Firewall rules.
//
// Covers boot to the main window, the live traffic reading, VirusTotal setup
// and results (test mode answers from a table, no network or Credential
// Manager), blocking a program, turning every block off and on, a hidden
// (logon-style) restart that keeps the block and the saved results,
// allowing it again, a command the window is not allowed to call, and a
// clean exit.
import { remote } from "webdriverio";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import assert from "node:assert/strict";

const skip = (reason) => {
  if (process.env.WATTWALL_REQUIRE_E2E === "1") {
    console.error(`desktop end-to-end suite is required but cannot run: ${reason}`);
    process.exit(1);
  }
  console.log(`SKIP desktop end-to-end suite: ${reason}`);
  process.exit(0);
};
const onPath = (tool) => {
  try {
    execFileSync("where", [tool], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};

const executable = resolve(process.env.WATTWALL_TEST_BINARY || "target/debug/WattWall.exe");
if (!existsSync(executable)) skip(`no debug build at ${executable} (npx tauri build --debug --no-bundle)`);
if (!onPath("msedgedriver")) skip("msedgedriver is not on PATH");

const realSettings = join(process.env.LOCALAPPDATA ?? "", "WattWall", "settings.json");

const stateDir = realpathSync.native(mkdtempSync(join(tmpdir(), "wattwall-e2e-")));
const profile = join(stateDir, "profile");
mkdirSync(profile, { recursive: true });
const notepad = "C:\\Windows\\System32\\notepad.exe";
const curl = "C:\\Windows\\System32\\curl.exe";
// A program no real PC has. The test app remembers it like any connected
// program, so it must turn up in the isolated profile and never in the
// installed app's settings, even while an installed WattWall writes its own.
const marker = `C:\\WattWall-e2e-${randomUUID()}\\probe.exe`;
writeFileSync(join(profile, "fake-connections.json"), JSON.stringify([notepad, curl, marker]));
const mentionsMarker = (path) => existsSync(path) && readFileSync(path, "utf8").toLowerCase().includes(marker.toLowerCase().replaceAll("\\", "\\\\"));

const appEnv = {
  ...process.env,
  WATTWALL_DATA_DIR: profile,
  WATTWALL_FAKE: "1",
  WATTWALL_E2E: "1",
  WEBVIEW2_USER_DATA_FOLDER: join(stateDir, "webview"),
};

const freePort = () => new Promise((resolvePort, reject) => {
  const server = createServer();
  server.on("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    server.close(() => resolvePort(port));
  });
});
const waitFor = async (check, message, timeout = 30000) => {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(message);
};
const reachable = async (url) => {
  try {
    return (await fetch(url)).ok;
  } catch {
    return false;
  }
};

const driverPort = await freePort();
const driver = spawn("msedgedriver", [`--port=${driverPort}`], { stdio: ["ignore", "pipe", "pipe"] });
let driverLog = "";
let driverError;
driver.on("error", (error) => { driverError = error; });
for (const stream of [driver.stdout, driver.stderr]) {
  stream?.on("data", (data) => { driverLog = (driverLog + data).slice(-12000); });
}

let browser;
let app;
let debugPort;
let policyState;
const policy = (mode, port) => {
  const args = ["-NoProfile", "-File", "scripts/webview-test-policy.ps1", "-Mode", mode, "-StateFile", policyState];
  if (port) args.push("-Port", String(port));
  execFileSync("pwsh", args, { stdio: "pipe" });
};
const invoke = (command, args = {}) => browser.executeAsync((commandName, commandArgs, done) => {
  window.__TAURI_INTERNALS__.invoke(commandName, commandArgs).then(
    (value) => done({ ok: true, value }),
    (error) => done({ ok: false, message: String(error) }),
  );
}, command, args);

const connect = async (args = []) => {
  debugPort = await freePort();
  policyState = join(stateDir, "webview-policy.json");
  policy("Enable", debugPort);
  app = spawn(executable, args, {
    env: { ...appEnv, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${debugPort}` },
    stdio: "ignore",
  });
  await waitFor(async () => {
    if (app.exitCode !== null) throw new Error(`WattWall exited at launch with ${app.exitCode}`);
    return reachable(`http://127.0.0.1:${debugPort}/json/version`);
  }, "WattWall did not expose its webview", 60000);
  browser = await remote({
    hostname: "127.0.0.1",
    port: driverPort,
    logLevel: "silent",
    connectionRetryCount: 0,
    connectionRetryTimeout: 60000,
    capabilities: {
      browserName: "webview2",
      "ms:edgeOptions": { debuggerAddress: `127.0.0.1:${debugPort}` },
      "wdio:enforceWebDriverClassic": true,
    },
  });
  await browser.waitUntil(
    () => browser.execute(() => Boolean(document.querySelector("#search"))),
    { timeout: 30000, timeoutMsg: "the main window never appeared" },
  );
};

const endSession = async () => {
  if (!browser) return;
  try { await browser.deleteSession(); } catch { /* the app may already have closed it */ }
  browser = undefined;
};

const exitApp = async () => {
  await invoke("quit_app");
  await waitFor(() => app.exitCode !== null, "WattWall did not exit", 20000);
  assert.equal(app.exitCode, 0, "WattWall must exit cleanly");
  app = undefined;
  policy("Restore");
  await endSession();
  await waitFor(async () => !(await reachable(`http://127.0.0.1:${debugPort}/json/version`)),
    "WebView2 kept running after WattWall exited", 20000);
};

const clickPath = (path) => browser.execute((want) => {
  const button = [...document.querySelectorAll("button.toggle")].find((el) =>
    (el.dataset.path ?? "").toLowerCase() === want.toLowerCase());
  if (!button) return false;
  button.click();
  return true;
}, path);

const pressed = (path) => browser.execute((want) => {
  const button = [...document.querySelectorAll("#blocked button.toggle")].find((el) =>
    (el.dataset.path ?? "").toLowerCase() === want.toLowerCase());
  return button?.getAttribute("aria-pressed") === "true";
}, path);

try {
  await waitFor(async () => {
    if (driverError) throw driverError;
    if (driver.exitCode !== null) throw new Error(`WebDriver server exited: ${driverLog}`);
    return reachable(`http://127.0.0.1:${driverPort}/status`);
  }, "WebDriver server did not start");

  await connect();
  await browser.waitUntil(
    async () => (await invoke("plugin:window|is_visible", { label: "main" })).value === true,
    { timeout: 10000, timeoutMsg: "a normal start must show the window" },
  );
  const hidden = (id) => browser.execute((elementId) => getComputedStyle(document.getElementById(elementId)).display === "none", id);
  assert.equal(await hidden("notice-overlay"), true, "the blank WattWall dialog must not cover the window");
  assert.equal(await hidden("settings-overlay"), true, "settings must start closed");
  assert.equal(await hidden("confirm-overlay"), true, "the block confirmation must start closed");
  await browser.$("#settings").click();
  await browser.$("#autostart").waitForDisplayed({ timeout: 5000 });
  await browser.$("#settings-close").click();
  await browser.waitUntil(() => hidden("settings-overlay"), { timeout: 5000, timeoutMsg: "settings did not close" });

  const fits = () => browser.execute(() => {
    const shell = document.querySelector(".app");
    if (!shell) return false;
    const box = shell.getBoundingClientRect();
    return document.documentElement.scrollWidth <= window.innerWidth + 1
      && Math.abs(box.height - window.innerHeight) < 2;
  });
  await browser.waitUntil(fits, { timeout: 10000, timeoutMsg: "the window contents do not fill the window" });
  await browser.setWindowSize(720, 480);
  await browser.waitUntil(fits, { timeout: 10000, timeoutMsg: "the layout does not follow a smaller window" });

  const denied = await invoke("plugin:opener|open_url", { url: "https://example.com/" });
  assert.equal(denied.ok, false, "the window must not be allowed to open remote URLs");

  await browser.$("#search").setValue("notepad");
  await browser.waitUntil(async () => {
    const count = await browser.execute(() => document.querySelectorAll("#seen button.toggle").length);
    return count === 1;
  }, { timeout: 10000, timeoutMsg: "search did not narrow the list to notepad" });
  await browser.$("#search").setValue("");

  // The traffic thread's first reading replaces the waiting mark in the header.
  await browser.waitUntil(
    () => browser.execute(() => /\/s$/.test(document.querySelector("#rate-send")?.textContent ?? "")),
    { timeout: 10000, timeoutMsg: "no traffic reading reached the window" },
  );

  const status = () => browser.execute(() => document.querySelector("#status-text")?.textContent ?? "");
  const statusIs = (want, message) =>
    browser.waitUntil(async () => (await status()) === want, { timeout: 10000, timeoutMsg: `${message} (header: ${want})` });
  const notepadRule = () => JSON.parse(readFileSync(join(profile, "fake-rules.json"), "utf8"))
    .find((rule) => String(rule.path).toLowerCase().endsWith("notepad.exe"));

  // VirusTotal, against the test mode's table: curl.exe is flagged,
  // notepad.exe is clean, and the made-up marker file cannot be hashed.
  const vtChip = (path) => browser.execute((want) => {
    const chip = [...document.querySelectorAll("button.vt-chip")].find((el) =>
      (el.dataset.path ?? "").toLowerCase() === want.toLowerCase());
    return chip && !chip.hidden ? { text: chip.textContent, tone: chip.dataset.tone } : null;
  }, path);
  const chipIs = (path, text, tone) => browser.waitUntil(async () => {
    const chip = await vtChip(path);
    return chip?.text === text && chip.tone === tone;
  }, { timeout: 15000, timeoutMsg: `${path} did not show ${text} (${tone})` });
  const lookups = () => {
    const log = join(profile, "fake-virustotal-calls.log");
    return existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean).length : 0;
  };
  const vtStatus = () => browser.execute(() => document.querySelector("#vt-status")?.textContent ?? "");
  const goodKey = "1f".repeat(32);

  assert.equal(await vtChip(notepad), null, "no VirusTotal chips while the check is off");
  await browser.$("#settings").click();
  await browser.$("#vt-enabled").click();
  await browser.$("#vt-key").waitForDisplayed({ timeout: 5000, timeoutMsg: "turning VirusTotal on did not ask for a key" });
  assert.equal(await browser.$("#vt-per-minute").getValue(), "4", "the free limits are offered first");
  assert.equal(await browser.$("#vt-per-day").getValue(), "500");
  await browser.$("#vt-key").setValue("not-a-key");
  await browser.$("#vt-save").click();
  await browser.waitUntil(async () => (await browser.$("#vt-error").getText()).includes("64"),
    { timeout: 5000, timeoutMsg: "a malformed key was not refused" });
  await browser.$("#vt-key").setValue("0".repeat(64));
  await browser.$("#vt-per-minute").setValue("1000");
  await browser.$("#vt-per-day").setValue("100000");
  await browser.$("#vt-save").click();
  await browser.waitUntil(() => hidden("vt-setup-overlay"), { timeout: 5000, timeoutMsg: "setup did not close" });
  await browser.waitUntil(async () => (await vtStatus()).includes("rejected"),
    { timeout: 15000, timeoutMsg: "a rejected key was not reported" });
  await browser.$("#vt-change").click();
  await browser.$("#vt-key").waitForDisplayed({ timeout: 5000 });
  assert.equal(await browser.$("#vt-per-day").getValue(), "100000", "the saved limits come back");
  await browser.$("#vt-key").setValue(goodKey);
  await browser.$("#vt-read-limits").click();
  await browser.waitUntil(async () => (await browser.$("#vt-quota-note").getText()).includes("500 a day"),
    { timeout: 10000, timeoutMsg: "the key's limits were not read from VirusTotal" });
  assert.equal(await browser.$("#vt-per-minute").getValue(), "4", "240 an hour is 4 a minute");
  assert.equal(await browser.$("#vt-per-day").getValue(), "500");
  await browser.$("#vt-save").click();
  await browser.waitUntil(() => hidden("vt-setup-overlay"), { timeout: 5000, timeoutMsg: "setup did not close" });
  await browser.$("#settings-close").click();
  await chipIs(notepad, "0/70", "ok");
  await chipIs(curl, "3/70", "bad");
  await chipIs(marker, "n/a", "muted");
  await browser.execute((want) => {
    [...document.querySelectorAll("button.vt-chip")].find((el) => (el.dataset.path ?? "").toLowerCase() === want.toLowerCase())?.click();
  }, curl);
  await browser.waitUntil(async () => (await browser.$("#vt-details-summary").getText()).startsWith("3 of 70"),
    { timeout: 5000, timeoutMsg: "the details dialog did not open" });
  assert.equal(await browser.execute(() => document.querySelectorAll("#vt-details-names li").length), 4);
  await browser.$("#vt-details-close").click();
  const everything = await invoke("app_state");
  assert.equal(JSON.stringify(everything.value).includes(goodKey), false, "the key must never reach the window");
  const sealed = readFileSync(join(profile, "secrets.bin"));
  assert.equal(sealed.includes(Buffer.from(goodKey)), false, "the key must be sealed, not written in the clear");
  const calls = lookups();
  assert.ok(calls >= 2, `expected lookups for curl and notepad, saw ${calls}`);

  await statusIs("Nothing blocked yet", "the header did not start empty");
  assert.equal(await clickPath(notepad), true, "notepad was not in the list");
  await browser.waitUntil(() => pressed(notepad), { timeout: 10000, timeoutMsg: "notepad did not move to Blocked" });
  assert.equal(notepadRule()?.outbound_enabled, true, "blocking notepad must write an enabled rule");
  await statusIs("Blocking 1 program", "the header did not report the block");

  await browser.$("#suspend").click();
  await statusIs("All blocks are off", "turning all blocks off did not show");
  assert.equal(notepadRule()?.outbound_enabled, false, "turning all blocks off must disable the rule, not delete it");
  await browser.$("#suspend").click();
  await statusIs("Blocking 1 program", "turning blocks back on did not show");
  assert.equal(notepadRule()?.outbound_enabled, true, "turning blocks back on must enable the rule");

  // Block All asks first, then cuts everything off; it is kept across a restart.
  const blockAllOn = () => {
    const flag = join(profile, "fake-block-all.json");
    return existsSync(flag) && JSON.parse(readFileSync(flag, "utf8")) === true;
  };
  await browser.$("#block-all").click();
  await browser.waitUntil(async () => (await browser.$("#confirm-title").getText()) === "Block all internet access?",
    { timeout: 5000, timeoutMsg: "Block all did not ask first" });
  assert.equal(blockAllOn(), false, "nothing is blocked before the owner says yes");
  await browser.$("#confirm-yes").click();
  await statusIs("All internet access blocked", "Block all did not show");
  assert.equal(blockAllOn(), true, "Block all must add its rules");
  assert.equal(await browser.$("#block-all-text").getText(), "Allow internet");

  // A logon start passes --hidden: the app runs in the tray and the window stays closed.
  await exitApp();
  await connect(["--hidden"]);
  const visible = await invoke("plugin:window|is_visible", { label: "main" });
  assert.equal(visible.ok, true, `could not ask whether the window is visible: ${visible.message}`);
  assert.equal(visible.value, false, "a --hidden start must leave the window closed");
  await browser.waitUntil(() => pressed(notepad), { timeout: 10000, timeoutMsg: "the block did not survive a restart" });
  await statusIs("All internet access blocked", "Block all did not survive a restart");
  const allowed = await invoke("set_block_all", { on: false });
  assert.equal(allowed.ok, true, `turning Block all off failed: ${allowed.message}`);
  assert.equal(blockAllOn(), false, "turning Block all off must remove its rules");
  await statusIs("Blocking 1 program", "the header did not come back after Block all");
  await chipIs(curl, "3/70", "bad");
  await chipIs(notepad, "0/70", "ok");
  await new Promise((r) => setTimeout(r, 1500));
  assert.equal(lookups(), calls, "results after a restart come from the saved answers, not new lookups");
  const removed = await invoke("remove_virustotal_key");
  assert.equal(removed.ok, true, `removing the key failed: ${removed.message}`);
  assert.equal(existsSync(join(profile, "secrets.bin")), false, "removing the key deletes the sealed file");
  await browser.waitUntil(async () => (await vtChip(notepad)) === null,
    { timeout: 10000, timeoutMsg: "chips stayed after the key was removed" });
  assert.equal(await clickPath(notepad), true, "notepad was not blocked after restart");
  await browser.waitUntil(async () => !(await pressed(notepad)), { timeout: 10000, timeoutMsg: "allow did not remove the block" });
  assert.equal(notepadRule(), undefined, "allow must remove the rule");
  await statusIs("Nothing blocked yet", "the header did not clear after allow");
  await exitApp();

  assert.equal(mentionsMarker(join(profile, "settings.json")), true, "the test app must keep its state in the isolated profile");
  assert.equal(mentionsMarker(realSettings), false, "the test app must never write the installed app's settings");
  console.log("PASS: boot, search, traffic reading, VirusTotal setup and results, block, turn off and on, Block all, hidden restart, cached results, allow, denied remote open, clean exit");
} catch (error) {
  if (browser) {
    try { console.error(await browser.execute(() => document.body.innerText.slice(-4000))); } catch { /* page already gone */ }
  }
  console.error(driverLog);
  throw error;
} finally {
  try {
    await endSession();
    if (driver.exitCode === null) driver.kill();
    if (app?.pid && app.exitCode === null) {
      execFileSync("taskkill", ["/PID", String(app.pid), "/T", "/F"], { stdio: "pipe" });
    }
  } finally {
    if (policyState && existsSync(policyState)) policy("Restore");
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        rmSync(stateDir, { recursive: true, force: true });
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
  }
}
