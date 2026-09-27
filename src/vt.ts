// The VirusTotal parts of the window: the Settings section, the setup dialog
// that asks for the key and limits, and the details dialog behind each chip.
// The key goes to Rust once and is never read back.
import { invoke } from "@tauri-apps/api/core";
import { lastSeenText, vtLimits, vtLink, vtVerdict, type AppState, type Row } from "./model";

export interface VtContext {
  $: <T extends HTMLElement>(selector: string) => T;
  openDialog(overlay: HTMLElement, focus: HTMLElement): void;
  closeDialog(overlay: HTMLElement): void;
  state(): AppState | null;
  update(next: AppState): void;
  say(message: string): void;
}

interface VtQuota {
  perMinute: number;
  perDay: number;
  quotas: { daily: { allowed: number; used: number } | null };
}

export interface VtView {
  overlays: HTMLElement[];
  paint(state: AppState): void;
  openDetails(row: Row): void;
}

export function setUpVirusTotal(ctx: VtContext): VtView {
  const { $ } = ctx;
  const enabled = $<HTMLInputElement>("#vt-enabled");
  const setupOverlay = $<HTMLDivElement>("#vt-setup-overlay");
  const detailsOverlay = $<HTMLDivElement>("#vt-details-overlay");
  const form = $<HTMLFormElement>("#vt-form");
  const key = $<HTMLInputElement>("#vt-key");
  const perMinute = $<HTMLInputElement>("#vt-per-minute");
  const perDay = $<HTMLInputElement>("#vt-per-day");
  const error = $<HTMLParagraphElement>("#vt-error");
  const quotaNote = $<HTMLSpanElement>("#vt-quota-note");
  let link = "";

  function openSetup(): void {
    const summary = ctx.state()?.virustotal;
    key.value = "";
    key.placeholder = summary?.hasKey ? "Saved. Leave empty to keep it." : "64 letters and digits";
    perMinute.value = String(summary?.perMinute ?? 4);
    perDay.value = String(summary?.perDay ?? 500);
    error.textContent = "";
    quotaNote.textContent = "";
    ctx.openDialog(setupOverlay, key);
  }

  $("#vt-read-limits").addEventListener("click", async () => {
    quotaNote.textContent = "Asking VirusTotal…";
    try {
      const answer = await invoke<VtQuota>("virustotal_quota", { key: key.value.trim() || null });
      perMinute.value = String(answer.perMinute);
      perDay.value = String(answer.perDay);
      const daily = answer.quotas.daily;
      quotaNote.textContent = daily
        ? `VirusTotal says this key allows ${daily.allowed} a day (${daily.used} used today).`
        : "Filled in from VirusTotal.";
    } catch (err) {
      quotaNote.textContent = String(err);
    }
  });

  enabled.addEventListener("change", async () => {
    const summary = ctx.state()?.virustotal;
    if (enabled.checked && !summary?.hasKey) {
      enabled.checked = false;
      openSetup();
      return;
    }
    try {
      ctx.update(await invoke<AppState>("set_virustotal", { enabled: enabled.checked }));
      ctx.say(enabled.checked ? "VirusTotal checks are on." : "VirusTotal checks are off.");
    } catch (err) {
      ctx.say(String(err));
      enabled.checked = Boolean(summary?.enabled);
    }
  });

  $("#vt-change").addEventListener("click", openSetup);
  $("#vt-remove").addEventListener("click", async () => {
    try {
      ctx.update(await invoke<AppState>("remove_virustotal_key"));
      ctx.say("The VirusTotal key is removed and the check is off.");
    } catch (err) {
      ctx.say(String(err));
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const limits = vtLimits(perMinute.value, perDay.value);
    if (typeof limits === "string") {
      error.textContent = limits;
      return;
    }
    const typed = key.value.trim();
    try {
      const next = await invoke<AppState>("configure_virustotal", { key: typed || null, ...limits });
      key.value = "";
      ctx.closeDialog(setupOverlay);
      ctx.update(next);
      ctx.say("VirusTotal checks are on. Results appear beside each program as they arrive.");
    } catch (err) {
      error.textContent = String(err);
    }
  });
  $("#vt-cancel").addEventListener("click", () => {
    key.value = "";
    ctx.closeDialog(setupOverlay);
  });

  function openDetails(row: Row): void {
    const vt = row.virustotal;
    const url = vt ? vtLink(vt.sha256) : null;
    if (!vt || !url || (vt.state !== "found" && vt.state !== "unknown")) return;
    link = url;
    $("#vt-details-title").textContent = `VirusTotal: ${row.name}`;
    $("#vt-details-summary").textContent = vtVerdict(vt);
    const names = $<HTMLUListElement>("#vt-details-names");
    names.replaceChildren(
      ...vt.names.map((name) => {
        const item = document.createElement("li");
        item.textContent = name;
        return item;
      }),
    );
    names.hidden = vt.names.length === 0;
    const seen = vt.checkedAt == null ? "" : lastSeenText(vt.checkedAt, Date.now() / 1000);
    $("#vt-details-checked").textContent = seen ? `Checked ${seen}. SHA-256:` : "SHA-256:";
    $("#vt-details-sha").textContent = vt.sha256;
    $("#vt-details-msg").textContent = "";
    ctx.openDialog(detailsOverlay, $("#vt-details-close"));
  }

  $("#vt-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(link).then(
      () => ($("#vt-details-msg").textContent = "Report link copied. Paste it into your browser."),
      () => ($("#vt-details-msg").textContent = "Could not copy. Select the hash above instead."),
    );
  });
  $("#vt-details-close").addEventListener("click", () => ctx.closeDialog(detailsOverlay));

  function paint(state: AppState): void {
    const summary = state.virustotal;
    enabled.checked = summary.enabled;
    $("#vt-configured").classList.toggle("hidden", !summary.hasKey);
    $("#vt-limits").textContent =
      `Your key: up to ${summary.perMinute} lookup${summary.perMinute === 1 ? "" : "s"} a minute and ${summary.perDay} a day.`;
    const status = $("#vt-status");
    status.textContent = summary.status;
    status.dataset.tone = summary.tone;
  }

  return { overlays: [detailsOverlay, setupOverlay], paint, openDetails };
}
