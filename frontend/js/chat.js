import {
  renderMessage,
  removeMessage,
  renderCves,
  renderDiscoveredAssets,
  renderLiveFeed,
  renderScanJobs,
} from "./render.js";
import {
  createScanJob,
  getApiBase,
  getUserKey,
  listDiscoveredAssets,
  listScanJobs,
  seedRealWorldThreats,
  sendToBackend,
  setUserKey,
} from "./api.js";
import {
  applyUiTranslations,
  getLang,
  localizeAssistantText,
  localizeStatusToken,
  setLang,
  t,
} from "./i18n.js";

const input = document.getElementById("input");
const form = document.getElementById("chat-form");
const sendBtn = document.getElementById("send-btn");
const quickActionsEl = document.getElementById("quick-actions");
const scanTargetInput = document.getElementById("scan-target");
const userKeyInput = document.getElementById("user-key");
const scanControlsEl = document.getElementById("scan-controls");
const scanJobsEl = document.getElementById("scan-jobs");
const discoveredAssetsEl = document.getElementById("discovered-assets");
const seedThreatPackBtn = document.getElementById("seed-threat-pack");
const liveFeedEl = document.getElementById("live-feed");
const socStatusEl = document.getElementById("soc-connection-status");
const langSelectEl = document.getElementById("lang-select");
let scanJobsTimerId = null;
let discoveredAssetsTimerId = null;
let socStream = null;
let socReconnectTimerId = null;
let streamFirstSnapshotReceived = false;
let latestCriticalIncidentId = null;
let scanAuthWarningShown = false;
let discoveredAssetsAuthWarningShown = false;

function localizeScanType(scanType) {
  const key = `ui_scan_${String(scanType || "").toLowerCase()}`;
  const translated = t(key);
  if (translated === key) {
    return String(scanType || "").toUpperCase();
  }
  const mode = getLang();
  if (mode === "en") {
    return translated.toUpperCase();
  }
  return translated;
}

async function handleSend(forcedText = null) {
  if (!input) return;

  const text = (forcedText ?? input.value).trim();
  if (!text) return;

  input.value = "";
  renderMessage("user", text);
  const loader = renderMessage("system", t("chat_analyzing"));

  try {
    const data = await sendToBackend(text);
    removeMessage(loader);

    if (data.type === "cves") {
      renderCves(data.cves || []);
      return;
    }

    if (data.type === "text") {
      renderMessage("assistant", localizeAssistantText(data.message || t("chat_no_message")));
      return;
    }

    renderMessage("error", t("chat_unknown_format"));
  } catch (err) {
    removeMessage(loader);
    renderMessage("error", `${t("chat_connection_error")}: ${String(err.message || err)}`);
  }
}

function getScanTarget() {
  const raw = (scanTargetInput?.value || "").trim();
  return raw || "127.0.0.1";
}

async function refreshScanJobs() {
  if (!scanJobsEl) return;
  try {
    const payload = await listScanJobs({ limit: 8 });
    renderScanJobs(scanJobsEl, payload.items || []);
    scanAuthWarningShown = false;
  } catch (err) {
    if (err && err.status === 401) {
      renderScanJobs(scanJobsEl, []);
      if (scanJobsTimerId) {
        window.clearInterval(scanJobsTimerId);
        scanJobsTimerId = null;
      }
      if (!scanAuthWarningShown) {
        renderMessage(
          "error",
          t("chat_rbac_scan_jobs"),
        );
        scanAuthWarningShown = true;
      }
      return;
    }
    renderScanJobs(scanJobsEl, []);
  }
}

function startScanJobsPolling() {
  if (!scanJobsEl || scanJobsTimerId) return;
  refreshScanJobs();
  scanJobsTimerId = window.setInterval(refreshScanJobs, 3000);
}

async function refreshDiscoveredAssets() {
  if (!discoveredAssetsEl) return;
  try {
    const payload = await listDiscoveredAssets({ limit: 12 });
    renderDiscoveredAssets(discoveredAssetsEl, payload.items || []);
    discoveredAssetsAuthWarningShown = false;
  } catch (err) {
    if (err && err.status === 401) {
      renderDiscoveredAssets(discoveredAssetsEl, []);
      if (discoveredAssetsTimerId) {
        window.clearInterval(discoveredAssetsTimerId);
        discoveredAssetsTimerId = null;
      }
      if (!discoveredAssetsAuthWarningShown) {
        renderMessage(
          "error",
          t("chat_rbac_assets"),
        );
        discoveredAssetsAuthWarningShown = true;
      }
      return;
    }
    renderDiscoveredAssets(discoveredAssetsEl, []);
  }
}

function startDiscoveredAssetsPolling() {
  if (!discoveredAssetsEl || discoveredAssetsTimerId) return;
  refreshDiscoveredAssets();
  discoveredAssetsTimerId = window.setInterval(refreshDiscoveredAssets, 5000);
}

function stopPollingFallbacks() {
  if (scanJobsTimerId) {
    window.clearInterval(scanJobsTimerId);
    scanJobsTimerId = null;
  }
  if (discoveredAssetsTimerId) {
    window.clearInterval(discoveredAssetsTimerId);
    discoveredAssetsTimerId = null;
  }
}

function ensurePollingFallbacks() {
  startScanJobsPolling();
  startDiscoveredAssetsPolling();
}

function setSocStatus(mode, label) {
  if (!socStatusEl) return;
  socStatusEl.classList.remove("connecting", "degraded");
  if (mode === "connecting") socStatusEl.classList.add("connecting");
  if (mode === "degraded") socStatusEl.classList.add("degraded");
  socStatusEl.textContent = label || t("status_connected");
}

function maybeNotifyCritical(incidents) {
  if (!Array.isArray(incidents) || incidents.length === 0) return;
  const critical = incidents.find((item) => String(item.severity || "").toUpperCase() === "CRITICAL");
  if (!critical || !critical.id) return;
  if (latestCriticalIncidentId === critical.id) return;

  if (streamFirstSnapshotReceived) {
    const details = localizeAssistantText(critical.message || t("chat_live_no_details"));
    renderMessage(
      "assistant",
      `${t("chat_live_alert")}\n${t("chat_live_critical")} ${critical.source || t("render_unknown")}\n${details}`,
    );
  }
  latestCriticalIncidentId = critical.id;
}

function connectSocStream() {
  if (socReconnectTimerId) {
    window.clearTimeout(socReconnectTimerId);
    socReconnectTimerId = null;
  }
  if (socStream) {
    socStream.close();
    socStream = null;
  }

  const userKey = getUserKey();
  if (userKey) {
    // Browser EventSource cannot set custom auth headers.
    // To avoid leaking keys in URL query, switch to authenticated polling endpoints.
    setSocStatus("degraded", t("status_fallback"));
    ensurePollingFallbacks();
    return;
  }

  const query = new URLSearchParams({ limit: "8", interval_sec: "3" });

  const streamUrl = `${getApiBase()}/stream/soc-live?${query.toString()}`;
  setSocStatus("connecting", t("status_connecting"));

  const stream = new EventSource(streamUrl);
  socStream = stream;

  stream.addEventListener("snapshot", (event) => {
    try {
      const payload = JSON.parse(event.data || "{}");
      renderScanJobs(scanJobsEl, payload.scan_jobs || []);
      renderDiscoveredAssets(discoveredAssetsEl, payload.assets || []);
      renderLiveFeed(liveFeedEl, payload.incidents || [], payload.errors || []);
      maybeNotifyCritical(payload.incidents || []);
      streamFirstSnapshotReceived = true;
      stopPollingFallbacks();
    } catch (_) {
      // Ignore malformed snapshot event.
    }
  });

  stream.onopen = () => {
    setSocStatus("", t("status_live"));
  };

  stream.onerror = () => {
    if (socStream) {
      socStream.close();
      socStream = null;
    }
    setSocStatus("degraded", t("status_fallback"));
    ensurePollingFallbacks();
    if (!socReconnectTimerId) {
      socReconnectTimerId = window.setTimeout(connectSocStream, 3500);
    }
  };
}

async function handleScanJobTrigger(scanType) {
  const targetIp = getScanTarget();
  const loader = renderMessage("system", `${t("chat_queueing_scan")}: ${localizeScanType(scanType)} ${targetIp}...`);
  try {
    const job = await createScanJob(targetIp, scanType);
    removeMessage(loader);
    renderMessage(
      "assistant",
      `${t("chat_scan_queued")}: ${localizeScanType(job.scan_type)} ${job.target_ip}\n${t("chat_scan_job_id")}: ${job.id}\n${t("chat_scan_status")}: ${localizeStatusToken(job.status) || job.status}`,
    );
    refreshScanJobs();
  } catch (err) {
    removeMessage(loader);
    if (err && err.status === 401) {
      renderMessage(
        "error",
        t("chat_scan_unauthorized"),
      );
      return;
    }
    renderMessage("error", `${t("chat_scan_failed")}: ${String(err.message || err)}`);
  }
}

async function handleSeedThreatPack() {
  const loader = renderMessage("system", t("chat_seed_loading"));
  try {
    const result = await seedRealWorldThreats();
    removeMessage(loader);
    renderMessage(
      "assistant",
      `${t("chat_seed_header")}\n${t("chat_seed_pack_loaded")}: ${result.source}\n${t("chat_seed_imported")}: ${result.imported_total}\n${t("chat_seed_created")}: ${result.created}\n${t("chat_seed_updated")}: ${result.updated}`,
    );
  } catch (err) {
    removeMessage(loader);
    if (err && err.status === 401) {
      renderMessage("error", t("chat_seed_unauthorized"));
      return;
    }
    if (err && err.status === 403) {
      renderMessage("error", t("chat_seed_forbidden"));
      return;
    }
    renderMessage("error", `${t("chat_seed_failed")}: ${String(err.message || err)}`);
  }
}

if (sendBtn) {
  sendBtn.onclick = handleSend;
}

if (form) {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    handleSend();
  });
}

if (quickActionsEl) {
  quickActionsEl.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const action = target.closest("[data-prompt]");
    if (!(action instanceof HTMLElement)) return;
    const prompt = action.dataset.prompt;
    if (!prompt) return;
    handleSend(prompt);
  });
}

if (scanControlsEl) {
  scanControlsEl.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const action = target.closest("[data-scan-type]");
    if (!(action instanceof HTMLElement)) return;
    const scanType = action.dataset.scanType;
    if (!scanType) return;
    handleScanJobTrigger(scanType);
  });
}

if (userKeyInput) {
  userKeyInput.value = getUserKey();
  userKeyInput.addEventListener("change", () => {
    setUserKey(userKeyInput.value);
    scanAuthWarningShown = false;
    discoveredAssetsAuthWarningShown = false;
    streamFirstSnapshotReceived = false;
    startScanJobsPolling();
    refreshScanJobs();
    startDiscoveredAssetsPolling();
    refreshDiscoveredAssets();
    connectSocStream();
  });
}

if (langSelectEl) {
  langSelectEl.value = getLang();
  langSelectEl.addEventListener("change", () => {
    setLang(langSelectEl.value);
    applyUiTranslations();
    setSocStatus("", t("status_connected"));
    connectSocStream();
  });
}

if (seedThreatPackBtn) {
  seedThreatPackBtn.addEventListener("click", () => {
    handleSeedThreatPack();
  });
}

startScanJobsPolling();
startDiscoveredAssetsPolling();
applyUiTranslations();
connectSocStream();

if (document.getElementById("messages")?.children.length === 0) {
  renderMessage(
    "assistant",
    t("chat_workspace_ready"),
  );
}
