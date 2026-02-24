import {
  renderMessage,
  removeMessage,
  renderCves,
  renderDiscoveredAssets,
  renderScanJobs,
} from "./render.js";
import {
  createScanJob,
  getUserKey,
  listDiscoveredAssets,
  listScanJobs,
  seedRealWorldThreats,
  sendToBackend,
  setUserKey,
} from "./api.js";

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
let scanJobsTimerId = null;
let discoveredAssetsTimerId = null;
let scanAuthWarningShown = false;
let discoveredAssetsAuthWarningShown = false;

async function handleSend(forcedText = null) {
  if (!input) return;

  const text = (forcedText ?? input.value).trim();
  if (!text) return;

  input.value = "";
  renderMessage("user", text);
  const loader = renderMessage("system", "Analyzing request...");

  try {
    const data = await sendToBackend(text);
    removeMessage(loader);

    if (data.type === "cves") {
      renderCves(data.cves || []);
      return;
    }

    if (data.type === "text") {
      renderMessage("assistant", data.message || "No message returned.");
      return;
    }

    renderMessage("error", "Unknown backend response format.");
  } catch (err) {
    removeMessage(loader);
    renderMessage("error", `Connection error: ${String(err.message || err)}`);
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
          "RBAC enabled: set 'User Key (RBAC)' in Scan Center to access scan jobs.",
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
          "RBAC enabled: set 'User Key (RBAC)' in Scan Center to access discovered devices.",
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

async function handleScanJobTrigger(scanType) {
  const targetIp = getScanTarget();
  const loader = renderMessage("system", `Queueing ${scanType} scan for ${targetIp}...`);
  try {
    const job = await createScanJob(targetIp, scanType);
    removeMessage(loader);
    renderMessage(
      "assistant",
      `Scan job queued: ${job.scan_type.toUpperCase()} ${job.target_ip}\nJob ID: ${job.id}\nStatus: ${job.status}`,
    );
    refreshScanJobs();
  } catch (err) {
    removeMessage(loader);
    if (err && err.status === 401) {
      renderMessage(
        "error",
        "Unauthorized for scan jobs. Enter valid RBAC User Key (manager/admin/analyst) in Scan Center.",
      );
      return;
    }
    renderMessage("error", `Failed to queue scan job: ${String(err.message || err)}`);
  }
}

async function handleSeedThreatPack() {
  const loader = renderMessage("system", "Importing real-world threat pack...");
  try {
    const result = await seedRealWorldThreats();
    removeMessage(loader);
    renderMessage(
      "assistant",
      `[Threat Intel]\nPack loaded: ${result.source}\nImported: ${result.imported_total}\nCreated: ${result.created}\nUpdated: ${result.updated}`,
    );
  } catch (err) {
    removeMessage(loader);
    if (err && err.status === 401) {
      renderMessage(
        "error",
        "Unauthorized. Real threat pack import requires manager/admin RBAC key.",
      );
      return;
    }
    if (err && err.status === 403) {
      renderMessage(
        "error",
        "Forbidden. Real threat pack import requires manager/admin role.",
      );
      return;
    }
    renderMessage("error", `Threat pack import failed: ${String(err.message || err)}`);
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
    startScanJobsPolling();
    refreshScanJobs();
    startDiscoveredAssetsPolling();
    refreshDiscoveredAssets();
  });
}

if (seedThreatPackBtn) {
  seedThreatPackBtn.addEventListener("click", () => {
    handleSeedThreatPack();
  });
}

startScanJobsPolling();
startDiscoveredAssetsPolling();

if (document.getElementById("messages")?.children.length === 0) {
  renderMessage(
    "assistant",
    "Workspace ready. Start with Scan Center on the left, or run a quick command from Quick Commands.",
  );
}
