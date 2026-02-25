const API_BASE = window.API_BASE_URL || "http://127.0.0.1:8000";
const USER_KEY_STORAGE = "soc_user_key";

export function getApiBase() {
  return API_BASE;
}

export function getUserKey() {
  const fromWindow = typeof window.USER_API_KEY === "string" ? window.USER_API_KEY.trim() : "";
  if (fromWindow) return fromWindow;
  const fromStorage = window.localStorage.getItem(USER_KEY_STORAGE) || "";
  return fromStorage.trim();
}

export function setUserKey(value) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    window.localStorage.removeItem(USER_KEY_STORAGE);
    return;
  }
  window.localStorage.setItem(USER_KEY_STORAGE, normalized);
}

async function request(path, options = {}) {
  const userKey = getUserKey();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (userKey) {
    headers["X-User-Key"] = userKey;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let detail = "";
    try {
      const parsed = await res.json();
      detail = parsed?.detail ? String(parsed.detail) : "";
    } catch (_) {
      detail = "";
    }
    const error = new Error(detail ? `Backend error: ${res.status} (${detail})` : `Backend error: ${res.status}`);
    error.status = res.status;
    error.detail = detail;
    throw error;
  }

  return res.json();
}

export async function sendToBackend(message) {
  return request("/chat", {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

export async function createScanJob(targetIp, scanType) {
  return request("/scans/jobs", {
    method: "POST",
    body: JSON.stringify({
      target_ip: targetIp,
      scan_type: scanType,
    }),
  });
}

export async function listScanJobs(params = {}) {
  const query = new URLSearchParams();
  if (params.limit) query.set("limit", String(params.limit));
  if (params.status) query.set("status", params.status);
  if (params.scanType) query.set("scan_type", params.scanType);
  if (params.targetIp) query.set("target_ip", params.targetIp);

  const suffix = query.toString() ? `?${query.toString()}` : "";
  return request(`/scans/jobs${suffix}`, { method: "GET" });
}

export async function listDiscoveredAssets(params = {}) {
  const query = new URLSearchParams();
  if (params.limit) query.set("limit", String(params.limit));
  if (params.search) query.set("search", params.search);
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return request(`/assets/discovered${suffix}`, { method: "GET" });
}

export async function seedRealWorldThreats() {
  return request("/knowledge/cves/seed/real-world", { method: "POST" });
}

