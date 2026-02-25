import { localizeStatusToken, t } from "./i18n.js";

const messagesEl = document.getElementById("messages");

function appendAndScroll(el) {
  messagesEl.appendChild(el);
  el.scrollIntoView({ behavior: "smooth" });
}

function appendTextNode(parent, value) {
  if (!value) return;
  parent.appendChild(document.createTextNode(value));
}

function appendLinks(parent, text) {
  const linkRegex = /(https?:\/\/[^\s]+|www\.[^\s]+)/gi;
  let cursor = 0;
  let match = linkRegex.exec(text);

  while (match) {
    const raw = match[0];
    const start = match.index;
    appendTextNode(parent, text.slice(cursor, start));

    let clean = raw;
    let trailing = "";
    while (/[),.!?:;]$/.test(clean)) {
      trailing = clean.slice(-1) + trailing;
      clean = clean.slice(0, -1);
    }

    const anchor = document.createElement("a");
    anchor.className = "msg-link";
    anchor.target = "_blank";
    anchor.rel = "noopener noreferrer nofollow";
    anchor.href = clean.startsWith("http") ? clean : `https://${clean}`;
    anchor.textContent = clean;
    parent.appendChild(anchor);
    appendTextNode(parent, trailing);

    cursor = start + raw.length;
    match = linkRegex.exec(text);
  }

  appendTextNode(parent, text.slice(cursor));
}

function appendBoldAndLinks(parent, text) {
  const boldRegex = /\*\*([^*]+)\*\*/g;
  let cursor = 0;
  let match = boldRegex.exec(text);

  while (match) {
    const start = match.index;
    appendLinks(parent, text.slice(cursor, start));

    const strong = document.createElement("strong");
    appendLinks(strong, match[1]);
    parent.appendChild(strong);

    cursor = start + match[0].length;
    match = boldRegex.exec(text);
  }

  appendLinks(parent, text.slice(cursor));
}

function appendInline(parent, text) {
  const codeRegex = /`([^`\n]+)`/g;
  let cursor = 0;
  let match = codeRegex.exec(text);

  while (match) {
    const start = match.index;
    appendBoldAndLinks(parent, text.slice(cursor, start));

    const code = document.createElement("code");
    code.className = "msg-code-inline";
    code.textContent = match[1];
    parent.appendChild(code);

    cursor = start + match[0].length;
    match = codeRegex.exec(text);
  }

  appendBoldAndLinks(parent, text.slice(cursor));
}

function normalizeTableCandidate(line) {
  const trimmed = String(line || "").trim();
  return trimmed
    .replace(/^[-*]\s+/, "")
    .replace(/^\d+\.\s+/, "")
    .trim();
}

function isTableCandidateLine(line) {
  const normalized = normalizeTableCandidate(line);
  if (!normalized.includes("|")) return false;
  const cells = normalized
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((part) => part.trim());
  return cells.length >= 2;
}

function parseTableRow(line) {
  const normalizedCandidate = normalizeTableCandidate(line);
  const normalized = normalizedCandidate.replace(/^\|/, "").replace(/\|$/, "");
  const cells = normalized.split("|").map((part) => part.trim());
  return cells.filter((cell, index) => !(index === cells.length - 1 && cell === ""));
}

function isSeparatorCell(cell) {
  const normalized = String(cell || "").trim();
  if (!normalized) return false;
  return /^:?-{3,}:?$/.test(normalized);
}

function isSeparatorRow(cells) {
  if (!Array.isArray(cells) || cells.length === 0) return false;
  return cells.every((cell) => isSeparatorCell(cell));
}

function appendTable(root, tableLines) {
  const parsedRows = tableLines
    .map((line) => parseTableRow(line))
    .filter((cells) => cells.length >= 2);

  if (parsedRows.length < 2) {
    return false;
  }

  let headerCells = null;
  let bodyStartIndex = 0;

  if (parsedRows.length >= 2 && isSeparatorRow(parsedRows[1])) {
    headerCells = parsedRows[0];
    bodyStartIndex = 2;
  }

  const tableWrap = document.createElement("div");
  tableWrap.className = "msg-table-wrap";

  const table = document.createElement("table");
  table.className = "msg-table";

  if (headerCells) {
    const thead = document.createElement("thead");
    const tr = document.createElement("tr");
    headerCells.forEach((cell) => {
      const th = document.createElement("th");
      appendInline(th, cell);
      tr.appendChild(th);
    });
    thead.appendChild(tr);
    table.appendChild(thead);
  }

  const tbody = document.createElement("tbody");
  for (let r = bodyStartIndex; r < parsedRows.length; r += 1) {
    const row = parsedRows[r];
    const tr = document.createElement("tr");
    row.forEach((cell) => {
      const td = document.createElement("td");
      appendInline(td, cell);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }

  if (tbody.children.length === 0) {
    return false;
  }

  table.appendChild(tbody);
  tableWrap.appendChild(table);
  root.appendChild(tableWrap);
  return true;
}

function renderRichAssistantText(text) {
  const root = document.createElement("div");
  root.className = "message-rich";

  const lines = String(text || "")
    .replace(/\r/g, "")
    .split("\n");

  let i = 0;
  let previousWasGap = false;

  while (i < lines.length) {
    const rawLine = lines[i];
    const line = rawLine.trim();

    if (!line) {
      if (!previousWasGap) {
        const gap = document.createElement("div");
        gap.className = "msg-gap";
        root.appendChild(gap);
      }
      previousWasGap = true;
      i += 1;
      continue;
    }

    previousWasGap = false;

    if (line.startsWith("```")) {
      const blockLines = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        blockLines.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) {
        i += 1;
      }

      const pre = document.createElement("pre");
      pre.className = "msg-codeblock";
      pre.textContent = blockLines.join("\n");
      root.appendChild(pre);
      continue;
    }

    const headingMatch = line.match(/^(#{1,3})\s+(.+)$/);
    if (headingMatch) {
      const heading = document.createElement("div");
      heading.className = "msg-heading";
      heading.dataset.level = String(headingMatch[1].length);
      appendInline(heading, headingMatch[2]);
      root.appendChild(heading);
      i += 1;
      continue;
    }

    if (/^\[[^\]]+\]$/.test(line)) {
      const chip = document.createElement("div");
      chip.className = "msg-section";
      chip.textContent = line.slice(1, -1);
      root.appendChild(chip);
      i += 1;
      continue;
    }

    if (isTableCandidateLine(line)) {
      const tableLines = [];
      while (i < lines.length) {
        const probeRaw = lines[i].trim();
        if (!probeRaw || !isTableCandidateLine(probeRaw)) break;
        tableLines.push(lines[i]);
        i += 1;
      }

      if (appendTable(root, tableLines)) {
        continue;
      }

      const fallback = document.createElement("p");
      fallback.className = "msg-p";
      appendInline(fallback, tableLines.join("\n"));
      root.appendChild(fallback);
      continue;
    }

    if (/^[-*]\s+/.test(line)) {
      const list = document.createElement("ul");
      list.className = "msg-list";
      while (i < lines.length) {
        const itemLine = lines[i].trim();
        const itemMatch = itemLine.match(/^[-*]\s+(.+)$/);
        if (!itemMatch) break;
        const li = document.createElement("li");
        appendInline(li, itemMatch[1]);
        list.appendChild(li);
        i += 1;
      }
      root.appendChild(list);
      continue;
    }

    if (/^\d+\.\s+/.test(line)) {
      const list = document.createElement("ol");
      list.className = "msg-olist";
      while (i < lines.length) {
        const itemLine = lines[i].trim();
        const itemMatch = itemLine.match(/^\d+\.\s+(.+)$/);
        if (!itemMatch) break;
        const li = document.createElement("li");
        appendInline(li, itemMatch[1]);
        list.appendChild(li);
        i += 1;
      }
      root.appendChild(list);
      continue;
    }

    const kvMatch = line.match(/^([A-Za-zА-Яа-яІіЇїЄє0-9 _/()'-]{2,40}):\s+(.+)$/);
    if (kvMatch) {
      const row = document.createElement("div");
      row.className = "msg-kv";

      const key = document.createElement("span");
      key.className = "msg-k";
      key.textContent = `${kvMatch[1]}:`;

      const value = document.createElement("span");
      value.className = "msg-v";
      appendInline(value, kvMatch[2]);

      row.appendChild(key);
      row.appendChild(value);
      root.appendChild(row);
      i += 1;
      continue;
    }

    const paragraph = document.createElement("p");
    paragraph.className = "msg-p";
    appendInline(paragraph, rawLine);
    root.appendChild(paragraph);
    i += 1;
  }

  return root;
}

export function renderMessage(role, text) {
  const msg = document.createElement("div");
  msg.className = `message ${role}`;

  const content = String(text ?? "");
  if (role === "assistant") {
    msg.appendChild(renderRichAssistantText(content));
  } else {
    msg.textContent = content;
  }

  appendAndScroll(msg);
  return msg;
}

export function removeMessage(el) {
  if (el) {
    el.remove();
  }
}

export function renderCves(cves) {
  cves.forEach((cve) => {
    const card = document.createElement("div");
    card.className = `cve-card ${String(cve.severity || "unknown").toLowerCase()}`;

    const header = document.createElement("div");
    header.className = "cve-header";

    const severityBadge = document.createElement("span");
    severityBadge.className = `severity-badge ${String(cve.severity || "unknown").toLowerCase()}`;
    severityBadge.textContent = String(cve.severity || "UNKNOWN");

    const cvssBadge = document.createElement("span");
    cvssBadge.className = "cvss-badge";
    cvssBadge.textContent = `CVSS ${cve.cvss}`;

    header.appendChild(severityBadge);
    header.appendChild(cvssBadge);

    const cveId = document.createElement("div");
    cveId.className = "cve-id";
    cveId.textContent = cve.cve_id || "CVE";

    const description = document.createElement("div");
    description.className = "cve-description";
    description.textContent = cve.description || t("render_unknown");

    const mitigation = document.createElement("div");
    mitigation.className = "cve-mitigation";
    mitigation.textContent = `${t("render_mitigation")}: ${cve.mitigation || t("render_unknown")}`;

    card.appendChild(header);
    card.appendChild(cveId);
    card.appendChild(description);
    card.appendChild(mitigation);

    appendAndScroll(card);
  });
}

export function renderResultBlock(title = "Result") {
  const block = document.createElement("div");
  block.className = "result-block";

  const titleEl = document.createElement("div");
  titleEl.className = "result-title";
  titleEl.textContent = title === "Result" ? t("render_result_title") : title;

  const content = document.createElement("div");
  content.className = "result-content";

  block.appendChild(titleEl);
  block.appendChild(content);
  appendAndScroll(block);
  return content;
}

export function renderScanJobs(container, jobs) {
  if (!container) return;
  container.innerHTML = "";

  if (!Array.isArray(jobs) || jobs.length === 0) {
    const empty = document.createElement("div");
    empty.className = "scan-jobs-empty";
    empty.textContent = t("render_scan_jobs_empty");
    container.appendChild(empty);
    return;
  }

  jobs.forEach((job) => {
    const card = document.createElement("div");
    card.className = "scan-job-card";

    const top = document.createElement("div");
    top.className = "scan-job-top";

    const left = document.createElement("div");
    left.className = "scan-job-type";
    const scanTypeKey = `ui_scan_${String(job.scan_type || "").toLowerCase()}`;
    const scanTypeLabel = t(scanTypeKey) === scanTypeKey
      ? String(job.scan_type || "").toUpperCase()
      : t(scanTypeKey);
    left.textContent = `${scanTypeLabel} | ${job.target_ip}`;

    const status = document.createElement("span");
    status.className = `scan-job-status ${String(job.status || "queued").toLowerCase()}`;
    status.textContent = localizeStatusToken(job.status || "queued");

    top.appendChild(left);
    top.appendChild(status);

    const meta = document.createElement("div");
    meta.className = "scan-job-meta";
    meta.textContent = `${t("render_attempts")}: ${job.attempts || 0} | ${t("render_created")}: ${job.created_at || "n/a"}`;

    card.appendChild(top);
    card.appendChild(meta);

    if (job.last_error) {
      const err = document.createElement("div");
      err.className = "scan-job-error";
      err.textContent = job.last_error;
      card.appendChild(err);
    }

    if (job.result_summary) {
      const summary = document.createElement("div");
      summary.className = "scan-job-summary";
      const openPorts = Array.isArray(job.result_summary.open_ports)
        ? job.result_summary.open_ports.join(", ")
        : "";
      if (openPorts) {
        summary.textContent = `${t("render_open_ports")}: ${openPorts}`;
      } else if (Array.isArray(job.result_summary.steps)) {
        summary.textContent = `${t("render_steps")}: ${job.result_summary.steps.length}`;
      } else {
        summary.textContent = t("render_result_available");
      }
      card.appendChild(summary);
    }

    container.appendChild(card);
  });
}

function formatDateTime(value) {
  if (!value) return t("render_none");
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString();
}

export function renderDiscoveredAssets(container, assets) {
  if (!container) return;
  container.innerHTML = "";

  if (!Array.isArray(assets) || assets.length === 0) {
    const empty = document.createElement("div");
    empty.className = "scan-jobs-empty";
    empty.textContent = t("render_assets_empty");
    container.appendChild(empty);
    return;
  }

  assets.forEach((asset) => {
    const card = document.createElement("div");
    card.className = "asset-card";

    const head = document.createElement("div");
    head.className = "asset-head";

    const ip = document.createElement("div");
    ip.className = "asset-ip";
    ip.textContent = asset.ip || "n/a";

    const criticality = document.createElement("span");
    criticality.className = `asset-badge ${String(asset.criticality || "medium").toLowerCase()}`;
    criticality.textContent = String(asset.criticality || "MEDIUM").toUpperCase();

    head.appendChild(ip);
    head.appendChild(criticality);

    const host = document.createElement("div");
    host.className = "asset-meta";
    host.textContent = `${t("render_host")}: ${asset.hostname || t("render_unknown")} | ${t("render_env")}: ${asset.environment || t("render_unknown")}`;

    const portsRaw = Array.isArray(asset.latest_open_ports) ? asset.latest_open_ports : [];
    const ports = portsRaw.length ? portsRaw.join(", ") : t("render_none");

    const scan = document.createElement("div");
    scan.className = "asset-meta";
    scan.textContent = `${t("render_open_ports")}: ${ports}`;

    const time = document.createElement("div");
    time.className = "asset-meta";
    time.textContent = `${t("render_last_seen")}: ${formatDateTime(asset.last_seen_at)} | ${t("render_last_scan")}: ${formatDateTime(asset.latest_scan_at)}`;

    card.appendChild(head);
    card.appendChild(host);
    card.appendChild(scan);
    card.appendChild(time);
    container.appendChild(card);
  });
}

function compactText(value, max = 120) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}...`;
}

export function renderLiveFeed(container, incidents, errors) {
  if (!container) return;
  container.innerHTML = "";

  const rows = [];

  if (Array.isArray(incidents)) {
    incidents.forEach((item) => {
      rows.push({
        type: "incident",
        id: item.id,
        severity: String(item.severity || "MEDIUM").toUpperCase(),
        source: item.source || "unknown",
        status: item.status || "new",
        message: compactText(item.message, 130),
        at: item.detected_at || "",
        attack: item.attack_technique_id || "",
        tactic: item.attack_tactic || "",
      });
    });
  }

  if (Array.isArray(errors)) {
    errors.forEach((item) => {
      rows.push({
        type: "error",
        id: item.id,
        severity: String(item.severity || "MEDIUM").toUpperCase(),
        source: `${item.source || "app"}.${item.operation || "op"}`,
        status: `${item.error_type || "Error"} x${item.occurrences || 1}`,
        message: compactText(item.error_type || "Error event", 130),
        at: item.last_seen_at || "",
      });
    });
  }

  rows.sort((a, b) => String(b.at).localeCompare(String(a.at)));

  if (rows.length === 0) {
    const empty = document.createElement("div");
    empty.className = "scan-jobs-empty";
    empty.textContent = t("render_live_empty");
    container.appendChild(empty);
    return;
  }

  rows.slice(0, 12).forEach((item) => {
    const card = document.createElement("div");
    card.className = "feed-item";

    const top = document.createElement("div");
    top.className = "feed-top";

    const left = document.createElement("div");
    left.className = "feed-source";
    const typeLabel = item.type === "incident" ? t("render_feed_incident") : t("render_feed_error");
    left.textContent = `${typeLabel} | ${item.source}`;

    const badge = document.createElement("span");
    badge.className = `asset-badge ${String(item.severity || "medium").toLowerCase()}`;
    badge.textContent = item.severity;

    top.appendChild(left);
    top.appendChild(badge);

    const msg = document.createElement("div");
    msg.className = "asset-meta";
    msg.textContent = item.message;

    const meta = document.createElement("div");
    meta.className = "asset-meta";
    const attack = item.attack ? ` | ${item.attack}${item.tactic ? ` (${item.tactic})` : ""}` : "";
    const localizedStatus = item.type === "incident"
      ? (localizeStatusToken(item.status) || item.status)
      : item.status;
    meta.textContent = `${localizedStatus}${attack} | ${formatDateTime(item.at)}`;

    card.appendChild(top);
    card.appendChild(msg);
    card.appendChild(meta);
    container.appendChild(card);
  });
}
