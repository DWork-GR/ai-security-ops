const messagesEl = document.getElementById("messages");

function appendAndScroll(el) {
  messagesEl.appendChild(el);
  el.scrollIntoView({ behavior: "smooth" });
}

export function renderMessage(role, text) {
  const msg = document.createElement("div");
  msg.className = `message ${role}`;
  msg.textContent = text;
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
    cveId.textContent = cve.cve_id || "Unknown CVE";

    const description = document.createElement("div");
    description.className = "cve-description";
    description.textContent = cve.description || "No description";

    const mitigation = document.createElement("div");
    mitigation.className = "cve-mitigation";
    mitigation.textContent = `Mitigation: ${cve.mitigation || "Not provided"}`;

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
  titleEl.textContent = title;

  const content = document.createElement("div");
  content.className = "result-content";

  block.appendChild(titleEl);
  block.appendChild(content);
  appendAndScroll(block);
  return content;
}
