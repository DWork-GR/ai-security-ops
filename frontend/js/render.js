const messagesEl = document.getElementById("messages");

export function renderMessage(role, text) {
  const msg = document.createElement("div");
  msg.className = `message ${role}`;
  msg.innerText = text;

  document.getElementById("chat").appendChild(msg);
  msg.scrollIntoView({ behavior: "smooth" });

  return msg;
}

export function removeMessage(el) {
  el?.remove();
}

function renderCves(cves) {
  const container = document.getElementById("messages");

  cves.forEach(cve => {
    const card = document.createElement("div");
    card.className = `cve-card ${cve.severity.toLowerCase()}`;

    card.innerHTML = `
      <div class="cve-header">
        <span class="severity-badge ${cve.severity.toLowerCase()}">
          ${cve.severity}
        </span>
        <span class="cvss-badge">CVSS ${cve.cvss}</span>
      </div>

      <div class="cve-id">${cve.cve_id}</div>

      <div class="cve-description">
        ${cve.description}
      </div>

      <div class="cve-mitigation">
        <span>🛠 Рекомендація:</span>
        ${cve.mitigation}
      </div>
    `;

    container.appendChild(card);
  });
}
