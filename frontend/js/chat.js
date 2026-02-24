import { renderMessage, removeMessage, renderCves } from "./render.js";
import { sendToBackend } from "./api.js";

const input = document.getElementById("input");
const form = document.getElementById("chat-form");
const sendBtn = document.getElementById("send-btn");
const quickActionsEl = document.getElementById("quick-actions");

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
    const prompt = target.dataset.prompt;
    if (!prompt) return;
    handleSend(prompt);
  });
}
