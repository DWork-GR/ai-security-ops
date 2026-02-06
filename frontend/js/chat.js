import { renderMessage, removeMessage, renderCves } from "./render.js";
import { sendToBackend } from "./api.js";

const input = document.getElementById("chat-input");
const form = document.getElementById("chat-form");

if (!input || !sendBtn || !form) {
  console.error("Chat DOM not found");
}

let busy = false;

import { renderMessage, removeMessage, renderCves } from "./render.js";
import { sendToBackend } from "./api.js";

async function handleSend() {
  const text = input.value.trim();
  if (!text) return;

  input.value = "";
  renderMessage("user", text);

  const loader = renderMessage("system", "⏳ Аналіз запиту...");

  try {
    const data = await sendToBackend(text);
    removeMessage(loader);

    if (data.type === "cves") {
      renderCves(data.cves);
    } else if (data.type === "text") {
      renderMessage("bot", data.message);
    } else {
      renderMessage("error", "❌ Невідомий формат відповіді");
    }

  } catch (err) {
    removeMessage(loader);
    renderMessage("error", "❌ Помилка зʼєднання з бекендом");
  }
}

sendBtn.onclick = handleSend;
input.addEventListener("keydown", e => {
  if (e.key === "Enter") handleSend();
});


form.addEventListener("submit", e => {
  e.preventDefault();
  handleSend();
});
