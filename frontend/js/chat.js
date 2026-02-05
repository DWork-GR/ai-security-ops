import { renderMessage, removeMessage } from "./render.js";
import { sendToBackend } from "./api.js";

const input = document.getElementById("input");
const sendBtn = document.getElementById("send");
const form = document.getElementById("chat-form");

if (!input || !sendBtn || !form) {
  console.error("Chat DOM not found");
}

let busy = false;

async function handleSend() {
  if (busy) return;

  const text = input.value.trim();
  if (!text) return;

  busy = true;
  input.value = "";

  renderMessage("user", text);

  const loader = renderMessage("system", "⏳ Аналіз запиту...");

  try {
    const data = await sendToBackend(text);
    removeMessage(loader);

    if (data.cves) {
      // TODO: renderCveCards(data.cves)
    } else {
      renderMessage("bot", data.response);
    }

  } catch (err) {
    removeMessage(loader);
    renderMessage("error", "❌ Помилка зʼєднання з бекендом");
  } finally {
    busy = false;
  }
}

form.addEventListener("submit", e => {
  e.preventDefault();
  handleSend();
});
