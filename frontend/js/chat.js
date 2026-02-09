import { renderMessage, removeMessage, renderCves } from "./render.js";
import { sendToBackend } from "./api.js";

const input = document.getElementById("input");
const form = document.getElementById("chat-form");
const sendBtn = document.getElementById("send-btn");

if (!input || !sendBtn || !form) {
  console.error("Chat DOM not found", { input, sendBtn, form });
}

async function handleSend() {
  console.log("HANDLE SEND CALLED");

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

form.addEventListener("submit", e => {
  e.preventDefault();
  handleSend();
});
