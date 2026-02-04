import { renderMessage, removeMessage } from "./render.js";
import { sendToBackend } from "./api.js";

const input = document.getElementById("input");
const sendBtn = document.getElementById("send");

async function handleSend() {
  const text = input.value.trim();
  if (!text) return;

  input.value = "";

  renderMessage("user", text);

  const loader = renderMessage("system", "⏳ Аналіз запиту...");

  try {
    const data = await sendToBackend(text);
    removeMessage(loader);

    if (data.cves) {
      // дальше красиво карточками
    } else {
      renderMessage("bot", data.response);
    }

  } catch (err) {
    removeMessage(loader);
    renderMessage("error", "❌ Помилка зʼєднання з бекендом");
  }
}

sendBtn.addEventListener("click", handleSend);
input.addEventListener("keydown", e => {
  if (e.key === "Enter") handleSend();
});
