import { renderMessage, removeMessage } from "./render.js";
import { sendToApi } from "./api.js";

const input = document.getElementById("chatInput");
const btn = document.getElementById("sendBtn");

btn.onclick = send;
input.onkeydown = e => e.key === "Enter" && send();

async function send() {
  const text = input.value.trim();
  if (!text) return;

  renderMessage("user", text);
  input.value = "";

  const thinking = renderMessage("system", "⏳ Аналіз запиту…");

  const response = await sendToApi(text);

  removeMessage(thinking);
  renderMessage("assistant", response);
}
