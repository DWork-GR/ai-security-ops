const messagesEl = document.getElementById("messages");

export function renderMessage(role, text) {
  const div = document.createElement("div");
  div.className = `message ${role}`;
  div.textContent = text;

  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;

  return div;
}

export function removeMessage(el) {
  el?.remove();
}
