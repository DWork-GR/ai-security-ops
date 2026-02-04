document.getElementById("sendBtn").onclick = async () => {
  const input = document.getElementById("userInput");
  const text = input.value;
  input.value = "";

  renderCard("⏳ Аналіз запиту", "Система обробляє дані…");

  const data = await sendToBackend(text);

  renderCard("📊 Результат", data.response);
};
