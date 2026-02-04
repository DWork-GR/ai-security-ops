function renderCard(title, text, level = "") {
  const div = document.createElement("div");
  div.className = `card ${level}`;

  div.innerHTML = `
    <div class="card-title">${title}</div>
    <div class="card-text">${text}</div>
  `;

  document.getElementById("messages").appendChild(div);
}
