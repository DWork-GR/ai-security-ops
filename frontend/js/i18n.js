const LANG_STORAGE = "soc_ui_lang";
const SUPPORTED_LANGS = new Set(["uk", "en", "duo"]);

const TEXT = {
  ui_title: { uk: "AI Security Ops", en: "AI Security Ops", duo: "AI Security Ops" },
  ui_subtitle: { uk: "Центр Керування", en: "Control Center", duo: "Центр Керування / Control Center" },
  ui_lang_label: { uk: "Мова", en: "Language", duo: "Мова / Language" },
  ui_quick_title: { uk: "Швидкі Команди", en: "Quick Commands", duo: "Швидкі Команди / Quick Commands" },
  ui_quick_subtitle: { uk: "Операції в 1 клік", en: "One click chat actions", duo: "Операції в 1 клік / One click chat actions" },
  ui_q_help: { uk: "Допомога", en: "Help", duo: "Допомога / Help" },
  ui_q_full: { uk: "Повна Перевірка", en: "Full Check", duo: "Повна Перевірка / Full Check" },
  ui_q_cve: { uk: "Критичні CVE", en: "Critical CVE", duo: "Критичні CVE / Critical CVE" },
  ui_q_inc: { uk: "Інциденти", en: "Incidents", duo: "Інциденти / Incidents" },
  ui_q_stats: { uk: "SOC Статистика", en: "SOC Stats", duo: "SOC Статистика / SOC Stats" },
  ui_q_errors: { uk: "Помилки", en: "Errors", duo: "Помилки / Errors" },
  ui_q_threats: { uk: "Аналіз Загроз", en: "Threat Analysis", duo: "Аналіз Загроз / Threat Analysis" },
  ui_q_status: { uk: "Статус Системи", en: "System Status", duo: "Статус Системи / System Status" },
  ui_q_roadmap: { uk: "План Розвитку", en: "Roadmap", duo: "План Розвитку / Roadmap" },
  ui_ti_title: { uk: "Threat Intelligence", en: "Threat Intelligence", duo: "Threat Intelligence" },
  ui_ti_subtitle: { uk: "Добірка реальних CVE", en: "Curated real CVEs", duo: "Добірка реальних CVE / Curated real CVEs" },
  ui_ti_btn: { uk: "Завантажити Пакет Реальних Загроз", en: "Load Real Threat Pack", duo: "Завантажити Пакет Реальних Загроз / Load Real Threat Pack" },
  ui_scan_title: { uk: "Центр Сканування", en: "Scan Center", duo: "Центр Сканування / Scan Center" },
  ui_scan_subtitle: { uk: "Черга та моніторинг сканів", en: "Queue and monitor scans", duo: "Черга та моніторинг сканів / Queue and monitor scans" },
  ui_target_label: { uk: "Цільовий IP", en: "Target IP", duo: "Цільовий IP / Target IP" },
  ui_rbac_label: { uk: "RBAC Ключ Користувача", en: "RBAC User Key", duo: "RBAC Ключ Користувача / RBAC User Key" },
  ui_scan_quick: { uk: "Швидкий", en: "Quick", duo: "Швидкий / Quick" },
  ui_scan_discovery: { uk: "Розвідка", en: "Discovery", duo: "Розвідка / Discovery" },
  ui_scan_vuln: { uk: "Вразливості", en: "Vulnerability", duo: "Вразливості / Vulnerability" },
  ui_scan_full: { uk: "Повний", en: "Full", duo: "Повний / Full" },
  ui_queue_title: { uk: "Жива Черга", en: "Live Queue", duo: "Жива Черга / Live Queue" },
  ui_queue_subtitle: { uk: "Оновлення кожні 3с", en: "Refresh every 3s", duo: "Оновлення кожні 3с / Refresh every 3s" },
  ui_assets_title: { uk: "Виявлені Пристрої", en: "Discovered Devices", duo: "Виявлені Пристрої / Discovered Devices" },
  ui_assets_subtitle: { uk: "Інвентаризація з реальних сканів", en: "Inventory from real scans", duo: "Інвентаризація з реальних сканів / Inventory from real scans" },
  ui_assets_view_title: { uk: "Огляд Мережевих Активів", en: "Network Asset View", duo: "Огляд Мережевих Активів / Network Asset View" },
  ui_assets_view_subtitle: { uk: "Оновлення кожні 5с", en: "Refresh every 5s", duo: "Оновлення кожні 5с / Refresh every 5s" },
  ui_live_title: { uk: "Живий SOC Потік", en: "Live SOC Feed", duo: "Живий SOC Потік / Live SOC Feed" },
  ui_live_subtitle: { uk: "Інциденти/помилки в реальному часі", en: "Real-time incidents/errors", duo: "Інциденти/помилки в реальному часі / Real-time incidents/errors" },
  ui_chat_title: { uk: "Чат Аналітика", en: "Analyst Chat", duo: "Чат Аналітика / Analyst Chat" },
  ui_chat_subtitle: { uk: "Діалог та результати розслідування", en: "Conversation and investigation output", duo: "Діалог та результати розслідування / Conversation and investigation output" },
  ui_chat_placeholder: {
    uk: "Приклад: покажи інциденти, пошук cve apache, аналіз загроз",
    en: "Example: show incidents, search cve apache, analyze threats",
    duo: "Приклад: покажи інциденти... / Example: show incidents...",
  },
  ui_send: { uk: "Надіслати", en: "Send", duo: "Надіслати / Send" },
  ui_scan_target_placeholder: { uk: "приклад: 10.0.0.5", en: "example: 10.0.0.5", duo: "приклад: 10.0.0.5 / example: 10.0.0.5" },
  ui_rbac_placeholder: {
    uk: "analyst-key / manager-key / admin-key",
    en: "analyst-key / manager-key / admin-key",
    duo: "analyst-key / manager-key / admin-key",
  },
  status_connecting: { uk: "Підключення...", en: "Connecting...", duo: "Підключення... / Connecting..." },
  status_live: { uk: "Live", en: "Live", duo: "Live" },
  status_fallback: { uk: "Резервний Режим", en: "Fallback", duo: "Резервний Режим / Fallback" },
  status_connected: { uk: "Підключено", en: "Connected", duo: "Підключено / Connected" },
  status_new: { uk: "новий", en: "new", duo: "новий / new" },
  status_triaged: { uk: "тріаж", en: "triaged", duo: "тріаж / triaged" },
  status_investigating: { uk: "розслідується", en: "investigating", duo: "розслідується / investigating" },
  status_mitigated: { uk: "пом'якшено", en: "mitigated", duo: "пом'якшено / mitigated" },
  status_closed: { uk: "закрито", en: "closed", duo: "закрито / closed" },
  status_false_positive: { uk: "хибне спрацювання", en: "false_positive", duo: "хибне спрацювання / false_positive" },
  status_queued: { uk: "в черзі", en: "queued", duo: "в черзі / queued" },
  status_running: { uk: "виконується", en: "running", duo: "виконується / running" },
  status_completed: { uk: "завершено", en: "completed", duo: "завершено / completed" },
  status_failed: { uk: "помилка", en: "failed", duo: "помилка / failed" },
  status_cancelled: { uk: "скасовано", en: "cancelled", duo: "скасовано / cancelled" },
  chat_analyzing: { uk: "Аналізую запит...", en: "Analyzing request...", duo: "Аналізую запит... / Analyzing request..." },
  chat_no_message: { uk: "Повідомлення від бекенду відсутнє.", en: "No message returned.", duo: "Повідомлення від бекенду відсутнє. / No message returned." },
  chat_unknown_format: { uk: "Невідомий формат відповіді бекенду.", en: "Unknown backend response format.", duo: "Невідомий формат відповіді бекенду. / Unknown backend response format." },
  chat_connection_error: { uk: "Помилка з'єднання", en: "Connection error", duo: "Помилка з'єднання / Connection error" },
  chat_rbac_scan_jobs: {
    uk: "RBAC увімкнено: додай ключ у полі 'RBAC User Key', щоб бачити scan jobs.",
    en: "RBAC enabled: set 'User Key (RBAC)' in Scan Center to access scan jobs.",
    duo: "RBAC увімкнено: додай ключ... / RBAC enabled: set key to access scan jobs.",
  },
  chat_rbac_assets: {
    uk: "RBAC увімкнено: додай ключ у полі 'RBAC User Key', щоб бачити активи.",
    en: "RBAC enabled: set 'User Key (RBAC)' in Scan Center to access discovered devices.",
    duo: "RBAC увімкнено: додай ключ... / RBAC enabled: set key to access discovered devices.",
  },
  chat_queueing_scan: { uk: "Додаю скан у чергу", en: "Queueing scan", duo: "Додаю скан у чергу / Queueing scan" },
  chat_scan_queued: { uk: "Скан поставлено в чергу", en: "Scan job queued", duo: "Скан поставлено в чергу / Scan job queued" },
  chat_scan_job_id: { uk: "ID Завдання", en: "Job ID", duo: "ID Завдання / Job ID" },
  chat_scan_status: { uk: "Статус", en: "Status", duo: "Статус / Status" },
  chat_scan_unauthorized: {
    uk: "Немає доступу до scan jobs. Введи валідний RBAC ключ.",
    en: "Unauthorized for scan jobs. Enter valid RBAC User Key (manager/admin/analyst) in Scan Center.",
    duo: "Немає доступу до scan jobs... / Unauthorized for scan jobs.",
  },
  chat_scan_failed: { uk: "Не вдалося поставити скан у чергу", en: "Failed to queue scan job", duo: "Не вдалося поставити скан у чергу / Failed to queue scan job" },
  chat_seed_loading: { uk: "Імпортую пакет реальних загроз...", en: "Importing real-world threat pack...", duo: "Імпортую пакет реальних загроз... / Importing real-world threat pack..." },
  chat_seed_header: { uk: "[Threat Intel]", en: "[Threat Intel]", duo: "[Threat Intel]" },
  chat_seed_pack_loaded: { uk: "Пакет завантажено", en: "Pack loaded", duo: "Пакет завантажено / Pack loaded" },
  chat_seed_imported: { uk: "Імпортовано", en: "Imported", duo: "Імпортовано / Imported" },
  chat_seed_created: { uk: "Створено", en: "Created", duo: "Створено / Created" },
  chat_seed_updated: { uk: "Оновлено", en: "Updated", duo: "Оновлено / Updated" },
  chat_seed_unauthorized: {
    uk: "Немає доступу. Для імпорту потрібна роль manager/admin.",
    en: "Unauthorized. Real threat pack import requires manager/admin RBAC key.",
    duo: "Немає доступу... / Unauthorized.",
  },
  chat_seed_forbidden: {
    uk: "Заборонено. Імпорт пакета доступний manager/admin.",
    en: "Forbidden. Real threat pack import requires manager/admin role.",
    duo: "Заборонено... / Forbidden.",
  },
  chat_seed_failed: { uk: "Помилка імпорту пакета загроз", en: "Threat pack import failed", duo: "Помилка імпорту пакета загроз / Threat pack import failed" },
  chat_live_alert: { uk: "[Live Alert]", en: "[Live Alert]", duo: "[Live Alert]" },
  chat_live_critical: { uk: "КРИТИЧНИЙ інцидент із", en: "CRITICAL incident from", duo: "КРИТИЧНИЙ інцидент із / CRITICAL incident from" },
  chat_live_no_details: { uk: "Немає деталей", en: "No details", duo: "Немає деталей / No details" },
  chat_workspace_ready: {
    uk: "Робочий простір готовий. Почни зі Scan Center ліворуч або обери швидку команду.",
    en: "Workspace ready. Start with Scan Center on the left, or run a quick command from Quick Commands.",
    duo: "Робочий простір готовий... / Workspace ready. Start with Scan Center on the left.",
  },
  render_scan_jobs_empty: { uk: "Скан-завдань поки немає.", en: "No scan jobs yet.", duo: "Скан-завдань поки немає. / No scan jobs yet." },
  render_attempts: { uk: "Спроб", en: "Attempts", duo: "Спроб / Attempts" },
  render_created: { uk: "Створено", en: "Created", duo: "Створено / Created" },
  render_open_ports: { uk: "Відкриті порти", en: "Open ports", duo: "Відкриті порти / Open ports" },
  render_steps: { uk: "Кроків", en: "Steps", duo: "Кроків / Steps" },
  render_result_available: { uk: "Результат доступний.", en: "Result available.", duo: "Результат доступний. / Result available." },
  render_assets_empty: {
    uk: "Ще немає виявлених пристроїв. Запусти скани для побудови інвентаря.",
    en: "No discovered devices yet. Run scans to build inventory.",
    duo: "Ще немає виявлених пристроїв... / No discovered devices yet.",
  },
  render_host: { uk: "Хост", en: "Host", duo: "Хост / Host" },
  render_env: { uk: "Середовище", en: "Env", duo: "Середовище / Env" },
  render_unknown: { uk: "невідомо", en: "unknown", duo: "невідомо / unknown" },
  render_none: { uk: "немає", en: "none", duo: "немає / none" },
  render_last_seen: { uk: "Остання активність", en: "Last seen", duo: "Остання активність / Last seen" },
  render_last_scan: { uk: "Останній скан", en: "Last scan", duo: "Останній скан / Last scan" },
  render_live_empty: { uk: "Живих подій поки немає.", en: "No live events yet.", duo: "Живих подій поки немає. / No live events yet." },
  render_feed_incident: { uk: "ІНЦИДЕНТ", en: "INCIDENT", duo: "ІНЦИДЕНТ / INCIDENT" },
  render_feed_error: { uk: "ПОМИЛКА", en: "ERROR", duo: "ПОМИЛКА / ERROR" },
  render_mitigation: { uk: "Рекомендація", en: "Mitigation", duo: "Рекомендація / Mitigation" },
  render_result_title: { uk: "Результат", en: "Result", duo: "Результат / Result" },
};

const UI_BINDINGS = [
  ["ui-title", "ui_title"],
  ["ui-subtitle", "ui_subtitle"],
  ["ui-lang-label", "ui_lang_label"],
  ["ui-quick-title", "ui_quick_title"],
  ["ui-quick-subtitle", "ui_quick_subtitle"],
  ["ui-q-help", "ui_q_help"],
  ["ui-q-full", "ui_q_full"],
  ["ui-q-cve", "ui_q_cve"],
  ["ui-q-inc", "ui_q_inc"],
  ["ui-q-stats", "ui_q_stats"],
  ["ui-q-errors", "ui_q_errors"],
  ["ui-q-threats", "ui_q_threats"],
  ["ui-q-status", "ui_q_status"],
  ["ui-q-roadmap", "ui_q_roadmap"],
  ["ui-ti-title", "ui_ti_title"],
  ["ui-ti-subtitle", "ui_ti_subtitle"],
  ["seed-threat-pack", "ui_ti_btn"],
  ["ui-scan-title", "ui_scan_title"],
  ["ui-scan-subtitle", "ui_scan_subtitle"],
  ["ui-target-label", "ui_target_label"],
  ["ui-rbac-label", "ui_rbac_label"],
  ["ui-scan-quick", "ui_scan_quick"],
  ["ui-scan-discovery", "ui_scan_discovery"],
  ["ui-scan-vuln", "ui_scan_vuln"],
  ["ui-scan-full", "ui_scan_full"],
  ["ui-queue-title", "ui_queue_title"],
  ["ui-queue-subtitle", "ui_queue_subtitle"],
  ["ui-assets-title", "ui_assets_title"],
  ["ui-assets-subtitle", "ui_assets_subtitle"],
  ["ui-assets-view-title", "ui_assets_view_title"],
  ["ui-assets-view-subtitle", "ui_assets_view_subtitle"],
  ["ui-live-title", "ui_live_title"],
  ["ui-live-subtitle", "ui_live_subtitle"],
  ["ui-chat-title", "ui_chat_title"],
  ["ui-chat-subtitle", "ui_chat_subtitle"],
  ["send-btn", "ui_send"],
];

function sanitizeLang(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (SUPPORTED_LANGS.has(normalized)) return normalized;
  return "uk";
}

export function getLang() {
  const fromStorage = window.localStorage.getItem(LANG_STORAGE);
  return sanitizeLang(fromStorage || "uk");
}

export function setLang(value) {
  const normalized = sanitizeLang(value);
  window.localStorage.setItem(LANG_STORAGE, normalized);
}

export function t(key) {
  const lang = getLang();
  const pack = TEXT[key];
  if (!pack) return key;
  return pack[lang] || pack.uk || key;
}

export function localizeStatusToken(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return "";
  const key = `status_${normalized}`;
  const translated = t(key);
  if (translated === key) {
    return normalized;
  }
  return translated;
}

export function applyUiTranslations() {
  UI_BINDINGS.forEach(([id, key]) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.textContent = t(key);
  });

  const input = document.getElementById("input");
  if (input) input.placeholder = t("ui_chat_placeholder");

  const target = document.getElementById("scan-target");
  if (target) target.placeholder = t("ui_scan_target_placeholder");

  const rbac = document.getElementById("user-key");
  if (rbac) rbac.placeholder = t("ui_rbac_placeholder");

  const select = document.getElementById("lang-select");
  if (select) select.value = getLang();

  const htmlLang = getLang() === "en" ? "en" : "uk";
  document.documentElement.lang = htmlLang;
}

function toUkrainianAssistantText(text) {
  let value = String(text || "");
  const replacements = [
    ["[Incidents] Latest SOC incidents:", "[Інциденти] Останні SOC-інциденти:"],
    ["[Errors] Latest error events:", "[Помилки] Останні події помилок:"],
    ["| detected_at | severity | status | source | ATT&CK | message |", "| час_виявлення | критичність | статус | джерело | ATT&CK | повідомлення |"],
    ["| detected_at | severity | status | source | message |", "| час_виявлення | критичність | статус | джерело | повідомлення |"],
    ["| last_seen_at | severity | operation | error_type | count |", "| час_останньої_помилки | критичність | операція | тип_помилки | кількість |"],
    ["No incidents found.", "Інцидентів не знайдено."],
    ["No error events found.", "Подій помилок не знайдено."],
    ["No matching CVEs found.", "Відповідних CVE не знайдено."],
    ["No critical CVEs found.", "Критичних CVE не знайдено."],
    ["No CVE records found.", "CVE записи відсутні."],
    ["Unknown backend response format.", "Невідомий формат відповіді бекенду."],
    ["[SOC KPI Snapshot]", "[SOC KPI Знімок]"],
    ["By severity:", "За критичністю:"],
    ["By source:", "За джерелом:"],
    ["By status:", "За статусом:"],
    ["[EN] Active Scan", "[EN] Активне Сканування"],
    ["- Task ID:", "- ID Завдання:"],
    ["- Target:", "- Ціль:"],
    ["- Status:", "- Статус:"],
    ["- Scan profile:", "- Профіль сканування:"],
    ["- Scanned ports:", "- Перевірено портів:"],
    ["- Open ports:", "- Відкриті порти:"],
    ["- New open ports vs baseline:", "- Нові відкриті порти (проти baseline):"],
    ["- Closed open ports vs baseline:", "- Закриті порти (проти baseline):"],
    ["- Findings:", "- Знахідок:"],
    ["- Incidents: created=", "- Інциденти: створено="],
    ["Top findings:", "Топ знахідок:"],
    ["SOC Snapshot:", "SOC Знімок:"],
    ["Ops Errors Snapshot:", "Операційні Помилки (знімок):"],
    ["Top CVEs (CVSS >= 9):", "Топ CVE (CVSS >= 9):"],
    ["No records.", "Записів немає."],
    ["Server error. Check backend logs.", "Помилка сервера. Перевір логи бекенду."],
    ["Invalid IP address.", "Некоректна IP-адреса."],
    ["IP address is missing.", "IP-адресу не вказано."],
    ["IP address is required: full check <ip>", "Потрібна IP-адреса: повна перевірка <ip>"],
    ["CVE identifier is missing.", "Ідентифікатор CVE відсутній."],
    ["No message returned.", "Повідомлення від бекенду відсутнє."],
  ];

  replacements.forEach(([from, to]) => {
    value = value.split(from).join(to);
  });

  const regexReplacements = [
    [/\bCRITICAL\b/g, "КРИТИЧНИЙ"],
    [/\bHIGH\b/g, "ВИСОКИЙ"],
    [/\bMEDIUM\b/g, "СЕРЕДНІЙ"],
    [/\bLOW\b/g, "НИЗЬКИЙ"],
    [/\bnew\b/g, "новий"],
    [/\btriaged\b/g, "тріаж"],
    [/\binvestigating\b/g, "розслідується"],
    [/\bmitigated\b/g, "пом'якшено"],
    [/\bclosed\b/g, "закрито"],
    [/\bfalse_positive\b/g, "хибне спрацювання"],
    [/\bqueued\b/g, "в черзі"],
    [/\brunning\b/g, "виконується"],
    [/\bcompleted\b/g, "завершено"],
    [/\bfailed\b/g, "помилка"],
    [/\bcancelled\b/g, "скасовано"],
  ];

  regexReplacements.forEach(([pattern, nextValue]) => {
    value = value.replace(pattern, nextValue);
  });

  return value;
}

export function localizeAssistantText(text) {
  const lang = getLang();
  const source = String(text || "");
  if (lang === "en") {
    return source;
  }

  const ukrainian = toUkrainianAssistantText(source);
  if (lang === "duo") {
    return `${ukrainian}\n\n[EN]\n${source}`;
  }
  return ukrainian;
}
