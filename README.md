# AI Security Ops

## 1. Project Title / Назва проєкту

**English:** AI Security Ops  
**Українською:** AI Security Ops - інтеграційно-орієнтований SOC-асистент для аналізу подій безпеки

## 2. Abstract / Короткий опис

**Українською**

AI Security Ops - це бакалаврський проєкт у галузі кібербезпеки, присвячений створенню інтеграційно-орієнтованої системи підтримки security operations. Система призначена для збору подій із зовнішніх джерел, їх нормалізації, кореляції, пріоритизації та формування практичних рекомендацій для аналітика. Вона поєднує функції прийому подій з IDS і сканерів, побудови інцидентів, управління чергою сканувань, формування звітів та використання chat-інтерфейсу для швидкого доступу до операційних дій.

Актуальність такої системи зумовлена зростанням кількості подій безпеки та необхідністю швидкого реагування на потенційні загрози. Навіть у навчальних, лабораторних або тестових мережах оператор отримує багато сигналів з різних інструментів, які потрібно не лише зібрати, а й інтерпретувати в контексті. Саме тому важливим є підхід, у якому чат або інтерфейс не є центром системи, а лише одним із клієнтів для ядра, що обробляє події та формує інциденти.

Проєкт вирішує проблему фрагментованості даних між кількома засобами безпеки. У поточній реалізації система приймає дані від Snort, OpenVAS-подібних сканів та Nmap, переводить їх у спільну структуру, зберігає у базі даних, визначає критичні знахідки, відстежує зміни статусів інцидентів і генерує операційні звіти. Додатково підтримуються API-доступ, базовий RBAC, outbound-сповіщення та live-stream для SOC-консолі.

Основні методи, використані у проєкті, включають аналіз логів і подій безпеки, правилову кореляцію, нормалізацію структур даних, базове збагачення знань з CVE та MITRE ATT&CK, активне мережне сканування, моніторинг черги завдань та опціональну LLM-підтримку для рекомендацій і узагальнення. У поточній версії не використовується повноцінна модель машинного навчання, тому акцент зроблено на детермінованій логіці, відтворюваності результатів та зрозумілості архітектури для дипломного дослідження.

У результаті створено працездатний MVP-сервіс, який демонструє повний базовий SOC-pipeline: `Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`. Система дозволяє приймати тестові події, створювати або оновлювати інциденти, запускати активні сканування, отримувати зведені показники та експортувати операційні підсумки. Це підтверджує практичну цінність розробки як основи для подальшого розширення.

**English**

AI Security Ops is a bachelor's cybersecurity project focused on building an integration-first security operations support system. The platform is designed to collect events from external tools, normalize and correlate them, prioritize risks, and produce actionable recommendations for an analyst. It combines alert ingestion, incident tracking, scan job execution, reporting, and a chat-style interface for fast SOC actions.

The relevance of this system comes from the growing number of security events and the need for faster operational response. Even in academic, lab, or small enterprise environments, analysts receive signals from multiple tools that must be interpreted in context rather than viewed separately. For that reason, the project treats chat as only one client interface, while the main value remains in the backend pipeline that processes and correlates security data.

The project addresses the problem of fragmented visibility across multiple security tools. In its current form, the system accepts data from Snort, OpenVAS-style scans, and Nmap, converts them into a common structure, stores them in a database, highlights critical findings, tracks incident state transitions, and generates operational summaries. It also exposes API endpoints, role-based access control, outbound notifications, and a live feed for a SOC-like console.

The implemented methods include log and alert analysis, rule-based correlation, event normalization, knowledge enrichment with CVE and MITRE ATT&CK mappings, active network scanning, queue monitoring for scan jobs, and optional LLM-assisted recommendations and summarization. The current version does not rely on a full machine learning classifier, so the emphasis is placed on deterministic logic, reproducible results, and an architecture that is easier to explain and defend in an academic setting.

As a result, the project delivers a working MVP that demonstrates a complete baseline SOC pipeline: `Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`. The system can ingest test events, create or update incidents, run active scans, expose operational metrics, and export summarized reports. This confirms the practical value of the solution and its suitability as a foundation for further research and engineering work.

## 3. System Architecture / Архітектура системи

### 3.1 Modules / Модулі

**Українською**

- API layer: обробляє HTTP-запити, валідацію, автентифікацію, RBAC та публічні контракти endpoint-ів.
- Integration adapters: приймають або запускають потоки даних для Snort, OpenVAS та Nmap, а також підтримують outbound-канали.
- Domain services: реалізують створення інцидентів, дедуплікацію, аналіз загроз, роботу зі сканами, помилками та доставкою подій.
- Persistence layer: забезпечує зберігання CVE, інцидентів, audit-log-ів, скан-завдань, знахідок, помилок і outbound-подій.
- Presentation layer: статична web-консоль і chat-workspace для демонстрації стану системи.

**English**

- API layer: handles HTTP requests, validation, authentication, RBAC, and endpoint contracts.
- Integration adapters: ingest or execute data flows for Snort, OpenVAS, Nmap, and outbound channels.
- Domain services: implement incident creation, deduplication, threat analysis, scan orchestration, error tracking, and outbound delivery.
- Persistence layer: stores CVEs, incidents, audit logs, scan jobs, findings, error events, and outbound events.
- Presentation layer: a static web console and chat workspace for operational visibility.

### 3.2 Component Interaction / Взаємодія компонентів

```text
Snort / OpenVAS / Nmap
          |
          v
  Integration Endpoints
          |
          v
  Normalize + Validate
          |
          v
  Correlate + Prioritize
          |
          v
  Incident / Scan Services
          |
          v
   Database + Audit Trail
          |
    +-----+-----+
    |           |
    v           v
Frontend UI   Reports / Outbound / Stream
```

**Українською**

Спершу система приймає події з інтеграційних endpoint-ів або запускає активне сканування. Далі дані проходять перевірку та нормалізацію до уніфікованої структури. Після цього сервісна логіка виконує кореляцію, дедуплікацію, збагачення контекстом CVE і формує або оновлює інциденти. Результати зберігаються у базі даних, після чого стають доступними через API, web-інтерфейс, live-stream, звіти або зовнішні сповіщення.

**English**

The system first accepts events through integration endpoints or launches active scans. The incoming data is validated and normalized into a shared structure. Then the service layer performs correlation, deduplication, knowledge enrichment, and creates or updates incidents. The results are stored in the database and exposed through APIs, the web interface, the live stream endpoint, reports, or outbound notifications.

### 3.3 Existing Project Structure / Поточна структура модулів

- [backend/app/api](/home/Daria/project/ai-security-ops/backend/app/api)
- [backend/app/services](/home/Daria/project/ai-security-ops/backend/app/services)
- [backend/app/integrations](/home/Daria/project/ai-security-ops/backend/app/integrations)
- [backend/app/database](/home/Daria/project/ai-security-ops/backend/app/database)
- [backend/app/ai](/home/Daria/project/ai-security-ops/backend/app/ai)
- [frontend](/home/Daria/project/ai-security-ops/frontend)
- [tests](/home/Daria/project/ai-security-ops/tests)
- [docs](/home/Daria/project/ai-security-ops/docs)

## 4. Technologies Used / Використані технології

**Backend**

- Python 3
- FastAPI
- SQLAlchemy
- Pydantic
- Uvicorn

**Frontend**

- HTML5
- CSS3
- Vanilla JavaScript
- Nginx (for containerized static serving)

**AI / Analytics**

- Rule-based correlation and incident prioritization
- CVE enrichment
- MITRE ATT&CK mapping
- Optional LLM integration: Ollama or Gemini

**Database**

- SQLite (default)
- PostgreSQL-compatible configuration path

**Containerization**

- Docker
- Docker Compose

**Testing**

- Pytest

**Monitoring / Operational Visibility**

- Internal operational metrics via API endpoints
- Error tracking and outbound delivery statistics
- Live SOC stream endpoint

**Important note / Важлива примітка**

No full ML model is currently used in the implemented version. The analytical core is based on deterministic processing, event normalization, correlation rules, scan analysis, and knowledge base enrichment. If needed, future versions may add anomaly detection or ML-based classification as an extension rather than a required part of the current diploma scope.

## 5. Installation and Run / Встановлення та запуск

### 5.1 Requirements / Вимоги

**Українською**

- Python 3.10+ бажано
- `pip` для встановлення залежностей
- Docker і Docker Compose (опціонально, для контейнеризованого запуску)
- `nmap` у системі для реального active scanning

**English**

- Python 3.10+ recommended
- `pip` for dependency installation
- Docker and Docker Compose (optional, for containerized startup)
- `nmap` installed for real active scanning

### 5.2 Local Run / Локальний запуск

1. Clone the repository.
2. Create and activate a virtual environment.
3. Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

4. Create local environment configuration:

```bash
cp .env.example .env
```

5. Configure secrets in `.env`:

- `INTEGRATION_API_KEY`
- `RBAC_KEYS`
- optionally `LLM_PROVIDER`, `OLLAMA_*`, `GEMINI_API_KEY`

6. Start the backend API:

```bash
uvicorn app.main:app --reload --app-dir backend
```

7. Open the frontend through any local static server and load:

- [frontend/index.html](/home/Daria/project/ai-security-ops/frontend/index.html)

8. Run tests:

```bash
python -m pytest -q
```

### 5.3 Docker Run / Запуск через Docker

1. Copy the environment file:

```bash
cp .env.example .env
```

2. Fill in real values for:

- `INTEGRATION_API_KEY`
- `RBAC_KEYS`

3. If LLM mode is needed, set:

- `LLM_PROVIDER=ollama`
- `OLLAMA_MODEL=llama3.2:3b`

4. Start all services:

```bash
docker compose up --build -d
```

5. After first startup, download the local model in the Ollama container:

```bash
docker compose exec ollama ollama pull llama3.2:3b
```

6. Open:

- Backend docs: `http://127.0.0.1:8000/docs`
- Frontend: `http://127.0.0.1:8080`

## 6. Functionality / Опис функціональності

### 6.1 Core Features / Основні можливості

- Alert and security event ingestion from Snort and scan integrations
- Active scan execution through OpenVAS-style and Nmap-based flows
- Incident creation, deduplication, status updates, and audit trail
- CVE search and knowledge base enrichment
- Operational summaries and markdown report export
- Role-based access control for analyst, manager, and admin roles
- Error tracking, outbound notifications, and live SOC stream
- Chat commands for quick operational actions

### 6.2 Functional Areas / Функціональні напрями

**Log and event analysis / Аналіз логів і подій**

The system parses incoming security data, validates fields, normalizes the structure, and maps it into a common operational format suitable for correlation and reporting.

**Threat classification and prioritization / Класифікація та пріоритизація загроз**

The system uses rule-based severity handling, CVE context, source type, and scan findings to classify and prioritize incidents. This is not an ML classifier in the current version.

**Anomaly or suspicious activity detection / Виявлення підозрілих станів**

The current version detects suspicious situations through predefined logic, such as critical Snort alerts, dangerous open services, severe vulnerabilities, repeated failures, and changes in scan results. A dedicated ML anomaly detector is not implemented.

**Visualization / Візуалізація**

The frontend provides a lightweight SOC-style console with chat, scan queue visibility, incident-related outputs, asset visibility, and a live operational feed.

**Report generation / Генерація звітів**

The system can generate operational summaries through API endpoints and export markdown-ready reports for demonstrations, documentation, or management review.

### 6.3 ML Status / Стан ML

**Українською**

У поточній версії проєкту повноцінне машинне навчання не застосовується. Тому метрики на зразок Accuracy або F1-score не розраховуються. Замість цього оцінюються коректність API, стабільність обробки подій, успішність створення інцидентів, робота сканувань, доставка outbound-подій та проходження acceptance-тестів.

**English**

The current implementation does not include a full machine learning model. Therefore, metrics such as Accuracy or F1-score are not reported. Instead, the project is evaluated through API correctness, event processing stability, incident creation behavior, scan lifecycle handling, outbound delivery behavior, and acceptance test coverage.

## 7. Example Usage / Приклад роботи

### 7.1 Example Input / Приклад вхідних даних

**Snort alert ingestion**

```http
POST /integrations/snort/alerts
X-API-Key: <integration_key>
Content-Type: application/json
```

```json
{
  "alerts": [
    {
      "signature": "ET TROJAN Possible Malicious Traffic",
      "source_ip": "10.0.0.15",
      "destination_ip": "10.0.0.20",
      "priority": 1,
      "timestamp": "2026-03-02T10:15:00Z"
    }
  ]
}
```

### 7.2 Example Output / Приклад результату

```json
{
  "incidents_created": 1,
  "incidents_updated": 0,
  "severity": "CRITICAL",
  "status": "new"
}
```

### 7.3 Demo Scenario / Демо-сценарій

1. Seed the knowledge base with real-world CVEs.
2. Send a test Snort alert.
3. Run an active scan for a test host.
4. Open incident statistics and discovered assets.
5. Export the operations report.

### 7.4 Screenshots / Скріншоти

Add screenshots of the following screens if required by the diploma format:

- Main SOC console
- Incident list or incident details
- Scan queue
- Report output
- API documentation (`/docs`)

## 8. Experimental Results / Результати експериментів

**Українською**

У поточній версії експериментальні результати представлені переважно як функціональне тестування та демонстраційні сценарії. Проєкт підтверджує коректну роботу авторизації, RBAC-обмежень, дедуплікації подій, життєвого циклу scan jobs, outbound retry та формування звітів. Acceptance-tests покривають ключові практичні сценарії роботи системи, що дозволяє підтвердити її працездатність у навчальному середовищі.

**English**

In the current version, experimental results are represented mainly by functional validation and demonstration scenarios rather than by ML benchmarking. The project confirms correct behavior for authentication, RBAC restrictions, event deduplication, scan job lifecycle handling, outbound retry logic, and reporting flows. The acceptance tests cover the key practical scenarios required to demonstrate that the system works reliably in an academic environment.

**What can be added later / Що можна додати пізніше**

- Comparison table for correlation quality before and after rule improvements
- Average processing time per event or scan task
- Count of created vs updated incidents in repeated scenarios
- Charts for incident severity distribution

## 9. Project Structure / Структура проєкту

```text
backend/
  app/
    ai/               # optional LLM client and expert logic
    api/              # FastAPI routers
    core/             # schemas and intent routing
    database/         # models, repositories, seed/import scripts
    integrations/     # Snort, OpenVAS, Nmap adapters
    nlp/              # regex and pattern-based command parsing
    services/         # business logic
    utils/            # helper utilities
  requirements.txt
  run.py
frontend/
  js/                 # UI logic
  styles/             # CSS styles
  index.html
docs/                 # architecture and acceptance documentation
tests/                # automated tests
docker-compose.yml
.env.example
README.md
```

## 10. Author / Автор

**Українською**

- ПІБ: `[Ваше ім'я та прізвище]`
- Група: `[Назва або номер групи]`
- Університет: `[Назва університету]`
- Науковий керівник: `[ПІБ наукового керівника]`

**English**

- Full name: `[Your full name]`
- Group: `[Group name or code]`
- University: `[University name]`
- Academic supervisor: `[Supervisor full name]`

## Additional Notes / Додаткові примітки

- The repository intentionally excludes real secrets. Use `.env.example` as the template and keep `.env` private.
- The default database is SQLite, but the configuration is designed to support migration toward PostgreSQL.
- The current diploma scope is focused on architecture, integration, event handling, and operational usefulness rather than on full-scale enterprise deployment.
