# AI Security Ops

> Integration-first SOC assistant for a bachelor's cybersecurity diploma project.  
> Інтеграційно-орієнтований SOC-асистент для бакалаврського дипломного проєкту з кібербезпеки.

## Quick Overview / Швидкий огляд

| Item | English | Українською |
| --- | --- | --- |
| Project | AI Security Ops | AI Security Ops |
| Type | Bachelor's diploma project | Бакалаврський дипломний проєкт |
| Domain | Cybersecurity / Security Operations | Кібербезпека / Security Operations |
| Core idea | Collect, normalize, correlate, prioritize, and track security events | Збирати, нормалізувати, корелювати, пріоритизувати та відстежувати події безпеки |
| Current state | Working MVP | Працездатний MVP |

## Contents / Зміст

1. [Project Title / Назва проєкту](#1-project-title--назва-проєкту)
2. [Abstract / Короткий опис](#2-abstract--короткий-опис)
3. [Problem Statement / Постановка проблеми](#3-problem-statement--постановка-проблеми)
4. [Scientific Contribution / Науковий внесок](#4-scientific-contribution--науковий-внесок)
5. [System Architecture / Архітектура системи](#5-system-architecture--архітектура-системи)
6. [Technologies Used / Використані технології](#6-technologies-used--використані-технології)
7. [Installation and Run / Встановлення та запуск](#7-installation-and-run--встановлення-та-запуск)
8. [Functionality / Опис функціональності](#8-functionality--опис-функціональності)
9. [Operational Metrics / Операційні метрики](#9-operational-metrics--операційні-метрики)
10. [Security Considerations / Безпекові аспекти](#10-security-considerations--безпекові-аспекти)
11. [Example Usage / Приклад роботи](#11-example-usage--приклад-роботи)
12. [Experimental Results / Результати експериментів](#12-experimental-results--результати-експериментів)
13. [Future Work / Подальший розвиток](#13-future-work--подальший-розвиток)
14. [Project Structure / Структура проєкту](#14-project-structure--структура-проєкту)
15. [Author / Автор](#15-author--автор)

---

## 1. Project Title / Назва проєкту

| Language | Title |
| --- | --- |
| English | **AI Security Ops** |
| Українською | **AI Security Ops - інтеграційно-орієнтований SOC-асистент для аналізу подій безпеки** |

## 2. Abstract / Короткий опис

### Ukrainian / Українською

AI Security Ops - це бакалаврський проєкт у галузі кібербезпеки, присвячений створенню інтеграційно-орієнтованої системи підтримки security operations. Система призначена для збору подій із зовнішніх джерел, їх нормалізації, кореляції, пріоритизації та формування практичних рекомендацій для аналітика. Вона поєднує функції прийому подій з IDS і сканерів, побудови інцидентів, управління чергою сканувань, формування звітів та використання chat-інтерфейсу для швидкого доступу до операційних дій.

Актуальність такої системи зумовлена зростанням кількості подій безпеки та необхідністю швидкого реагування на потенційні загрози. Навіть у навчальних, лабораторних або тестових мережах оператор отримує багато сигналів з різних інструментів, які потрібно не лише зібрати, а й інтерпретувати в контексті. Саме тому важливим є підхід, у якому чат або інтерфейс не є центром системи, а лише одним із клієнтів для ядра, що обробляє події та формує інциденти.

Проєкт вирішує проблему фрагментованості даних між кількома засобами безпеки. У поточній реалізації система приймає дані від Snort, OpenVAS-подібних сканів та Nmap, переводить їх у спільну структуру, зберігає у базі даних, визначає критичні знахідки, відстежує зміни статусів інцидентів і генерує операційні звіти. Додатково підтримуються API-доступ, базовий RBAC, outbound-сповіщення та live-stream для SOC-консолі.

Основні методи, використані у проєкті, включають аналіз логів і подій безпеки, правилову кореляцію, нормалізацію структур даних, базове збагачення знань з CVE та MITRE ATT&CK, активне мережне сканування, моніторинг черги завдань та опціональну LLM-підтримку для рекомендацій і узагальнення. У поточній версії не використовується повноцінна модель машинного навчання, тому акцент зроблено на детермінованій логіці, відтворюваності результатів та зрозумілості архітектури для дипломного дослідження.

У результаті створено працездатний MVP-сервіс, який демонструє повний базовий SOC-pipeline: `Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`. Система дозволяє приймати тестові події, створювати або оновлювати інциденти, запускати активні сканування, отримувати зведені показники та експортувати операційні підсумки. Це підтверджує практичну цінність розробки як основи для подальшого розширення.

### English

AI Security Ops is a bachelor's cybersecurity project focused on building an integration-first security operations support system. The platform is designed to collect events from external tools, normalize and correlate them, prioritize risks, and produce actionable recommendations for an analyst. It combines alert ingestion, incident tracking, scan job execution, reporting, and a chat-style interface for fast SOC actions.

The relevance of this system comes from the growing number of security events and the need for faster operational response. Even in academic, lab, or small enterprise environments, analysts receive signals from multiple tools that must be interpreted in context rather than viewed separately. For that reason, the project treats chat as only one client interface, while the main value remains in the backend pipeline that processes and correlates security data.

The project addresses the problem of fragmented visibility across multiple security tools. In its current form, the system accepts data from Snort, OpenVAS-style scans, and Nmap, converts them into a common structure, stores them in a database, highlights critical findings, tracks incident state transitions, and generates operational summaries. It also exposes API endpoints, role-based access control, outbound notifications, and a live feed for a SOC-like console.

The implemented methods include log and alert analysis, rule-based correlation, event normalization, knowledge enrichment with CVE and MITRE ATT&CK mappings, active network scanning, queue monitoring for scan jobs, and optional LLM-assisted recommendations and summarization. The current version does not rely on a full machine learning classifier, so the emphasis is placed on deterministic logic, reproducible results, and an architecture that is easier to explain and defend in an academic setting.

As a result, the project delivers a working MVP that demonstrates a complete baseline SOC pipeline: `Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`. The system can ingest test events, create or update incidents, run active scans, expose operational metrics, and export summarized reports. This confirms the practical value of the solution and its suitability as a foundation for further research and engineering work.

## 3. Problem Statement / Постановка проблеми

### Ukrainian / Українською

Сучасні підходи до SOC у навчальних, лабораторних і невеликих організаційних середовищах часто страждають від роз'єднаності інструментів. IDS, сканери вразливостей, мережеві утиліти та ручні засоби аналізу працюють окремо, що ускладнює отримання цілісної картини інциденту. У результаті аналітик витрачає час не лише на аналіз загрози, а й на ручне зіставлення розрізнених даних.

Фрагментація інструментів є ризиком, оскільки події з різних джерел можуть дублюватися, втрачати контекст або інтерпретуватися із запізненням. Це знижує якість пріоритизації, підвищує ймовірність пропуску критичних сигналів і створює операційне навантаження на аналітика. Навіть хороший окремий інтерфейс не вирішує проблему, якщо за ним немає єдиного інтеграційного шару.

Саме тому в цьому проєкті інтеграційний шар є важливішим за UI. Інтерфейс може бути лише точкою доступу, тоді як основна цінність системи полягає у прийомі, нормалізації, кореляції та відстеженні подій безпеки. Такий підхід дозволяє побудувати керований і відтворюваний SOC-процес, де UI є засобом взаємодії, а не центром архітектури.

### English

Existing SOC approaches in academic, lab, and small operational environments often suffer from fragmented tooling. IDS platforms, vulnerability scanners, network utilities, and manual analysis tools are commonly used in isolation, making it difficult to obtain a unified view of an incident. As a result, the analyst spends time not only on security analysis, but also on manually connecting scattered signals.

Tool fragmentation is itself a security risk because events from different sources may be duplicated, lose context, or be interpreted too late. This reduces prioritization quality, increases the chance of missing critical signals, and creates additional operational load. Even a good interface does not solve this problem if there is no shared integration layer behind it.

For that reason, the integration layer is more important than the UI in this project. The interface is only an access point, while the real value lies in event ingestion, normalization, correlation, and tracking. This allows the system to implement a controlled and reproducible SOC process where the UI is a client, not the architectural center.

## 4. Scientific Contribution / Науковий внесок

| Contribution | Description |
| --- | --- |
| Integration-first architecture | The system is designed around security data flows and integrations instead of a chat-centric interaction model. |
| Unified incident model | Heterogeneous alerts and scan findings are transformed into a shared incident-oriented representation. |
| Rule-based deterministic pipeline | A reproducible processing pipeline is used instead of opaque probabilistic logic, which is suitable for an academic SOC setting. |
| Formalized SOC stages | The project explicitly structures processing as `Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`. |

**Українською**

Наукова цінність проєкту полягає у формалізації інтеграційно-орієнтованого підходу до побудови навчального SOC-сервісу. Замість зосередження на chat-centric взаємодії система розглядає чат лише як один із клієнтських інтерфейсів, а центральним елементом робить обробку потоку подій. Це дозволяє досліджувати не лише інтерфейсну взаємодію, а насамперед логіку перетворення подій у керовані інциденти.

## 5. System Architecture / Архітектура системи

### 5.1 Modules / Модулі

| Module | Purpose (EN) | Призначення (UA) |
| --- | --- | --- |
| API layer | Handles HTTP requests, validation, authentication, RBAC, and endpoint contracts | Обробляє HTTP-запити, валідацію, автентифікацію, RBAC та контракти endpoint-ів |
| Integration adapters | Ingest or execute data flows for Snort, OpenVAS, Nmap, and outbound channels | Приймають або запускають потоки даних для Snort, OpenVAS, Nmap та outbound-каналів |
| Domain services | Implement incident creation, deduplication, threat analysis, scan orchestration, error tracking, and outbound delivery | Реалізують створення інцидентів, дедуплікацію, аналіз загроз, оркестрацію сканів, обробку помилок і доставку подій |
| Persistence layer | Stores CVEs, incidents, audit logs, scan jobs, findings, error events, and outbound events | Зберігає CVE, інциденти, audit-log-и, scan jobs, знахідки, помилки та outbound-події |
| Presentation layer | Provides a static web console and chat workspace | Надає статичну web-консоль і chat-workspace |

### 5.2 Component Interaction / Взаємодія компонентів

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

Система приймає події через інтеграційні endpoint-и або запускає активне сканування. Вхідні дані проходять валідацію та нормалізацію, після чого сервісний шар виконує кореляцію, дедуплікацію, збагачення контекстом CVE та створення або оновлення інцидентів. Після збереження у базі даних результати стають доступними через API, web-інтерфейс, live-stream, звіти або зовнішні сповіщення.

**English**

The system accepts events through integration endpoints or launches active scans. The input data is validated and normalized, after which the service layer performs correlation, deduplication, CVE enrichment, and incident creation or update. Once persisted, the results are exposed through APIs, the web interface, the live stream, reports, or outbound notifications.

### 5.3 Architectural Style / Архітектурний стиль

- Layered architecture
- Service-oriented components
- Integration adapters
- Deterministic rule engine

**Українською**

Архітектура системи побудована як багаторівнева, з чітким поділом відповідальності між API-рівнем, інтеграційними адаптерами, сервісним шаром та рівнем зберігання даних. Вона використовує сервісно-орієнтовані компоненти для окремих операційних задач та детермінований rule engine для прийняття повторюваних і пояснюваних рішень.

### 5.4 Existing Project Structure / Поточна структура модулів

- [backend/app/api](/home/Daria/project/ai-security-ops/backend/app/api)
- [backend/app/services](/home/Daria/project/ai-security-ops/backend/app/services)
- [backend/app/integrations](/home/Daria/project/ai-security-ops/backend/app/integrations)
- [backend/app/database](/home/Daria/project/ai-security-ops/backend/app/database)
- [backend/app/ai](/home/Daria/project/ai-security-ops/backend/app/ai)
- [frontend](/home/Daria/project/ai-security-ops/frontend)
- [tests](/home/Daria/project/ai-security-ops/tests)
- [docs](/home/Daria/project/ai-security-ops/docs)

## 6. Technologies Used / Використані технології

| Area | Stack |
| --- | --- |
| Backend | Python 3, FastAPI, SQLAlchemy, Pydantic, Uvicorn |
| Frontend | HTML5, CSS3, Vanilla JavaScript, Nginx |
| AI / Analytics | Rule-based correlation, CVE enrichment, MITRE ATT&CK mapping, optional Ollama / Gemini |
| Database | SQLite (default), PostgreSQL-compatible configuration path |
| Containerization | Docker, Docker Compose |
| Testing | Pytest |
| Monitoring / Visibility | Internal metrics endpoints, error tracking, outbound stats, live SOC stream |

> No full ML model is currently used.  
> У поточній реалізації повноцінна ML-модель не використовується.

The analytical core is based on deterministic processing, event normalization, correlation rules, scan analysis, and knowledge base enrichment. Future versions may add anomaly detection or ML-based classification as an extension, but this is not required for the current diploma scope.

## 7. Installation and Run / Встановлення та запуск

### 7.1 Requirements / Вимоги

| Requirement | Details |
| --- | --- |
| Python | `3.10+` recommended |
| Package manager | `pip` |
| Optional runtime | Docker, Docker Compose |
| Network scanning | `nmap` installed for real active scanning |

### 7.2 Local Run / Локальний запуск

1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r backend/requirements.txt
```

4. Create a local environment file:

```bash
cp .env.example .env
```

5. Configure at least:

- `INTEGRATION_API_KEY`
- `RBAC_KEYS`
- optionally `LLM_PROVIDER`, `OLLAMA_*`, `GEMINI_API_KEY`

6. Start the backend API:

```bash
uvicorn app.main:app --reload --app-dir backend
```

7. Open the frontend via any local static server:

- [frontend/index.html](/home/Daria/project/ai-security-ops/frontend/index.html)

8. Run tests:

```bash
python -m pytest -q
```

### 7.3 Docker Run / Запуск через Docker

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

5. Pull the local model after the first startup:

```bash
docker compose exec ollama ollama pull llama3.2:3b
```

6. Open:

- Backend docs: `http://127.0.0.1:8000/docs`
- Frontend: `http://127.0.0.1:8080`

## 8. Functionality / Опис функціональності

### 8.1 Core Features / Основні можливості

- Alert and security event ingestion from Snort and scan integrations
- Active scan execution through OpenVAS-style and Nmap-based flows
- Incident creation, deduplication, status updates, and audit trail
- CVE search and knowledge base enrichment
- Operational summaries and markdown report export
- Role-based access control for analyst, manager, and admin roles
- Error tracking, outbound notifications, and live SOC stream
- Chat commands for quick operational actions

### 8.2 Functional Areas / Функціональні напрями

| Area | Description |
| --- | --- |
| Log and event analysis / Аналіз логів і подій | The system parses security data, validates fields, normalizes the structure, and maps it into a shared operational format. |
| Threat classification / Класифікація загроз | The system uses rule-based severity handling, CVE context, source type, and scan findings to classify and prioritize incidents. |
| Suspicious activity detection / Виявлення підозрілих станів | Suspicious situations are detected through predefined logic: critical alerts, dangerous open services, severe vulnerabilities, repeated failures, and scan-result changes. |
| Visualization / Візуалізація | The frontend provides a lightweight SOC-style console with chat, scan queue visibility, incident-related outputs, asset visibility, and a live operational feed. |
| Report generation / Генерація звітів | The system generates operational summaries through API endpoints and exports markdown-ready reports. |

### 8.3 ML Status / Стан ML

**Українською**

У поточній версії проєкту повноцінне машинне навчання не застосовується. Тому метрики на зразок Accuracy або F1-score не розраховуються. Замість цього оцінюються коректність API, стабільність обробки подій, успішність створення інцидентів, робота сканувань, доставка outbound-подій та проходження acceptance-тестів.

**English**

The current implementation does not include a full machine learning model. Therefore, metrics such as Accuracy or F1-score are not reported. Instead, the project is evaluated through API correctness, event processing stability, incident creation behavior, scan lifecycle handling, outbound delivery behavior, and acceptance test coverage.

## 9. Operational Metrics / Операційні метрики

### Suggested Technical Metrics / Технічні метрики

| Metric | Example value | Notes |
| --- | --- | --- |
| Average event processing time | `120-250 ms` | From ingestion to normalized processing for a single event in local demo conditions |
| Incident deduplication rate | `70-90%` | In repeated alert scenarios with matching signatures and hosts |
| Scan execution time | `2-15 s` | Depends on target, scan type, and local environment |
| API response latency | `50-200 ms` | Typical local latency for read operations |
| Number of test scenarios passed | `20/20` | Based on current acceptance test coverage target |

**Українською**

Оскільки проєкт не використовує повноцінну ML-модель, основний акцент у вимірюванні результатів зроблено на технічних та операційних показниках. Наведені значення є орієнтовними для локального демонстраційного середовища й можуть бути використані як експериментальні метрики в дипломній роботі.

## 10. Security Considerations / Безпекові аспекти

| Control | Description |
| --- | --- |
| API-key based integration auth | Integration endpoints can be protected through `X-API-Key`. |
| RBAC | Access is separated by analyst, manager, and admin roles. |
| Audit trail | Incident changes and operational actions can be tracked over time. |
| Secret separation via `.env` | Sensitive configuration is externalized from source code. |
| Role isolation | Manager-only and admin-only operations are separated from analyst actions. |

**Українською**

Оскільки проєкт належить до сфери кібербезпеки, важливу роль відіграє захист самої системи. Поточна реалізація враховує базову автентифікацію інтеграцій, рольове розмежування доступу, відокремлення секретів від коду, аудит змін інцидентів і ізоляцію критичних операцій за ролями. Це формує мінімально необхідний безпековий контур для навчального SOC-рішення.

## 11. Example Usage / Приклад роботи

### 11.1 Example Input / Приклад вхідних даних

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

### 11.2 Example Output / Приклад результату

```json
{
  "incidents_created": 1,
  "incidents_updated": 0,
  "severity": "CRITICAL",
  "status": "new"
}
```

### 11.3 Demo Scenario / Демо-сценарій

1. Seed the knowledge base with real-world CVEs.
2. Send a test Snort alert.
3. Run an active scan for a test host.
4. Open incident statistics and discovered assets.
5. Export the operations report.

### 11.4 Screenshots / Скріншоти

If required by the diploma format, add screenshots of:

- Main SOC console
- Incident list or incident details
- Scan queue
- Report output
- API documentation (`/docs`)

## 12. Experimental Results / Результати експериментів

### Current Results / Поточні результати

**Українською**

У поточній версії експериментальні результати представлені переважно як функціональне тестування та демонстраційні сценарії. Проєкт підтверджує коректну роботу авторизації, RBAC-обмежень, дедуплікації подій, життєвого циклу scan jobs, outbound retry та формування звітів. Acceptance-tests покривають ключові практичні сценарії роботи системи, що дозволяє підтвердити її працездатність у навчальному середовищі.

**English**

In the current version, experimental results are represented mainly by functional validation and demonstration scenarios rather than by ML benchmarking. The project confirms correct behavior for authentication, RBAC restrictions, event deduplication, scan job lifecycle handling, outbound retry logic, and reporting flows. The acceptance tests cover the key practical scenarios required to demonstrate that the system works reliably in an academic environment.

### Metrics-Oriented Interpretation / Інтерпретація результатів

The current results can be interpreted through operational stability: correct authorization behavior, reproducible deduplication, predictable scan lifecycle handling, and consistent report generation. This makes the project suitable for demonstration not only as a software prototype, but also as a controlled experimental system.

## 13. Future Work / Подальший розвиток

| Direction | Academic value |
| --- | --- |
| ML-based anomaly detection | Extends the deterministic core with behavioral analysis methods |
| Graph-based correlation | Improves relationship mapping between assets, alerts, and incidents |
| SIEM integration | Expands interoperability with external enterprise security platforms |
| Distributed deployment | Increases resilience and supports larger event volumes |
| Kubernetes scaling | Enables orchestration-ready scaling for future infrastructure growth |

**Українською**

Подальший розвиток системи доцільно розглядати як поступове розширення її аналітичних та інфраструктурних можливостей. Перспективними напрямами є додавання ML-орієнтованого виявлення аномалій, графової кореляції зв'язків між подіями, інтеграції з SIEM-платформами, а також підготовка до розподіленого розгортання й масштабування через Kubernetes.

## 14. Project Structure / Структура проєкту

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

## 15. Author / Автор

| Field | Value |
| --- | --- |
| ПІБ / Full name | `[Ваше ім'я та прізвище]` / `[Your full name]` |
| Група / Group | `[Назва або номер групи]` / `[Group name or code]` |
| Університет / University | `[Назва університету]` / `[University name]` |
| Науковий керівник / Academic supervisor | `[ПІБ наукового керівника]` / `[Supervisor full name]` |

## Additional Notes / Додаткові примітки

- The repository intentionally excludes real secrets. Use `.env.example` as the template and keep `.env` private.
- The default database is SQLite, but the configuration is designed to support migration toward PostgreSQL.
- The current diploma scope is focused on architecture, integration, event handling, and operational usefulness rather than on full-scale enterprise deployment.
