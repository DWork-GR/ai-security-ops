# AI Security Ops

Integration-first SOC асистент для бакалаврського дипломного проєкту з кібербезпеки.

Проєкт зосереджений на процесах security operations:
`Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`

## Що робить цей проєкт

- Приймає події з інтеграцій (Snort, скани у стилі OpenVAS/Nmap).
- Корелює результати у інциденти з enrichment за MITRE ATT&CK.
- Відстежує scan jobs, активи, помилки та доставку outbound-сповіщень.
- Дає чат-команди для швидких SOC-дій аналітика.
- Формує операційні підсумки для звітів і демонстрації.

## Архітектура

Backend:
- `FastAPI` + `SQLAlchemy` + сумісна конфігурація SQLite/PostgreSQL
- Модульні роутери API (`integrations`, `incidents`, `scans`, `assets`, `knowledge`, `errors`, `outbound`, `reports`, `stream`, `chat`)

Frontend:
- Статична SOC-консоль на HTML/CSS/JS
- Chat workspace + статус черги + знайдені активи + live feed

Базова модель безпеки:
- Авторизація інтеграцій через `X-API-Key`
- RBAC через `X-User-Key` (`analyst`, `manager`, `admin`)
- Редакція чутливих значень у пайплайні помилок

## Структура репозиторію

```text
backend/
  app/
    api/
    services/
    integrations/
    database/
frontend/
tests/
docs/
```

## Швидкий старт

1. Створіть і активуйте віртуальне середовище.
2. Встановіть залежності:
```bash
pip install -r backend/requirements.txt
```
Для реального active scanning встановіть `nmap` у систему та залишайте `NMAP_ALLOW_SOCKET_FALLBACK=false`.
3. Створіть локальну конфігурацію:
```bash
cp .env.example .env
```
4. Встановіть надійні секрети у `.env`:
- `INTEGRATION_API_KEY`
- `RBAC_KEYS`
5. Запустіть API:
```bash
uvicorn app.main:app --reload --app-dir backend
```
6. Відкрийте frontend через локальний static server та завантажте `frontend/index.html`.
7. Запустіть тести:
```bash
python -m pytest -q
```

## Конфігурація

Ключові env-параметри:

- `RBAC_ENABLED=true`
- `INTEGRATION_AUTH_REQUIRED=true`
- `CHAT_AUTH_REQUIRED=true`
- `STREAM_ALLOW_QUERY_USER_KEY=false`
- `CORS_ORIGINS=http://127.0.0.1:5500` (у production вкажіть реальний origin)
- `LLM_PROVIDER=none|ollama|gemini`
- `NMAP_ALLOW_SOCKET_FALLBACK=false` (щоб не переключатися на socket fallback)

Рекомендації:
- Для повністю офлайн-демо використовуйте `LLM_PROVIDER=none`.
- Для локальної безкоштовної LLM-інтеграції використовуйте `ollama`.

## Автентифікація та авторизація

Integration endpoints:
- Захищені через `X-API-Key`, коли `INTEGRATION_AUTH_REQUIRED=true`.
- Працюють у fail-closed режимі, якщо auth увімкнено, але серверний ключ не налаштовано.

RBAC endpoints:
- Використовують `X-User-Key`, який мапиться через `RBAC_KEYS`.
- Ролі:
  - `analyst`: читання і дії аналітика
  - `manager`: керівні операції, звіти, outbound-статистика
  - `admin`: повний доступ

Chat:
- `POST /chat` вимагає `X-User-Key`, коли `CHAT_AUTH_REQUIRED=true`.

Stream:
- `GET /stream/soc-live` за замовчуванням вимагає header `X-User-Key`.
- Query-автентифікація (`user_key`) за замовчуванням вимкнена.

## Основні API-ендпоінти

Інтеграції:
- `POST /integrations/snort/alerts`
- `POST /integrations/openvas/scan`
- `POST /integrations/openvas/scan/active`
- `POST /integrations/nmap/scan/active`

Сканування:
- `POST /scans/jobs`
- `GET /scans/jobs`
- `GET /scans/jobs/{id}`
- `POST /scans/jobs/{id}/run`

Інциденти та SOC-метрики:
- `GET /incidents`
- `GET /incidents/stats/summary`
- `PATCH /incidents/{id}/status`
- `GET /incidents/{id}/audit`

База знань:
- `GET /knowledge/cves/search`
- `GET /knowledge/cves/{cve_id}`
- `POST /knowledge/cves/seed/real-world`
- `POST /knowledge/cves/import/nvd`

Операційна видимість:
- `GET /assets/discovered`
- `GET /errors`
- `GET /errors/stats/summary`
- `GET /outbound/events`
- `GET /outbound/events/stats/summary`
- `GET /stream/soc-live`

Звіти:
- `GET /reports/operations`
- `GET /reports/operations/markdown`

## Чат-команди (приклади)

- `help`
- `full check 127.0.0.1`
- `scan 10.0.0.5`
- `show incidents`
- `incident stats`
- `show critical cves`
- `search cve apache`
- `show errors`
- `error stats`
- `analyze threats`
- `system status`
- `roadmap`

## Security Checklist

- Не комітьте реальні значення `.env`.
- Ротуйте секрети, якщо вони колись потрапляли в git.
- Обмежуйте CORS origins у production.
- Використовуйте довгі випадкові ключі для `INTEGRATION_API_KEY` і `RBAC_KEYS`.
- Залишайте `STREAM_ALLOW_QUERY_USER_KEY=false`.
- У реальному деплої вмикайте TLS і auth на рівні reverse proxy.
- Перегляньте політику доступу до `/errors` перед публічним запуском.

## LLM режими

- `LLM_PROVIDER=none`: лише офлайн-логіка.
- `LLM_PROVIDER=ollama`: локальна модель (`OLLAMA_BASE_URL`, `OLLAMA_MODEL`).
- `LLM_PROVIDER=gemini`: хмарна модель (`GEMINI_API_KEY` обов'язковий).

Швидкий приклад для Ollama:

```bash
ollama pull llama3.2:3b
```

У `.env`:
- `LLM_PROVIDER=ollama`
- `OLLAMA_MODEL=llama3.2:3b`

## Демо-сценарій (5-7 хвилин)

1. Засійте threat pack: `POST /knowledge/cves/seed/real-world`.
2. Надішліть тестову Snort-подію.
3. Запустіть активне сканування тестового хоста.
4. Відкрийте інциденти та incident stats.
5. Покажіть знайдені активи та scan queue.
6. Покажіть errors/outbound stats.
7. Експортуйте markdown operations report.

## Тестування

Запуск:

```bash
python -m pytest -q
```

Acceptance-тести покривають:
- auth guards
- RBAC restrictions
- життєвий цикл scan jobs
- поведінку доступу до stream
- outbound retry/idempotency
- сценарії incidents/errors/reports
