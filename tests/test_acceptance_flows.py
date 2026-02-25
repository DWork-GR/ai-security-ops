def test_openvas_scan_creates_incident(client):
    response = client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "10.0.0.5"
    assert payload["status"] == "running"
    assert payload["task_id"]

    incidents_response = client.get("/incidents")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()["items"]
    assert len(incidents) == 1
    assert incidents[0]["source"] == "openvas"


def test_snort_ingestion_deduplicates_by_source_and_message(client):
    body = {
        "alerts": [
            {
                "message": "[**] SQL Injection Attempt [**]",
                "priority": 1,
                "src_ip": "192.168.1.10",
                "dst_ip": "10.0.0.5",
            }
        ]
    }

    first = client.post("/integrations/snort/alerts", json=body)
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["accepted"] == 1
    assert first_payload["incidents_created"] == 1
    assert first_payload["incidents_updated"] == 0

    second = client.post("/integrations/snort/alerts", json=body)
    assert second.status_code == 200
    second_payload = second.json()
    assert second_payload["accepted"] == 1
    assert second_payload["incidents_created"] == 0
    assert second_payload["incidents_updated"] == 1


def test_chat_cve_lookup_and_critical_list(client):
    lookup = client.post("/chat", json={"message": "CVE-2021-44228"})
    assert lookup.status_code == 200
    lookup_payload = lookup.json()
    assert lookup_payload["type"] == "text"
    assert "CVSS" in lookup_payload["message"]

    critical = client.post("/chat", json={"message": "show critical cves"})
    assert critical.status_code == 200
    critical_payload = critical.json()
    assert critical_payload["type"] == "cves"
    assert any(item["severity"] == "CRITICAL" for item in critical_payload["cves"])


def test_chat_threat_analysis_returns_summary(client):
    response = client.post("/chat", json={"message": "analyze threats"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "text"
    assert "[Incidents]" in payload["message"]
    assert "[EN] Rule-Based SOC Analysis" in payload["message"]
    assert "[UK] Rule-Based SOC Аналіз" in payload["message"]
    assert "[LLM]" in payload["message"]


def test_integrations_api_key_guard_when_enabled(client, monkeypatch):
    from app.api import dependencies

    monkeypatch.setattr(dependencies, "INTEGRATION_AUTH_REQUIRED", True)
    monkeypatch.setattr(dependencies, "INTEGRATION_API_KEY", "demo-key")

    no_key = client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    assert no_key.status_code == 401

    bad_key = client.post(
        "/integrations/openvas/scan",
        json={"target": "10.0.0.5"},
        headers={"X-API-Key": "wrong"},
    )
    assert bad_key.status_code == 401

    good_key = client.post(
        "/integrations/openvas/scan",
        json={"target": "10.0.0.5"},
        headers={"X-API-Key": "demo-key"},
    )
    assert good_key.status_code == 200


def test_incident_status_update_and_filters(client):
    create = client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    assert create.status_code == 200

    incidents = client.get("/incidents")
    assert incidents.status_code == 200
    items = incidents.json()["items"]
    assert len(items) >= 1
    incident_id = items[0]["id"]

    update = client.patch(f"/incidents/{incident_id}/status", json={"status": "triaged"})
    assert update.status_code == 200
    assert update.json()["item"]["status"] == "triaged"
    assert update.json()["item"]["risk_score"] >= 0

    filtered = client.get("/incidents", params={"status": "triaged"})
    assert filtered.status_code == 200
    assert any(item["id"] == incident_id for item in filtered.json()["items"])

    audit = client.get(f"/incidents/{incident_id}/audit")
    assert audit.status_code == 200
    assert any(item["action"] == "status_changed" for item in audit.json()["items"])


def test_incident_stats_and_operations_report(client):
    client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    client.post(
        "/integrations/snort/alerts",
        json={
            "alerts": [
                {
                    "message": "[**] SQL Injection Attempt [**]",
                    "priority": 1,
                }
            ]
        },
    )

    stats = client.get("/incidents/stats/summary")
    assert stats.status_code == 200
    payload = stats.json()
    assert payload["total_incidents"] >= 2
    assert "by_source" in payload

    report = client.get("/reports/operations")
    assert report.status_code == 200
    report_payload = report.json()
    assert "SOC Operations Summary" in report_payload["report_en"]
    assert "Підсумок SOC Операцій" in report_payload["report_uk"]

    markdown = client.get("/reports/operations/markdown")
    assert markdown.status_code == 200
    assert "# SOC Operations Report" in markdown.text


def test_rbac_manager_required_for_reports_and_audit(client, monkeypatch):
    from app.api import rbac

    monkeypatch.setattr(rbac, "RBAC_ENABLED", True)
    monkeypatch.setattr(
        rbac,
        "RBAC_KEY_TO_ROLE",
        {
            "analyst-key": "analyst",
            "manager-key": "manager",
            "admin-key": "admin",
        },
    )

    create = client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    assert create.status_code == 200
    incident_id = client.get("/incidents", headers={"X-User-Key": "admin-key"}).json()["items"][0]["id"]

    no_role = client.get("/reports/operations")
    assert no_role.status_code == 401

    analyst = client.get("/reports/operations", headers={"X-User-Key": "analyst-key"})
    assert analyst.status_code == 403

    manager = client.get("/reports/operations", headers={"X-User-Key": "manager-key"})
    assert manager.status_code == 200

    analyst_audit = client.get(
        f"/incidents/{incident_id}/audit",
        headers={"X-User-Key": "analyst-key"},
    )
    assert analyst_audit.status_code == 403

    manager_audit = client.get(
        f"/incidents/{incident_id}/audit",
        headers={"X-User-Key": "manager-key"},
    )
    assert manager_audit.status_code == 200


def test_rbac_status_restriction_for_close_flow(client, monkeypatch):
    from app.api import rbac

    monkeypatch.setattr(rbac, "RBAC_ENABLED", True)
    monkeypatch.setattr(
        rbac,
        "RBAC_KEY_TO_ROLE",
        {
            "analyst-key": "analyst",
            "manager-key": "manager",
        },
    )

    create = client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    assert create.status_code == 200
    incident_id = client.get("/incidents", headers={"X-User-Key": "manager-key"}).json()["items"][0]["id"]

    denied = client.patch(
        f"/incidents/{incident_id}/status",
        json={"status": "closed"},
        headers={"X-User-Key": "analyst-key"},
    )
    assert denied.status_code == 403

    allowed = client.patch(
        f"/incidents/{incident_id}/status",
        json={"status": "closed"},
        headers={"X-User-Key": "manager-key"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["item"]["status"] == "closed"


def test_openvas_active_scan_returns_structured_findings(client):
    response = client.post(
        "/integrations/openvas/scan/active",
        json={"target": "127.0.0.1", "ports": [22, 80, 443], "timeout_ms": 120},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "127.0.0.1"
    assert payload["status"] == "completed"
    assert payload["scanner"] == "openvas"
    assert payload["discovery_engine"] in {"nmap", "socket-fallback"}
    assert payload["scan_profile"] in {"tcp-default", "tcp-custom"}
    assert payload["scanned_ports"] == 3
    assert "incidents_created" in payload
    assert "incidents_updated" in payload


def test_nmap_active_scan_returns_structured_findings(client):
    response = client.post(
        "/integrations/nmap/scan/active",
        json={"target": "127.0.0.1", "ports": [22, 80, 443], "timeout_ms": 120},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "127.0.0.1"
    assert payload["status"] == "completed"
    assert payload["scanner"] == "nmap"
    assert payload["discovery_engine"] in {"nmap", "socket-fallback"}
    assert payload["scan_profile"] in {"nmap-tcp-default", "nmap-tcp-custom"}
    assert payload["scanned_ports"] == 3
    assert "incidents_created" in payload
    assert "incidents_updated" in payload

    incidents_response = client.get("/incidents")
    assert incidents_response.status_code == 200
    items = incidents_response.json()["items"]
    assert any(item["source"] == "nmap" for item in items)


def test_scan_jobs_create_and_list(client):
    created = client.post(
        "/scans/jobs",
        json={"target_ip": "127.0.0.1", "scan_type": "quick"},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["target_ip"] == "127.0.0.1"
    assert payload["scan_type"] == "quick"
    assert payload["status"] == "queued"
    assert payload["id"]

    listed = client.get("/scans/jobs", params={"status": "queued", "limit": 20})
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert any(item["id"] == payload["id"] for item in items)

    loaded = client.get(f"/scans/jobs/{payload['id']}")
    assert loaded.status_code == 200
    assert loaded.json()["id"] == payload["id"]


def test_scan_job_run_now_executes_and_returns_summary(client, monkeypatch):
    from app.services import scan_job_service

    def fake_run_active_scan(db, *, target, ports=None, timeout_ms=250, source="openvas"):
        return {
            "task_id": "job-test-task",
            "scanner": source,
            "discovery_engine": "socket-fallback",
            "target": target,
            "status": "completed",
            "scan_profile": "nmap-tcp-custom" if source == "nmap" else "tcp-custom",
            "scanned_ports": len(ports or []),
            "open_ports": [80],
            "duration_ms": 11,
            "findings": [],
            "incidents_created": 1,
            "incidents_updated": 0,
            "baseline_scan_task_id": None,
            "new_open_ports": [80],
            "closed_open_ports": [],
        }

    monkeypatch.setattr(scan_job_service, "run_active_scan", fake_run_active_scan)

    created = client.post(
        "/scans/jobs",
        json={"target_ip": "127.0.0.1", "scan_type": "quick"},
    )
    assert created.status_code == 200
    job_id = created.json()["id"]

    executed = client.post(f"/scans/jobs/{job_id}/run")
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["id"] == job_id
    assert payload["status"] == "completed"
    assert payload["attempts"] == 1
    assert payload["result_summary"]["scanner"] == "nmap"
    assert payload["result_summary"]["open_ports"] == [80]


def test_knowledge_search_filters_by_cvss_and_query(client):
    response = client.get(
        "/knowledge/cves/search",
        params={"q": "apache", "min_cvss": 9, "limit": 20},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 1
    assert any(item["cve_id"].startswith("CVE-") for item in payload["items"])
    assert all(item["cvss"] >= 9 for item in payload["items"])


def test_error_event_is_recorded_and_searchable(client, monkeypatch):
    from app.api import integrations

    def broken_scan(*args, **kwargs):
        raise RuntimeError("scan backend unavailable")

    monkeypatch.setattr(integrations, "run_active_scan", broken_scan)
    response = client.post(
        "/integrations/openvas/scan/active",
        json={"target": "127.0.0.1"},
    )
    assert response.status_code == 500

    errors = client.get("/errors")
    assert errors.status_code == 200
    items = errors.json()["items"]
    assert any(item["source"] == "openvas" and item["operation"] == "active_scan" for item in items)

    stats = client.get("/errors/stats/summary")
    assert stats.status_code == 200
    assert stats.json()["total_errors"] >= 1


def test_outbound_delivery_retry_for_telegram_and_github(client, monkeypatch):
    from app import config
    from app.services import outbound_service

    monkeypatch.setattr(config, "OUTBOUND_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(config, "OUTBOUND_RETRY_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "demo-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "123456")
    monkeypatch.setattr(config, "GITHUB_TOKEN", "ghp_demo")
    monkeypatch.setattr(config, "GITHUB_REPO", "owner/repo")
    monkeypatch.setattr(config, "OUTBOUND_WEBHOOK_URL", "")

    attempts: dict[tuple[str, str], int] = {}

    def flaky_delivery(*, channel: str, payload: dict, idempotency_key: str):
        key = (channel, idempotency_key)
        attempts[key] = attempts.get(key, 0) + 1
        if attempts[key] == 1:
            raise RuntimeError(f"temporary {channel} failure")

    monkeypatch.setattr(outbound_service, "_deliver_to_channel", flaky_delivery)

    response = client.post(
        "/integrations/snort/alerts",
        json={
            "alerts": [
                {
                    "message": "[**] SQL Injection Attempt [**]",
                    "priority": 1,
                    "src_ip": "192.168.1.20",
                    "dst_ip": "10.0.0.20",
                }
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()["incidents_created"] == 1

    outbound_items = client.get("/outbound/events")
    assert outbound_items.status_code == 200
    items = outbound_items.json()["items"]
    assert len(items) == 2
    assert {item["channel"] for item in items} == {"telegram", "github"}
    assert all(item["status"] == "sent" for item in items)
    assert all(item["attempts"] == 2 for item in items)

    stats = client.get("/outbound/events/stats/summary")
    assert stats.status_code == 200
    payload = stats.json()
    assert payload["total_events"] == 2
    assert payload["sent_events"] == 2


def test_outbound_idempotency_uses_channel_and_event_key(monkeypatch):
    from app import config
    from app.database.db import SessionLocal
    from app.database.repository import create_incident, list_outbound_events
    from app.services import outbound_service

    monkeypatch.setattr(config, "OUTBOUND_MIN_SEVERITY", "HIGH")
    monkeypatch.setattr(config, "OUTBOUND_RETRY_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", "demo-token")
    monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", "123456")
    monkeypatch.setattr(config, "GITHUB_TOKEN", "")
    monkeypatch.setattr(config, "GITHUB_REPO", "")
    monkeypatch.setattr(config, "OUTBOUND_WEBHOOK_URL", "")

    calls = {"count": 0}

    def ok_delivery(*, channel: str, payload: dict, idempotency_key: str):
        calls["count"] += 1

    monkeypatch.setattr(outbound_service, "_deliver_to_channel", ok_delivery)

    with SessionLocal() as db:
        incident = create_incident(
            db,
            source="snort",
            message="Critical alert for 10.0.0.9",
            severity="CRITICAL",
            status="new",
        )
        outbound_service.dispatch_incident_event(
            db,
            incident=incident,
            event_type="incident.created",
            event_key="evt-fixed",
        )
        outbound_service.dispatch_incident_event(
            db,
            incident=incident,
            event_type="incident.created",
            event_key="evt-fixed",
        )
        items = list_outbound_events(db, limit=50)

    assert calls["count"] == 1
    assert len(items) == 1
    assert items[0].channel == "telegram"
    assert items[0].status == "sent"
    assert items[0].attempts == 1


def test_chat_help_menu_is_available(client):
    response = client.post("/chat", json={"message": "допомога"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "text"
    assert "[Меню Користувача]" in payload["message"]
    assert "повна перевірка <ip>" in payload["message"]

    response_en = client.post("/chat", json={"message": "help!"})
    assert response_en.status_code == 200
    payload_en = response_en.json()
    assert payload_en["type"] == "text"
    assert payload_en["message"] == payload["message"]


def test_chat_full_check_runs_pipeline(client):
    response = client.post("/chat", json={"message": "повна перевірка 127.0.0.1"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "text"
    assert "[Full Check]" in payload["message"]
    assert "SOC Snapshot:" in payload["message"]


def test_chat_ukrainian_incident_and_error_commands(client):
    incidents = client.post("/chat", json={"message": "покажи інциденти"})
    assert incidents.status_code == 200
    assert incidents.json()["type"] == "text"

    errors = client.post("/chat", json={"message": "покажи помилки"})
    assert errors.status_code == 200
    assert errors.json()["type"] == "text"


def test_chat_understands_natural_ukrainian_help_variant(client):
    response = client.post("/chat", json={"message": "допоможи, будь ласка"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "text"
    assert "[Меню Користувача]" in payload["message"]


def test_chat_help_topic_scan(client):
    response = client.post("/chat", json={"message": "допомога сканування"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "text"
    assert "[Допомога: Сканування]" in payload["message"]
    assert "повна перевірка" in payload["message"]


def test_chat_platform_status_and_roadmap(client):
    status = client.post("/chat", json={"message": "статус системи"})
    assert status.status_code == 200
    status_payload = status.json()
    assert status_payload["type"] == "text"
    assert "[Статус Системи]" in status_payload["message"]
    assert "CVE records:" in status_payload["message"]

    roadmap = client.post("/chat", json={"message": "план розвитку"})
    assert roadmap.status_code == 200
    roadmap_payload = roadmap.json()
    assert roadmap_payload["type"] == "text"
    assert "[План Розвитку Диплому]" in roadmap_payload["message"]
def test_knowledge_seed_real_world_pack_is_available(client):
    first = client.post("/knowledge/cves/seed/real-world")
    assert first.status_code == 200
    payload = first.json()
    assert payload["source"] == "real-world-curated-pack"
    assert payload["imported_total"] >= 40
    assert payload["created"] + payload["updated"] == payload["imported_total"]

    second = client.post("/knowledge/cves/seed/real-world")
    assert second.status_code == 200
    second_payload = second.json()
    assert second_payload["created"] == 0
    assert second_payload["updated"] == second_payload["imported_total"]


def test_assets_discovered_returns_latest_open_ports(client, monkeypatch):
    from app.services import scan_service

    def fake_discover_open_tcp_ports(*, target, ports, timeout_ms):
        return [22, 5432], "socket-fallback"

    monkeypatch.setattr(scan_service, "discover_open_tcp_ports", fake_discover_open_tcp_ports)

    scan = client.post("/integrations/openvas/scan/active", json={"target": "127.0.0.1"})
    assert scan.status_code == 200

    discovered = client.get("/assets/discovered", params={"limit": 10})
    assert discovered.status_code == 200
    items = discovered.json()["items"]
    assert len(items) >= 1

    host = next((item for item in items if item["ip"] == "127.0.0.1"), None)
    assert host is not None
    assert host["latest_open_ports"] == [22, 5432]
    assert host["latest_scan_profile"]


def test_chat_show_incidents_returns_markdown_table(client):
    client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    response = client.post("/chat", json={"message": "show incidents"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["type"] == "text"
    assert "| detected_at | severity | status | source | ATT&CK | message |" in payload["message"]


def test_stream_soc_live_once_returns_snapshot(client):
    response = client.get("/stream/soc-live", params={"once": "true", "limit": 4})
    assert response.status_code == 200
    body = response.text
    assert "event: snapshot" in body
    assert '"incident_stats"' in body
    assert '"scan_jobs"' in body


def test_stream_soc_live_rbac_with_query_user_key(client, monkeypatch):
    from app.api import stream

    monkeypatch.setattr(stream, "RBAC_ENABLED", True)
    monkeypatch.setattr(stream, "RBAC_KEY_TO_ROLE", {"analyst-key": "analyst"})

    unauthorized = client.get("/stream/soc-live", params={"once": "true"})
    assert unauthorized.status_code == 401

    authorized = client.get(
        "/stream/soc-live",
        params={"once": "true", "user_key": "analyst-key"},
    )
    assert authorized.status_code == 200
    assert "event: snapshot" in authorized.text


def test_stream_soc_live_rejects_query_key_when_disabled(client, monkeypatch):
    from app.api import stream

    monkeypatch.setattr(stream, "RBAC_ENABLED", True)
    monkeypatch.setattr(stream, "STREAM_ALLOW_QUERY_USER_KEY", False)
    monkeypatch.setattr(stream, "RBAC_KEY_TO_ROLE", {"analyst-key": "analyst"})

    denied = client.get(
        "/stream/soc-live",
        params={"once": "true", "user_key": "analyst-key"},
    )
    assert denied.status_code == 401

    allowed = client.get(
        "/stream/soc-live",
        params={"once": "true"},
        headers={"X-User-Key": "analyst-key"},
    )
    assert allowed.status_code == 200
    assert "event: snapshot" in allowed.text


def test_chat_requires_key_when_rbac_and_chat_auth_enabled(client, monkeypatch):
    from app.api import chat, rbac

    monkeypatch.setattr(chat, "CHAT_AUTH_REQUIRED", True)
    monkeypatch.setattr(rbac, "RBAC_ENABLED", True)
    monkeypatch.setattr(rbac, "RBAC_KEY_TO_ROLE", {"analyst-key": "analyst"})

    denied = client.post("/chat", json={"message": "help"})
    assert denied.status_code == 401

    allowed = client.post(
        "/chat",
        json={"message": "help"},
        headers={"X-User-Key": "analyst-key"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["type"] == "text"


def test_integrations_fail_closed_when_auth_required_and_server_key_missing(client, monkeypatch):
    from app.api import dependencies

    monkeypatch.setattr(dependencies, "INTEGRATION_AUTH_REQUIRED", True)
    monkeypatch.setattr(dependencies, "INTEGRATION_API_KEY", "")

    response = client.post("/integrations/openvas/scan", json={"target": "10.0.0.5"})
    assert response.status_code == 503


def test_incident_items_include_attack_enrichment(client):
    response = client.post(
        "/integrations/openvas/scan/active",
        json={"target": "127.0.0.1", "ports": [22, 80], "timeout_ms": 120},
    )
    assert response.status_code == 200

    incidents = client.get("/incidents")
    assert incidents.status_code == 200
    items = incidents.json()["items"]
    assert len(items) >= 1
    assert any(item.get("attack_technique_id") for item in items)


def test_incidents_filter_by_attack_technique(client):
    response = client.post(
        "/integrations/openvas/scan/active",
        json={"target": "127.0.0.1", "ports": [22, 80], "timeout_ms": 120},
    )
    assert response.status_code == 200

    filtered = client.get("/incidents", params={"attack_technique": "T1595"})
    assert filtered.status_code == 200
    items = filtered.json()["items"]
    assert len(items) >= 1
    assert all(item["attack_technique_id"] == "T1595" for item in items)
