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
    assert payload["scan_profile"] in {"tcp-default", "tcp-custom"}
    assert payload["scanned_ports"] == 3
    assert "incidents_created" in payload
    assert "incidents_updated" in payload


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
