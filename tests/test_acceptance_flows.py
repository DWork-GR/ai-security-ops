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
    assert "Incidents: created=" in payload["message"]
    assert "SOC analysis summary" in payload["message"]


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
