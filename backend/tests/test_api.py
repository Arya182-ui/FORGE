from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_api_list_rules():
    response = client.get("/api/rules")
    assert response.status_code == 200
    rules = response.json()
    assert isinstance(rules, list)
    assert len(rules) >= 7


def test_api_create_scan():
    payload = {
        "target_path": "examples/vulnerable",
        "language": "python"
    }
    response = client.post("/api/scans", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total_findings_count"] >= 8
    
    scan_id = data["summary"]["id"]
    
    # Test GET /api/scans/{scan_id}
    res_summary = client.get(f"/api/scans/{scan_id}")
    assert res_summary.status_code == 200
    assert res_summary.json()["id"] == scan_id

    # Test GET /api/scans/{scan_id}/findings
    res_findings = client.get(f"/api/scans/{scan_id}/findings")
    assert res_findings.status_code == 200
    findings_list = res_findings.json()
    assert len(findings_list) >= 8

    # Test GET /api/findings/{finding_id}
    first_finding_id = findings_list[0]["id"]
    res_single = client.get(f"/api/findings/{first_finding_id}")
    assert res_single.status_code == 200
    assert res_single.json()["id"] == first_finding_id
