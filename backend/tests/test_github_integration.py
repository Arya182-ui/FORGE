from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.github.webhook import verify_github_signature, parse_pr_event
import hmac
import hashlib

client = TestClient(app)


def test_github_signature_verification():
    secret = "test_secret_key"
    payload = b'{"action": "opened", "pull_request": {"number": 1}}'

    # Valid signature
    valid_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert verify_github_signature(payload, valid_sig, secret) is True

    # Invalid signature
    assert verify_github_signature(payload, "sha256=invalid_hash_123", secret) is False


def test_parse_pr_event():
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "head": {"sha": "abc123456789"}
        },
        "repository": {
            "full_name": "acme/forge-project"
        }
    }
    action, repo, pr_num, sha = parse_pr_event(payload)
    assert action == "opened"
    assert repo == "acme/forge-project"
    assert pr_num == 42
    assert sha == "abc123456789"


def test_github_status_endpoint():
    response = client.get("/api/github/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"
    assert "pull_request.opened" in data["supported_events"]


def test_github_test_pr_scan_simulation():
    payload = {
        "repo_full_name": "acme/college-project",
        "pr_number": 15,
        "target_path": "examples/vulnerable"
    }
    response = client.post("/api/github/test-pr-scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "FORGE-PR-SECURITY-REVIEW" in data["simulated_github_comment"]
    assert data["summary"]["total_findings_count"] >= 10
