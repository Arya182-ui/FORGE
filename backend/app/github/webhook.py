import hmac
import hashlib
from typing import Tuple, Dict, Any, Optional


def verify_github_signature(payload_bytes: bytes, signature_header: Optional[str], secret: str) -> bool:
    """
    Validates GitHub webhook HMAC SHA-256 signature (X-Hub-Signature-256).
    Returns True if signature is valid.
    """
    if not secret:
        return True  # If no secret is configured, bypass check (for local development)

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, signature_header)


def parse_pr_event(payload: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str]]:
    """
    Parses GitHub PR payload.
    Returns (action, repo_full_name, pr_number, head_sha).
    """
    action = payload.get("action")
    pr_data = payload.get("pull_request", {})
    repo_data = payload.get("repository", {})

    repo_full_name = repo_data.get("full_name")
    pr_number = pr_data.get("number")
    head_sha = pr_data.get("head", {}).get("sha")

    return action, repo_full_name, pr_number, head_sha
