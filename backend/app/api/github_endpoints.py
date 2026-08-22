from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, HTTPException, Header, status
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.github.webhook import verify_github_signature, parse_pr_event
from backend.app.github.service import GitHubPRScannerService

router = APIRouter(prefix="/github", tags=["GitHub Integration"])


class TestPRScanRequest(BaseModel):
    repo_full_name: str = Field(..., example="owner/repo")
    pr_number: int = Field(..., example="1")
    target_path: Optional[str] = Field("./examples/vulnerable", description="Local project path to simulate PR scan")


@router.get("/status")
def github_status():
    return {
        "status": "active",
        "webhook_secret_configured": bool(settings.GITHUB_WEBHOOK_SECRET),
        "github_token_configured": bool(settings.GITHUB_TOKEN),
        "supported_events": ["pull_request.opened", "pull_request.reopened", "pull_request.synchronize"]
    }


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None),
    x_hub_signature_256: Optional[str] = Header(None)
):
    body_bytes = await request.body()

    # Step 1: Validate HMAC SHA-256 Signature
    if settings.GITHUB_WEBHOOK_SECRET and x_hub_signature_256:
        if not verify_github_signature(body_bytes, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature.")

    payload = await request.json()

    # Step 2: Handle pull_request events
    if x_github_event == "pull_request":
        action, repo_name, pr_num, head_sha = parse_pr_event(payload)
        if action in {"opened", "reopened", "synchronize"} and repo_name and pr_num:
            service = GitHubPRScannerService()
            result = service.process_pr_scan(repo_name, pr_num, head_sha or "head")
            return {"status": "processed", "result": result}

    return {"status": "ignored", "event": x_github_event}


@router.post("/test-pr-scan")
def test_pr_scan(request: TestPRScanRequest):
    """
    Simulates a GitHub PR scan locally using specified code files.
    Allows easy demonstration without a live GitHub webhook tunnel.
    """
    from backend.app.scanner.engine import ScannerEngine
    engine = ScannerEngine()

    try:
        report = engine.run_scan(request.target_path, save_to_db=True)
        summary = report.summary
        findings = report.findings

        comment_body = f"<!-- FORGE-PR-SECURITY-REVIEW -->\n"
        comment_body += f"# 🛡️ FORGE — PR Security Analysis Review (Simulated)\n\n"
        comment_body += f"Simulated security scan for repository **{request.repo_full_name}** PR **#{request.pr_number}**.\n\n"
        comment_body += f"### Scan Summary\n"
        comment_body += f"- **Scanned Files**: {summary.scanned_files_count}\n"
        comment_body += f"- **Total Issues Found**: **{summary.total_findings_count}**\n\n"

        if not findings:
            comment_body += "✅ **No security vulnerabilities found in PR files!**\n"
        else:
            comment_body += "### ⚠️ Findings Overview\n"
            comment_body += "| Severity | Rule | File | Finding Title |\n"
            comment_body += "| --- | --- | --- | --- |\n"
            for f in findings:
                comment_body += f"| **{f.severity}** | `{f.rule_id}` | `{f.file_path}:{f.line_number}` | {f.title} |\n"

        return {
            "status": "success",
            "repo_full_name": request.repo_full_name,
            "pr_number": request.pr_number,
            "summary": summary,
            "simulated_github_comment": comment_body
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Simulation failed: {str(e)}")
