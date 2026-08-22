import httpx
from typing import List, Dict, Any, Optional
from backend.app.config import settings


class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.GITHUB_TOKEN
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Forge-Security-Platform/0.1.0"
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    def get_pr_files(self, repo_full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Fetches list of modified files in a PR."""
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}/files"
        try:
            res = httpx.get(url, headers=self.headers, timeout=10.0)
            if res.status_code == 200:
                return res.json()
        except Exception:
            pass
        return []

    def get_file_content(self, raw_url: str) -> Optional[str]:
        """Fetches raw file content from GitHub raw URL."""
        try:
            res = httpx.get(raw_url, headers=self.headers, timeout=10.0)
            if res.status_code == 200:
                return res.text
        except Exception:
            pass
        return None

    def list_pr_comments(self, repo_full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Lists issue comments on a PR."""
        url = f"{self.base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"
        try:
            res = httpx.get(url, headers=self.headers, timeout=10.0)
            if res.status_code == 200:
                return res.json()
        except Exception:
            pass
        return []

    def post_pr_comment(self, repo_full_name: str, pr_number: int, body: str) -> bool:
        """Posts a new comment on a PR."""
        url = f"{self.base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"
        try:
            res = httpx.post(url, headers=self.headers, json={"body": body}, timeout=10.0)
            return res.status_code in {200, 201}
        except Exception:
            return False

    def update_pr_comment(self, repo_full_name: str, comment_id: int, body: str) -> bool:
        """Updates an existing comment on a PR to prevent duplicate comment spam."""
        url = f"{self.base_url}/repos/{repo_full_name}/issues/comments/{comment_id}"
        try:
            res = httpx.patch(url, headers=self.headers, json={"body": body}, timeout=10.0)
            return res.status_code == 200
        except Exception:
            return False
