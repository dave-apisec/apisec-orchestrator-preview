"""Keep each scanned repo's two GitHub ids bound to one APIsec application.

APIsec finds a repo's application by the repo id sent at registration. Surface
CLI 1.2+ sends ``github:<owner>/<repo>``, which is what scans run by the CLI
itself and APIsec's migration tooling use. Orchestrator releases before 1.1
and the APIsec GitHub Action send ``github:<numeric id>``. Binding both ids to
the same application lets every scanner find it, so none creates a duplicate.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlparse

TIMEOUT = 60


class ApisecError(Exception):
    pass


def name_id(full_name: str, server_url: str = "") -> str:
    """The id Surface CLI 1.2 derives in GitHub Actions (core/ci_identity.py)."""
    owner, name = full_name.strip().lower().split("/", 1)
    server = (server_url or "https://github.com").strip().rstrip("/")
    host = (urlparse(server if "://" in server else f"https://{server}").hostname or "github.com").lower()
    return f"github:{owner}/{name}" if host == "github.com" else f"github:{host}/{owner}/{name}"


def numeric_id(repo_id: str) -> str:
    return f"github:{repo_id}"


def _post(endpoint: str, pat: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(
        endpoint.rstrip("/") + path,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    req.add_unredirected_header("Authorization", f"Bearer {pat}")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raise ApisecError(f"POST {path} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ApisecError(f"POST {path} failed: {exc}") from exc


class Repo:
    """The registration fields APIsec requires, read from the checkout."""

    def __init__(self, path: str, full_name: str, server_url: str = ""):
        self.full_name = full_name
        self.name = full_name.split("/", 1)[1]
        self.url = f"{(server_url or 'https://github.com').rstrip('/')}/{full_name}"
        self.commit = _git(path, "rev-parse", "HEAD") or "0" * 40
        self.branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD") or "HEAD"

    def body(self, canonical_id: str, app_id: str | None = None) -> dict:
        body = {
            "repoName": self.name,
            "repoUrl": self.url,
            "branch": self.branch,
            "commitSha": self.commit,
            "scmProvider": "github",
            "canonicalRepoId": canonical_id,
        }
        if app_id:
            body["existingAppId"] = app_id
        return body


def _git(path: str, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def lookup(endpoint: str, pat: str, ids: list[str]) -> dict[str, str | None] | None:
    """Application each id is bound to (None if unbound). None if the token may not look."""
    try:
        data = _post(
            endpoint,
            pat,
            "/v1/applications/surface/repo-bindings",
            {"repos": [{"canonicalRepoId": i} for i in ids]},
        )
    except ApisecError as exc:
        # The lookup needs an ADMIN token; other tokens fall back to registration.
        if isinstance(exc.__cause__, urllib.error.HTTPError) and exc.__cause__.code in (401, 403, 404):
            return None
        raise
    return {r["canonicalRepoId"]: r.get("applicationId") for r in data.get("repos", [])}


def resolve(endpoint: str, pat: str, repo: Repo, canonical_id: str) -> str:
    """Application ``canonical_id`` resolves to. Creates one if it is unbound."""
    app_id = _post(endpoint, pat, "/v1/applications/surface", repo.body(canonical_id)).get("appId")
    if not app_id:
        raise ApisecError("registration response has no appId")
    return str(app_id)


def bind(endpoint: str, pat: str, repo: Repo, canonical_id: str, app_id: str) -> None:
    """Bind ``canonical_id`` to ``app_id`` unless it is already bound elsewhere (left as is)."""
    _post(endpoint, pat, "/v1/applications/surface", repo.body(canonical_id, app_id))
