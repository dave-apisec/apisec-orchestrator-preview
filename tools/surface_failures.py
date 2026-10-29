#!/usr/bin/env python3
"""Collect the failed jobs of an APIsec Surface org scan into one bundle to send to APIsec.

Run it on any machine where the GitHub CLI (gh) is logged in to your organization:

    python3 surface_failures.py OWNER/REPO               # newest completed org-scan run
    python3 surface_failures.py OWNER/REPO --since 7d    # every failed run in the last 7 days
    python3 surface_failures.py https://github.com/OWNER/REPO/actions/runs/123456

OWNER/REPO is the repository that runs the "APIsec Surface org scan" workflow. The script only
reads from GitHub. It writes a folder and a .zip into the current directory (or --out): for every
failed job, which repository it scanned, why it failed, what to do about it, and its log. Tokens,
keys and email addresses are removed before anything is written.

Needs Python 3.9+ and gh (https://cli.github.com). No other dependencies.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

__version__ = "1.0.0"

SCHEMA_VERSION = 1
WORKFLOW_NAME = "APIsec Surface org scan"
EXIT_OK, EXIT_USAGE, EXIT_NOT_FOUND = 0, 2, 3
NOT_SUCCESSFUL = {"failure", "cancelled", "timed_out", "startup_failure", "action_required"}
MAX_LOG_BYTES = 4 * 1024 * 1024
CONTEXT_LINES = 20


class UsageError(Exception):
    """Exits 2: the arguments, gh or its login are not usable."""


class NotFoundError(Exception):
    """Exits 3: no matching repository, workflow or run."""


# =============================================================================
# gh
# =============================================================================


class GhError(Exception):
    def __init__(self, message: str, status: int | None = None, detail: str = ""):
        super().__init__(message)
        self.status = status
        self.detail = detail or message


_STATUS_RE = re.compile(r"HTTP (\d{3})")
_TRANSIENT_RE = re.compile(
    r"rate limit|timeout|timed out|connection reset|connection refused|EOF|TLS handshake|"
    r"i/o timeout|no such host|temporary failure|network is unreachable",
    re.IGNORECASE,
)
_RETRY_STATUS = {429, 500, 502, 503, 504}


def _default_runner(args: list[str], timeout: float) -> tuple[int, bytes, str]:
    env = {"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1", "GH_PAGER": ""}
    proc = subprocess.run(
        args, capture_output=True, timeout=timeout, env={**os.environ, **env}, stdin=subprocess.DEVNULL
    )
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", errors="replace")


class Gh:
    """Read-only GitHub REST calls through the gh CLI, so the user's own gh login is used as is."""

    def __init__(self, hostname: str = "", runner=None, sleep=time.sleep, attempts: int = 5):
        self.hostname = hostname
        self.runner = runner or _default_runner
        self.sleep = sleep
        self.attempts = attempts
        self._escape_flag: bool | None = None
        self._lock = threading.Lock()
        self.exe = "gh"

    def _base(self) -> list[str]:
        args = [self.exe, "api"]
        if self.hostname:
            args += ["--hostname", self.hostname]
        return args

    def raw(self, path: str, *, log: bool = False) -> bytes:
        args = self._base()
        if log and self._escape_flag is not False:
            args.append("--allow-escape-sequences")
        args.append(path)
        delay = 3.0
        for attempt in range(1, self.attempts + 1):
            try:
                rc, out, err = self.runner(args, 300 if log else 120)
            except subprocess.TimeoutExpired:
                rc, out, err = 1, b"", "gh timed out"
            if rc == 0:
                return out
            if log and "--allow-escape-sequences" in args and "unknown flag" in err:
                # gh before 2.7x has no such flag and also no such refusal.
                with self._lock:
                    self._escape_flag = False
                args.remove("--allow-escape-sequences")
                continue
            match = _STATUS_RE.search(err)
            status = int(match.group(1)) if match else None
            transient = status in _RETRY_STATUS or (
                (status in (None, 403)) and _TRANSIENT_RE.search(err) is not None
            )
            if not transient or attempt == self.attempts:
                message = err.strip().splitlines()[-1] if err.strip() else f"gh exited {rc}"
                raise GhError(message, status, err)
            # GitHub asks for at least a minute's pause after a secondary rate limit.
            self.sleep(max(delay, 61.0) if "rate limit" in err.lower() else delay)
            delay = min(delay * 3, 60.0)
        raise GhError("gh failed")  # unreachable

    def json(self, path: str):
        out = self.raw(path)
        try:
            return json.loads(out.decode("utf-8", errors="replace").lstrip("\ufeff") or "null")
        except json.JSONDecodeError as exc:
            raise GhError(f"unexpected response from {path}: {exc}") from exc

    def paged(self, path: str, key: str | None = None, limit: int = 10000) -> list:
        """Every item of a list endpoint, one page of 100 at a time.

        Done here rather than with `gh api --paginate`, whose output for object responses
        (`{"total_count":…,"jobs":[…]}`) is several JSON documents back to back on older gh.
        """
        sep = "&" if "?" in path else "?"
        items: list = []
        page = 1
        while True:
            data = self.json(f"{path}{sep}per_page=100&page={page}")
            batch = data if isinstance(data, list) else (data or {}).get(key or "", []) or []
            items.extend(batch)
            total = data.get("total_count") if isinstance(data, dict) else None
            if len(batch) < 100 or (total is not None and len(items) >= total) or len(items) >= limit:
                return items[:limit]
            page += 1


def preflight(gh: Gh, repo: str) -> dict:
    exe = shutil.which("gh")
    if gh.runner is _default_runner:
        if not exe:
            raise UsageError(
                "The GitHub CLI (gh) is not installed or not on PATH. Install it from "
                "https://cli.github.com, run `gh auth login`, then run this again."
            )
        gh.exe = exe
    try:
        return gh.json(f"repos/{repo}")
    except GhError as exc:
        text = exc.detail
        host = gh.hostname or "github.com"
        if exc.status == 401 or "auth login" in text or "not logged" in text.lower():
            raise UsageError(
                f"gh is not logged in to {host}. Run `gh auth login --hostname {host}`."
            ) from exc
        if exc.status == 403 and "SAML" in text:
            raise UsageError(
                f"Your gh token is not authorized for this organization's SSO. Run "
                f"`gh auth refresh --hostname {host}` and approve SSO for the org, then try again."
            ) from exc
        if exc.status == 404:
            raise NotFoundError(
                f"{repo} was not found on {host}, or your gh login cannot see it. Check the name, and "
                f"that `gh auth status` shows an account with access (scope `repo` for private repos)."
            ) from exc
        raise UsageError(f"Could not reach {repo} through gh: {exc}") from exc


# =============================================================================
# Targets
# =============================================================================

_RUN_URL_RE = re.compile(r"^/([^/]+)/([^/]+)/actions/runs/(\d+)(?:/attempts/(\d+))?")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@dataclass
class RunRef:
    run_id: int
    attempt: int | None = None


def parse_run(value: str) -> tuple[str, str, RunRef]:
    """A run id or run URL -> (host, owner/repo, run). Host and repo are empty for a bare id."""
    value = value.strip()
    if value.isdigit():
        return "", "", RunRef(int(value))
    url = urlparse(value)
    match = _RUN_URL_RE.match(url.path or "")
    if not url.netloc or not match:
        raise UsageError(f"Not a run id or run URL: {value}")
    attempt = int(match.group(4)) if match.group(4) else None
    return url.netloc, f"{match.group(1)}/{match.group(2)}", RunRef(int(match.group(3)), attempt)


def parse_since(value: str, now: datetime) -> datetime:
    match = re.fullmatch(r"(\d+)\s*([hdw])", value.strip().lower())
    if match:
        n, unit = int(match.group(1)), match.group(2)
        return now - timedelta(hours=n * {"h": 1, "d": 24, "w": 168}[unit])
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageError(f"--since takes e.g. 24h, 7d, 2w or a date like 2026-10-01: {value}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _calls_orchestrator(gh: Gh, repo: str, wf: dict) -> bool:
    try:
        data = gh.json(f"repos/{repo}/contents/{quote(wf.get('path', ''))}")
        text = base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
    except (GhError, ValueError, AttributeError):
        return False
    return "apisec-orchestrator/" in text or "apisec-orgscan" in text


def find_workflow(gh: Gh, repo: str, wanted: str = "") -> dict:
    workflows = gh.paged(f"repos/{repo}/actions/workflows", "workflows")
    if wanted:
        key = wanted.strip().lower()
        for wf in workflows:
            path = (wf.get("path") or "").lower()
            if key in (str(wf.get("id")), (wf.get("name") or "").lower(), path, path.rsplit("/", 1)[-1]):
                return wf
        names = ", ".join(f"'{w.get('name')}' ({w.get('path')})" for w in workflows) or "none"
        raise NotFoundError(f"No workflow '{wanted}' in {repo}. Workflows: {names}")
    named = [w for w in workflows if (w.get("name") or "").strip().lower() == WORKFLOW_NAME.lower()]
    if len(named) == 1:
        return named[0]
    candidates = named or workflows
    calling = [w for w in candidates if _calls_orchestrator(gh, repo, w)]
    if len(calling) == 1:
        return calling[0]
    names = ", ".join(f"'{w.get('name')}' ({w.get('path')})" for w in (calling or workflows)) or "none"
    if calling or len(named) > 1:
        names = ", ".join(f"'{w.get('name')}' ({w.get('path')})" for w in (calling or named))
        raise UsageError(f"Several workflows in {repo} run the org scan: {names}. Pick one with --workflow.")
    raise NotFoundError(
        f"No '{WORKFLOW_NAME}' workflow found in {repo}. Workflows: {names}. "
        f"Pass the right repository, or pick one with --workflow."
    )


# =============================================================================
# Logs
# =============================================================================

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")


def decode_log(raw: bytes) -> list[str]:
    """Log bytes -> lines, without escape codes. Timestamps are kept."""
    text = raw.decode("utf-8", errors="replace").lstrip("\ufeff")
    text = _ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return text.split("\n")


def truncate(lines: list[str], limit: int = MAX_LOG_BYTES) -> list[str]:
    """The head and tail of a log too large to send whole. Analysis always sees the full log."""
    if sum(len(x) + 1 for x in lines) <= limit:
        return lines
    head: list[str] = []
    size = 0
    for line in lines:
        size += len(line) + 1
        if size > limit // 4:
            break
        head.append(line)
    tail: list[str] = []
    size = 0
    for line in reversed(lines):
        size += len(line) + 1
        if size > limit * 3 // 4:
            break
        tail.append(line)
    dropped = len(lines) - len(head) - len(tail)
    return [*head, f"[... {dropped} lines left out by surface_failures ...]", *reversed(tail)]


def strip_ts(line: str) -> str:
    return _TS_RE.sub("", line, count=1)


def _decoration(text: str) -> bool:
    """Rich box and table rules, and spinner frames."""
    c = text[:1]
    return bool(c) and ("\u2500" <= c <= "\u259f" or "\u2800" <= c <= "\u28ff")


@dataclass
class Step:
    title: str
    output: list[str] = field(default_factory=list)  # what the step printed, minus group dumps


def split_steps(lines: list[str]) -> list[Step]:
    """Splits a job log at each `##[group]Run …` header. The header group itself (the script and
    its env) is skipped, as are nested groups."""
    steps = [Step("Set up job")]
    depth = 0
    for raw in lines:
        line = strip_ts(raw)
        if line.startswith("##[group]Run "):
            steps.append(Step(line[len("##[group]") :].strip()))
            depth = 1
            continue
        if line.startswith("Post job cleanup."):
            steps.append(Step("Post job cleanup"))
            depth = 0
            continue
        if line.startswith("##[group]"):
            depth += 1
            continue
        if line.startswith("##[endgroup]"):
            depth = max(0, depth - 1)
            continue
        if depth == 0:
            steps[-1].output.append(line)
    return steps


def meaningful(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        text = line.strip()
        if not text or _decoration(text) or text.startswith("[command]"):
            continue
        out.append(text)
    return out


_GENERIC_ERRORS = re.compile(
    r"^(?:Process completed with exit code \d+\.?|The process '.*' failed with exit code \d+|"
    r"The operation was canceled\.?)$"
)
_EXIT_RE = re.compile(r"\(exit (\d+)\)|exit code (\d+)")
_SURFACE_VERSION_RE = re.compile(r"^│?\s*Version:\s*([0-9][\w.+-]*)")
_CLI_VERSION_RE = re.compile(r"^\s*CLI_VERSION:\s*([0-9][\w.+-]*)")
_DRY_RUN_RE = re.compile(r"\bdry_run=(\w+)")
_ANALYZE_RE = re.compile(r"apisec-orgscan scan|apisec-surface\b.*\banalyze")
_BLOCK_MARKERS = ("Manifest upload failed", "Upload failed", "Error:", "ERROR:")


def _block(lines: list[str], start: int, limit: int = 12) -> str:
    """A message Rich wrapped over several lines, joined back into one."""
    parts = []
    for text in lines[start : start + limit]:
        if not text.strip() or text.startswith("##["):
            break
        parts.append(text.strip())
    return re.sub(r"\s+", " ", " ".join(parts))


def analyze_cause(step: Step) -> tuple[str, list[str], int | None]:
    """(cause, context lines, exit code) from the output of the Analyze step."""
    lines = [line.rstrip() for line in step.output]
    first_error = next((i for i, x in enumerate(lines) if x.startswith("##[error]")), len(lines))
    body = lines[:first_error]
    exit_code = None
    for line in lines[first_error:]:
        match = _EXIT_RE.search(line)
        if match:
            exit_code = int(match.group(1) or match.group(2))
            break
    context = [x for x in meaningful(body) if not x.startswith("profile=")][-CONTEXT_LINES:]
    cause = ""
    for i, text in enumerate(body):
        stripped = text.strip()
        if stripped.startswith("Analysis failed:"):
            cause = stripped
            break
        if stripped.startswith(_BLOCK_MARKERS):
            cause = _block(body, i)
            break
        if stripped.startswith("Traceback (most recent call last)"):
            tail = [x for x in body[i + 1 :] if x.strip() and not x.startswith((" ", "\t"))]
            cause = tail[0].strip() if tail else stripped
            break
    if not cause and context:
        cause = context[-1]
    if not cause and first_error < len(lines):
        cause = lines[first_error][len("##[error]") :].strip()
    return cause, context, exit_code


# =============================================================================
# Classification
# =============================================================================


@dataclass(frozen=True)
class Rule:
    category: str
    hint: str
    pattern: str = ""
    step: str = ""
    exit_code: int | None = None
    kind: str = ""
    conclusion: str = ""

    def matches(self, text: str, steps: list[str], exit_code: int | None, kind: str, conclusion: str) -> bool:
        if self.pattern and re.search(self.pattern, text, re.IGNORECASE | re.MULTILINE):
            return True
        if self.step and any(re.search(self.step, s, re.IGNORECASE) for s in steps):
            return True
        if self.exit_code is not None and exit_code == self.exit_code and kind == "scan":
            return True
        if self.kind and kind == self.kind:
            return True
        return bool(self.conclusion) and conclusion == self.conclusion


SEND = "Send this bundle to APIsec."
RULES = [
    Rule(
        "billing",
        "GitHub did not start the job because the org's Actions billing or spending limit blocked it. "
        "Fix it under Settings > Billing and plans, then re-run the workflow.",
        pattern=r"account payments have failed|spending limit",
    ),
    Rule(
        "timeout",
        "The scan reached the job's time limit. Tell APIsec which repositories time out; until then, "
        "skip them with the EXCLUDE_REPOS variable.",
        pattern=r"exceeded the maximum execution time|has timed out",
        conclusion="timed_out",
    ),
    Rule(
        "run-cancelled",
        "The run was cancelled, by hand or by a newer run. Re-run it; nothing needs fixing.",
        pattern=r"run was canceled by|canceled by @|higher priority waiting request",
    ),
    Rule(
        "runner-lost",
        "The runner stopped responding mid-job. Usually transient: re-run. If it repeats on "
        "self-hosted runners, check their health and capacity.",
        pattern=r"lost communication with the server|received a shutdown signal|"
        r"hosted runner encountered an error|No runner matching",
    ),
    Rule(
        "github-app-token",
        "The GitHub App could not mint a token. Check ORCHESTRATOR_APP_ID and "
        "ORCHESTRATOR_APP_PRIVATE_KEY, and that the app is installed on the org with Contents: read "
        "and Metadata: read.",
        pattern=r"could not get a token for|Failed to create (?:an )?(?:installation )?token|"
        r"A JSON web token could not be decoded",
        step=r"create-github-app-token|Mint GitHub App token",
    ),
    Rule(
        "missing-setting",
        "A required setting is missing. Add the variable or secret named in the cause, at org or "
        "repository level.",
        pattern=r"Set the APISEC_ENDPOINT|Set the APISEC_TOKEN",
    ),
    Rule(
        "github-access",
        "The workflow's GitHub credential cannot read this repository. Add the repository to the "
        "GitHub App installation (or to the token's repository list), then re-run.",
        pattern=r"Bad credentials|Resource not accessible by|Repository not found|"
        r"could not read Username|terminal prompts disabled",
    ),
    Rule(
        "apisec-app-lookup",
        "The scan could not look up this repository's APIsec application, which needs an APISEC_TOKEN "
        "with the Admin role. " + SEND,
        pattern=r"could not check its APIsec application",
    ),
    Rule(
        "apisec-auth",
        "APIsec rejected the token. Check that the APISEC_TOKEN secret is current and that its user "
        "can access the tenant.",
        pattern=r"rejected the API key|HTTP 401|invalid (?:api key|token)",
        exit_code=5,
    ),
    Rule(
        "manifest-too-large",
        "The repository's API manifest is larger than APIsec accepts. " + SEND,
        pattern=r"HTTP 413|too large",
    ),
    Rule(
        "apisec-unreachable",
        "The runner could not reach APIsec. Check the APISEC_ENDPOINT variable and the runner's "
        "outbound network access (proxy, firewall, TLS inspection).",
        pattern=r"Connection refused|Name or service not known|nodename nor servname|Failed to resolve|"
        r"ConnectTimeout|ConnectError|Read timed out|CERTIFICATE_VERIFY_FAILED",
    ),
    Rule(
        "apisec-server-error",
        "APIsec returned a server error. Re-run the workflow; if the same repository fails again, "
        + SEND[0].lower()
        + SEND[1:],
        pattern=r"HTTP 5\d\d\b",
    ),
    Rule(
        "runner-resources",
        "The runner ran out of disk or memory. Run this repository on a larger runner, or skip it with "
        "EXCLUDE_REPOS, and tell APIsec.",
        pattern=r"No space left on device|MemoryError|out of memory|exit code 137\b|\bKilled\b",
    ),
    Rule(
        "install-failed",
        "Installing apisec-orgscan or apisec-surface from PyPI failed. Check that the runner can reach "
        "PyPI or your mirror, and APISEC_CLI_VERSION if you pinned it.",
        pattern=r"No matching distribution|Could not find a version that satisfies|ResolutionImpossible",
        step=r"^Install$|pip install",
    ),
    Rule(
        "runner-setup",
        "Setting up Python on the runner failed. Self-hosted runners must be Linux (x64 or arm64); "
        "macOS runners are not supported.",
        pattern=r"hostedtoolcache|was not found in the local cache",
        step=r"setup-python",
    ),
    Rule(
        "checkout-failed",
        "Checking out the repository failed. Check that the GitHub App or token can read it.",
        step=r"checkout",
    ),
    Rule(
        "upload-failed",
        "The analysis ran but uploading it to APIsec failed. " + SEND,
        pattern=r"upload failed",
        exit_code=2,
    ),
    Rule("config-invalid", "The Surface configuration is invalid. " + SEND, exit_code=4),
    Rule(
        "analysis-crash",
        "APIsec Surface failed while analyzing this repository. This is a product issue, not a setup "
        "problem. " + SEND,
        pattern=r"^Analysis failed:|Traceback \(most recent call last\)",
        exit_code=1,
    ),
    Rule(
        "store-update",
        "Saving the scan record failed; the next run rescans the affected repositories. Usually "
        "transient. If it repeats, " + SEND[0].lower() + SEND[1:],
        kind="update-store",
    ),
    Rule("cancelled", "The job was cancelled. Re-run the workflow.", conclusion="cancelled"),
]
UNKNOWN_HINT = "No known failure pattern matched. " + SEND


def classify(text: str, steps: list[str], exit_code: int | None, kind: str, conclusion: str):
    for rule in RULES:
        if rule.matches(text, steps, exit_code, kind, conclusion):
            return rule.category, rule.hint
    return "unknown", UNKNOWN_HINT


# =============================================================================
# Redaction
# =============================================================================

_SECRET_NAME = (
    r"[A-Z0-9_]*?(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|PAT|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)"
    r"(?:_[A-Z0-9]+)*"
)
_REDACTIONS = [
    # A key cut short by log truncation has no END line, so everything after BEGIN goes.
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*)", re.S),
        "private-key",
    ),
    # Base64 key material on lines of its own, as in a key body printed without its BEGIN line.
    (re.compile(r"(?m)^((?:\d{4}-\d\d-\d\dT[\d:.]+Z )?[ \t]*)[A-Za-z0-9+/]{60,}={0,2}$"), "line"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "github-token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "github-token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "jwt"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws-key"),
    (re.compile(r"\b(?:npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{50,}|xox[abprs]-[A-Za-z0-9-]{10,})"), "token"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"), "api-key"),
    # Authorization headers, whatever the scheme and however short the credential.
    (
        re.compile(
            r"(?i)(\bauthorization[\"']?[ \t]*[:=][ \t]*[\"']?(?:(?:basic|bearer|token|digest)[ \t]+)?)"
            r"(?!\*\*\*|(?:basic|bearer|token|digest)[ \t]+\*\*\*)[^\s\"',;]+"
        ),
        "value",
    ),
    (re.compile(r"(?i)\b((?:bearer|basic)[ \t]+)(?!\*\*\*|\[REDACTED)[A-Za-z0-9._~+/=-]{16,}"), "value"),
    (re.compile(r"(x-access-token:)[^@\s]+(@)"), None),
    # Credentials in a URL; the password may itself contain @ or /.
    (re.compile(r"(https?://)[^/\s:@]+:\S*?(@)(?=[^@/\s]+(?:[/:?#\s]|$))"), None),
    # NAME=value and NAME: value for secret-looking environment names, quoted keys in JSON or
    # YAML ("password": "x"), x-api-key style headers, and --password value flags. Lowercase
    # prose ("invalid token: HTTP 401") is left alone.
    (
        re.compile(
            r"(\b" + _SECRET_NAME + r"[ \t]*[:=][ \t]*)"
            r"(?!\*\*\*|\$|\[REDACTED)(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']+)"
        ),
        "value",
    ),
    (
        re.compile(
            r"(?i)([\"'][\w-]*(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)"
            r"[\"'][ \t]*[:=][ \t]*)(?![\"']?\*\*\*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s,}\]]+)"
        ),
        "value",
    ),
    (
        re.compile(r"(?i)(\bx-[\w-]*(?:api-?key|token|secret)[ \t]*:[ \t]*)(?!\*\*\*|\[REDACTED)(\S+)"),
        "value",
    ),
    (
        re.compile(
            r"(?i)(--(?:password|passwd|token|api-key|apikey|secret|pat)(?:[ \t]+|=))"
            r"(?!\*\*\*|-|\[REDACTED)(\S+)"
        ),
        "value",
    ),
    (
        re.compile(
            r"(?<![\w.+-])(?!git@)[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"
        ),
        "email",
    ),
]


class Redactor:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.count = 0

    def __call__(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        for pattern, label in _REDACTIONS:
            text, n = pattern.subn(lambda m, label=label: self._replace(m, label), text)
            self.count += n
        return text

    @staticmethod
    def _replace(match: re.Match, label: str | None) -> str:
        if label == "value":
            return f"{match.group(1)}[REDACTED]"
        if label == "line":
            return f"{match.group(1)}[REDACTED:key-material]"
        if label is None:
            # Keep the surrounding syntax (`Bearer `, `https://`, `@`) and drop only the secret.
            groups = [g for g in match.groups() if g is not None]
            return f"{groups[0]}[REDACTED]{''.join(groups[1:])}"
        return f"[REDACTED:{label}]"


# =============================================================================
# Collection
# =============================================================================


@dataclass
class Failure:
    run_id: int
    job_id: int
    job_name: str
    job_url: str
    kind: str
    repo: str
    conclusion: str
    failed_steps: list[str]
    started_at: str
    completed_at: str
    runner: str
    run_attempt: int = 1
    category: str = "unknown"
    hint: str = ""
    cause: str = ""
    context: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    exit_code: int | None = None
    surface_version: str = ""
    dry_run: str = ""
    log_status: str = ""
    log_file: str = ""
    log_lines: list[str] = field(default_factory=list, repr=False)


@dataclass
class RunSummary:
    run_id: int
    url: str
    attempt: int
    event: str
    created_at: str
    conclusion: str
    jobs_total: int = 0
    scan_jobs: int = 0
    scan_succeeded: int = 0
    skipped: int = 0
    not_successful: int = 0
    plan_failed: bool = False


_SCAN_NAME_RE = re.compile(r"(?:^|/ )Scan (.+)$")
_NOISE_RE = re.compile(
    r"Node\.js \d+ (?:is deprecated|actions are deprecated)|label will migrate to|"
    r"^Process completed with exit code \d+\.?$|^The operation was canceled\.?$|"
    r"^The process '.*' failed with exit code \d+$"
)
_SPECIAL_RE = re.compile(
    r"account payments have failed|spending limit|exceeded the maximum execution time|has timed out|"
    r"run was canceled by|canceled by @|higher priority waiting request|lost communication with the server|"
    r"received a shutdown signal|hosted runner encountered an error",
    re.IGNORECASE,
)


def job_kind(name: str) -> tuple[str, str]:
    leaf = name.rsplit(" / ", 1)[-1].strip()
    match = _SCAN_NAME_RE.search(name)
    if match and "${{" not in match.group(1):
        return "scan", match.group(1).strip()
    if leaf == "Plan":
        return "plan", ""
    if leaf == "Update store":
        return "update-store", ""
    return "other", ""


def analyze_job(f: Failure, annotations: list[dict], log: list[str] | None) -> Failure:
    """Fills in cause, category and hint from what GitHub recorded for the job."""
    exit_codes: list[int] = []
    kept: list[tuple[str, str]] = []
    for a in annotations:
        message = (a.get("message") or "").strip()
        level = a.get("annotation_level") or ""
        match = re.search(r"exit code (\d+)", message)
        if match:
            exit_codes.append(int(match.group(1)))
        if level == "notice" or not message or _NOISE_RE.search(message):
            continue
        kept.append(((a.get("title") or "").strip(), message))
    f.annotations = [f"{t}: {m}" if t else m for t, m in kept]

    analyze_steps: list[Step] = []
    errors: list[str] = []
    if log is not None:
        f.log_lines = log
        steps = split_steps(log)
        analyze_steps = [s for s in steps if _ANALYZE_RE.search(s.title)]
        for step in steps:
            for line in step.output:
                if line.startswith("##[error]"):
                    message = line[len("##[error]") :].strip()
                    if message and not _GENERIC_ERRORS.match(message):
                        errors.append(message)
        for raw in log:
            line = strip_ts(raw)
            if not f.surface_version:
                m = _SURFACE_VERSION_RE.match(line) or _CLI_VERSION_RE.match(line)
                if m:
                    f.surface_version = m.group(1)
            if not f.dry_run:
                m = _DRY_RUN_RE.search(line)
                if m and line.startswith("profile="):
                    f.dry_run = m.group(1)

    special = next((m for _, m in kept if _SPECIAL_RE.search(m)), "")
    own = next((m for t, m in kept if t == "APIsec Surface"), "")
    analyze_failed = any(re.search(r"^Analyze$", s) for s in f.failed_steps) or (
        bool(analyze_steps) and not f.failed_steps and f.kind == "scan"
    )
    cause, context, exit_code = "", [], None
    if analyze_failed and analyze_steps:
        cause, context, exit_code = analyze_cause(analyze_steps[-1])
    if special:
        # A timeout or cancellation also leaves "The operation was canceled." in the step output;
        # the annotation says why.
        cause = special
    if not cause:
        cause = own or (errors[0] if errors else "") or (f.annotations[0] if f.annotations else "")
    if not context and log is not None:
        steps = [s for s in split_steps(log) if s.title not in ("Set up job", "Post job cleanup")]
        failed = [s for s in steps if any(fs and fs in s.title for fs in f.failed_steps)]
        source = failed[-1].output if failed else [x for s in steps for x in s.output]
        context = [x for x in meaningful(source) if not x.startswith("##[warning]")][-CONTEXT_LINES:]
    if not cause and f.failed_steps:
        cause = f"Step '{f.failed_steps[0]}' failed with no error message."
    if not cause:
        cause = {
            "cancelled": "The job was cancelled with no reason recorded.",
            "startup_failure": "The job failed to start.",
        }.get(f.conclusion, "GitHub recorded no error message for this job.")
    if exit_code is None:
        own_exit = _EXIT_RE.search(own) if own else None
        if own_exit:
            exit_code = int(own_exit.group(1) or own_exit.group(2))
        elif exit_codes:
            exit_code = exit_codes[0]
    f.cause, f.context, f.exit_code = cause, context, exit_code
    haystack = "\n".join([cause, *f.annotations, *errors])
    f.category, f.hint = classify(
        haystack, f.failed_steps, exit_code if analyze_failed else None, f.kind, f.conclusion
    )
    return f


class Collector:
    def __init__(self, gh: Gh, repo: str, *, all_attempts: bool = False, workers: int = 4, progress=None):
        self.gh = gh
        self.repo = repo
        self.all_attempts = all_attempts
        self.workers = max(1, workers)
        self.progress = progress or (lambda _msg: None)
        self.problems: list[str] = []
        self._lock = threading.Lock()

    def _problem(self, message: str) -> None:
        with self._lock:
            self.problems.append(message)

    def run(self, ref: RunRef) -> tuple[RunSummary, list[Failure]]:
        data = self.gh.json(f"repos/{self.repo}/actions/runs/{ref.run_id}")
        attempt = ref.attempt or data.get("run_attempt") or 1
        summary = RunSummary(
            run_id=ref.run_id,
            url=data.get("html_url", ""),
            attempt=attempt,
            event=data.get("event", ""),
            created_at=data.get("created_at", ""),
            conclusion=data.get("conclusion") or data.get("status") or "",
        )
        if ref.attempt:
            path = f"repos/{self.repo}/actions/runs/{ref.run_id}/attempts/{ref.attempt}/jobs"
        else:
            which = "all" if self.all_attempts else "latest"
            path = f"repos/{self.repo}/actions/runs/{ref.run_id}/jobs?filter={which}"
        jobs = self.gh.paged(path, "jobs")
        failures = self._select(summary, jobs)
        self.progress(
            f"Run {ref.run_id}: {summary.jobs_total} jobs, {len(failures)} not successful. "
            "Fetching details..."
        )
        pool = ThreadPoolExecutor(max_workers=self.workers)
        done: list[Failure] = []
        try:
            futures = [pool.submit(self._detail, f) for f in failures]
            for i, future in enumerate(futures, 1):
                done.append(future.result())
                if i % 10 == 0 and i < len(futures):
                    self.progress(f"  {i}/{len(futures)} jobs read")
        finally:
            # On Ctrl-C, do not wait for the jobs still queued.
            pool.shutdown(wait=False, cancel_futures=True)
        return summary, done

    def _select(self, summary: RunSummary, jobs: list[dict]) -> list[Failure]:
        failures = []
        summary.jobs_total = len(jobs)
        for job in jobs:
            name = job.get("name") or ""
            kind, repo = job_kind(name)
            conclusion = job.get("conclusion") or job.get("status") or ""
            if kind == "scan":
                summary.scan_jobs += 1
                summary.scan_succeeded += conclusion == "success"
            summary.skipped += conclusion == "skipped"
            if conclusion not in NOT_SUCCESSFUL:
                continue
            summary.not_successful += 1
            summary.plan_failed |= kind == "plan"
            failures.append(
                Failure(
                    run_id=summary.run_id,
                    run_attempt=job.get("run_attempt") or summary.attempt,
                    job_id=job.get("id"),
                    job_name=name,
                    job_url=job.get("html_url", ""),
                    kind=kind,
                    repo=repo,
                    conclusion=conclusion,
                    failed_steps=[
                        s.get("name", "") for s in job.get("steps") or [] if s.get("conclusion") == "failure"
                    ],
                    started_at=job.get("started_at") or "",
                    completed_at=job.get("completed_at") or "",
                    runner=job.get("runner_name") or "",
                )
            )
        return failures

    def _detail(self, f: Failure) -> Failure:
        try:
            return self._read_job(f)
        except Exception as exc:  # one odd job must not lose the rest of the bundle
            self._problem(f"{f.job_name} ({f.job_id}): could not be read: {exc!r}")
            f.cause = f.cause or "Could not read this job; open it on GitHub."
            f.hint = f.hint or UNKNOWN_HINT
            return f

    def _read_job(self, f: Failure) -> Failure:
        try:
            annotations = self.gh.paged(f"repos/{self.repo}/check-runs/{f.job_id}/annotations")
        except GhError as exc:
            annotations = []
            self._problem(f"{f.job_name} ({f.job_id}): annotations unavailable: {exc}")
        log = None
        try:
            log = decode_log(self.gh.raw(f"repos/{self.repo}/actions/jobs/{f.job_id}/logs", log=True))
            f.log_status = "ok"
        except GhError as exc:
            f.log_status = {
                404: "not available (the job never started, or the log was deleted)",
                410: "expired",
            }.get(exc.status or 0, f"not available: {exc}")
        try:
            return analyze_job(f, annotations, log)
        except Exception as exc:  # one odd job must not lose the rest of the bundle
            self._problem(f"{f.job_name} ({f.job_id}): could not analyze: {exc!r}")
            f.cause = f.cause or "Could not analyze this job; see its log."
            f.hint = f.hint or UNKNOWN_HINT
            return f

    def list_runs(self, workflow: dict, since: datetime | None, max_runs: int) -> list[RunRef]:
        base = f"repos/{self.repo}/actions/workflows/{workflow['id']}/runs?status=completed"
        if since is None:
            runs = self.gh.json(f"{base}&per_page=1").get("workflow_runs") or []
            return [RunRef(r["id"]) for r in runs[:1]]
        created = quote(">=" + since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        # Runs that concluded "success" are read too: a failed job does not always fail the run.
        runs = self.gh.paged(f"{base}&created={created}", "workflow_runs", limit=1000)
        if len(runs) > max_runs:
            self.progress(f"{len(runs)} runs since then; reading the newest {max_runs} (--max-runs).")
        return [RunRef(r["id"]) for r in runs[:max_runs]]


# =============================================================================
# Bundle
# =============================================================================

_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_name(name: str, fallback: str = "job") -> str:
    """A file name that is valid, visible and unambiguous on Windows, macOS and Linux."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._ ") or fallback
    if name.split(".", 1)[0].upper() in _RESERVED:
        name = f"{name}_"
    return name[:100]


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _fence(lines: list[str]) -> list[str]:
    body = "\n".join(lines).replace("```", "'''")
    return ["```", body, "```"]


def _label(f: Failure) -> str:
    if f.repo:
        return f.repo
    return {"plan": "(Plan job)", "update-store": "(Update store job)"}.get(f.kind, f.job_name)


def write_bundle(
    out_dir: Path,
    repo: str,
    runs: list[RunSummary],
    failures: list[Failure],
    problems: list[str],
    redact: Redactor,
    *,
    make_zip: bool = True,
    now: datetime | None = None,
) -> tuple[Path, Path | None]:
    now = now or datetime.now(timezone.utc)
    root = out_dir / f"surface-failures-{safe_name(repo.replace('/', '-'))}-{now.strftime('%Y%m%d-%H%M%S')}"
    (root / "logs").mkdir(parents=True, exist_ok=True)

    used: set[str] = set()
    for f in failures:
        f.cause = redact(f.cause)
        # As one text, so a secret spread over several lines is still caught.
        f.context = redact("\n".join(f.context)).split("\n") if f.context else []
        f.annotations = [redact(x) for x in f.annotations]
        if f.log_lines:
            stem = safe_name(_label(f).strip("()"), fallback=str(f.job_id))[:60]
            rel = f"logs/{f.run_id}/{stem}.log"
            if rel in used:
                rel = f"logs/{f.run_id}/{stem}-{f.job_id}.log"
            used.add(rel)
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            text = redact("\n".join(truncate(f.log_lines)))
            path.write_text(text, encoding="utf-8", errors="replace")
            f.log_file = rel
    problems = [redact(p) for p in problems]

    order = {r.category: i for i, r in enumerate(RULES)}
    failures.sort(key=lambda f: (order.get(f.category, len(RULES)), f.run_id, _label(f).lower()))

    records = []
    for f in failures:
        record = asdict(f)
        record.pop("log_lines")
        record["repo_label"] = _label(f)
        records.append(record)
    (root / "failures.json").write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "tool_version": __version__,
                "generated_at": now.isoformat(),
                "repository": repo,
                "runs": [asdict(r) for r in runs],
                "failures": records,
                "collection_problems": problems,
                "redaction": {"enabled": redact.enabled, "replacements": redact.count},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    columns = (
        "run_id repo_label category cause exit_code conclusion failed_steps hint job_url log_file "
        "log_status surface_version dry_run job_name"
    ).split()
    with (root / "failures.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        for record in records:
            writer.writerow(
                [
                    "; ".join(v) if isinstance(v := record[c], list) else ("" if v is None else v)
                    for c in columns
                ]
            )
    (root / "summary.md").write_text(_summary(repo, runs, failures, problems, redact, now), encoding="utf-8")
    (root / "README.txt").write_text(
        "APIsec Surface org scan: failed jobs\n\n"
        "summary.md     what failed, why, and what to do about it (start here)\n"
        "failures.csv   the same, one row per failed job\n"
        "failures.json  the same, for tools\n"
        "logs/          each failed job's log, by run id and repository\n\n"
        + (
            f"Tokens, private keys, credentials in URLs and email addresses were replaced with [REDACTED] "
            f"({redact.count} replacements). Repository names and host names were kept.\n"
            if redact.enabled
            else "Redaction was turned off (--no-redact). Review the logs before sharing them.\n"
        )
        + f"\nMade by surface_failures.py {__version__}.\n",
        encoding="utf-8",
    )
    archive = None
    if make_zip:
        archive = Path(shutil.make_archive(str(root), "zip", root_dir=root.parent, base_dir=root.name))
    return root, archive


def _summary(repo, runs, failures, problems, redact, now) -> str:
    out = [
        "# APIsec Surface org scan: failed jobs",
        "",
        f"Repository `{repo}` · generated {now.strftime('%Y-%m-%d %H:%M UTC')} · "
        f"surface_failures.py {__version__}",
        "",
        (
            f"Redaction: on ({redact.count} values replaced with `[REDACTED]`)."
            if redact.enabled
            else "Redaction: **off**. Review before sharing."
        ),
        "",
        "## Runs",
        "",
        "| Run | Started | Event | Attempt | Result | Repos scanned | Succeeded | Not successful |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in runs:
        out.append(
            f"| [{r.run_id}]({r.url}) | {r.created_at} | {r.event} | {r.attempt} | {r.conclusion} | "
            f"{r.scan_jobs} | {r.scan_succeeded} | {r.not_successful} |"
        )
    for r in runs:
        if r.plan_failed:
            out += ["", f"> **Run {r.run_id}: the Plan job failed, so no repositories were scanned.**"]
    out += ["", "## Failures by category", ""]
    if not failures:
        out.append("No failed jobs.")
    by_category: dict[str, list[Failure]] = {}
    for f in failures:
        by_category.setdefault(f.category, []).append(f)
    for category, items in by_category.items():
        out += [f"### {category} ({len(items)})", "", items[0].hint, ""]
        out += ["| Repository | Cause | Exit | Log |", "|---|---|---|---|"]
        for f in items:
            log = f"[log]({f.log_file})" if f.log_file else f.log_status or "-"
            exit_code = "" if f.exit_code is None else str(f.exit_code)
            out.append(f"| [{_md(_label(f))}]({f.job_url}) | {_md(f.cause)[:300]} | {exit_code} | {log} |")
        out.append("")
    if failures:
        out += ["## Details", ""]
    for f in failures:
        out += [
            f"### {_md(_label(f))}: {f.category}",
            "",
            f"- Job: [{_md(f.job_name)}]({f.job_url}) · run {f.run_id}, attempt {f.run_attempt}",
            f"- Result: {f.conclusion}"
            + (f" · failed step: {', '.join(f.failed_steps)}" if f.failed_steps else "")
            + ("" if f.exit_code is None else f" · exit code {f.exit_code}"),
            f"- Runner: {f.runner or 'none'} · {f.started_at or '?'} to {f.completed_at or '?'}"
            + (f" · Surface {f.surface_version}" if f.surface_version else "")
            + (f" · dry_run={f.dry_run}" if f.dry_run else ""),
            f"- Log: {f.log_file or f.log_status}",
            f"- What to do: {f.hint}",
            "",
            "Cause:",
            "",
            *_fence([f.cause]),
        ]
        if f.context:
            out += ["", "Last output before the failure:", "", *_fence(f.context)]
        if f.annotations:
            out += ["", "Annotations:", ""] + [f"- {_md(a)}" for a in f.annotations]
        out.append("")
    if problems:
        out += ["## Collection problems", "", *[f"- {_md(p)}" for p in problems], ""]
    return "\n".join(out)


# =============================================================================
# CLI
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="surface_failures.py",
        description="Collect why APIsec Surface org-scan jobs failed into a bundle to send to APIsec.",
        epilog="Examples:\n"
        "  python3 surface_failures.py acme/apisec-scan\n"
        "  python3 surface_failures.py acme/apisec-scan --since 7d\n"
        "  python3 surface_failures.py https://github.com/acme/apisec-scan/actions/runs/123456\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="OWNER/REPO that runs the org scan, or a run URL")
    p.add_argument(
        "--run", action="append", default=[], metavar="ID|URL", help="a run to collect (repeatable)"
    )
    p.add_argument("--since", metavar="AGE|DATE", help="every failed run since, e.g. 24h, 7d, 2026-10-01")
    p.add_argument(
        "--max-runs", type=int, default=20, help="with --since, at most this many runs (default 20)"
    )
    p.add_argument(
        "--workflow", default="", metavar="NAME|FILE|ID", help="the org-scan workflow, if not found"
    )
    p.add_argument(
        "--all-attempts", action="store_true", help="include jobs from earlier attempts of a re-run"
    )
    p.add_argument("--hostname", default="", help="GitHub Enterprise Server host (default github.com)")
    p.add_argument("--out", default=".", help="where to write the bundle (default: current directory)")
    p.add_argument("--no-zip", action="store_true", help="write the folder only")
    p.add_argument(
        "--no-redact", action="store_true", help="keep tokens and emails (do not share the result)"
    )
    p.add_argument("--workers", type=int, default=4, help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def main(argv: list[str] | None = None, gh: Gh | None = None, now: datetime | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # a Windows console cannot print every character
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    now = now or datetime.now(timezone.utc)
    try:
        return _main(args, gh, now)
    except UsageError as exc:
        _say(f"error: {exc}")
        return EXIT_USAGE
    except NotFoundError as exc:
        _say(f"error: {exc}")
        return EXIT_NOT_FOUND
    except GhError as exc:
        _say(f"error: GitHub request failed: {exc}")
        return EXIT_USAGE
    except KeyboardInterrupt:
        _say("Interrupted.")
        return 130
    except Exception:
        import traceback

        traceback.print_exc()
        _say(
            f"error: surface_failures.py {__version__} hit an unexpected problem. Send the output above "
            "to APIsec."
        )
        return 1


def _main(args: argparse.Namespace, gh: Gh | None, now: datetime) -> int:
    host, repo = args.hostname, args.target.strip().rstrip("/")
    refs: list[RunRef] = []
    for value in ([repo] if "/actions/runs/" in repo else []) + args.run:
        run_host, run_repo, ref = parse_run(value)
        if run_repo:
            if "/actions/runs/" in repo:
                repo = run_repo
            elif run_repo.lower() != repo.lower():
                raise UsageError(f"Run {value} belongs to {run_repo}, not {repo}.")
        if run_host and run_host not in ("github.com", "www.github.com") and not host:
            host = run_host
        refs.append(ref)
    if repo.startswith(("https://", "http://")):
        url = urlparse(repo)
        if url.netloc not in ("github.com", "www.github.com") and not host:
            host = url.netloc
        repo = "/".join(url.path.strip("/").split("/")[:2])
    if not _REPO_RE.match(repo):
        raise UsageError(f"Expected OWNER/REPO or a run URL, got: {args.target}")
    if refs and args.since:
        raise UsageError("Use either --run or --since, not both.")

    gh = gh or Gh(hostname=host)
    gh.hostname = gh.hostname or host
    preflight(gh, repo)
    collector = Collector(gh, repo, all_attempts=args.all_attempts, workers=args.workers, progress=_say)
    if not refs:
        workflow = find_workflow(gh, repo, args.workflow)
        _say(f"Workflow: {workflow.get('name')} ({workflow.get('path')})")
        since = parse_since(args.since, now) if args.since else None
        refs = collector.list_runs(workflow, since, max(1, args.max_runs))
        if not refs:
            raise NotFoundError(
                f"No failed runs of '{workflow.get('name')}' in {repo} since {args.since}."
                if since
                else f"'{workflow.get('name')}' has no completed runs in {repo} yet."
            )

    runs: list[RunSummary] = []
    failures: list[Failure] = []
    for ref in refs:
        try:
            summary, found = collector.run(ref)
        except GhError as exc:
            if exc.status == 404 and len(refs) == 1:
                raise NotFoundError(f"Run {ref.run_id} was not found in {repo}.") from exc
            collector.problems.append(f"Run {ref.run_id}: could not be read: {exc}")
            continue
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            collector.problems.append(f"Run {ref.run_id}: could not be read: {exc!r}")
            continue
        runs.append(summary)
        failures.extend(found)
    if not runs:
        raise UsageError("No run could be read. " + "; ".join(collector.problems))
    if args.since:
        clean = [r for r in runs if not r.not_successful]
        runs = [r for r in runs if r.not_successful]
        if clean:
            _say(f"{len(clean)} of {len(clean) + len(runs)} runs had no failed jobs.")
    if not failures and not collector.problems:
        newest = runs[0] if runs else None
        print(
            f"No failed jobs in run {newest.run_id} ({newest.created_at[:10]}). "
            "To look at earlier runs, add --since 7d."
            if newest and not args.since
            else f"No failed jobs since {args.since}."
        )
        return EXIT_OK

    redact = Redactor(enabled=not args.no_redact)
    root, archive = write_bundle(
        Path(args.out), repo, runs, failures, collector.problems, redact, make_zip=not args.no_zip, now=now
    )

    counts: dict[str, int] = {}
    for f in failures:
        counts[f.category] = counts.get(f.category, 0) + 1
    print("")
    for r in runs:
        line = f"Run {r.run_id} ({r.created_at[:10]}, {r.conclusion}): {r.scan_jobs} repos, "
        line += f"{r.not_successful} failed job" + ("" if r.not_successful == 1 else "s")
        print(line + (" -- Plan failed, nothing was scanned" if r.plan_failed else ""))
    if counts:
        width = max(len(c) for c in counts)
        for category, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"  {category:<{width}}  {n}")
    else:
        print("  No failed jobs.")
    if collector.problems:
        print(f"  ({len(collector.problems)} collection problems, listed in summary.md)")
    print("")
    print(f"Summary: {root / 'summary.md'}")
    if archive:
        print(f"Send this file to APIsec: {archive}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
