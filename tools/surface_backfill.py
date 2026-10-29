#!/usr/bin/env python3
"""Run the APIsec Surface org scan several times in a row, to scan a large organization in batches.

Each batch is one run of the "APIsec Surface org scan" workflow with its own maximum number of
repositories and parallel scans. Runs are started one after another: each starts when the previous
one has finished, so the next run skips the repositories the previous one scanned. The series stops
early once a run finds nothing left to scan.

    python3 surface_backfill.py OWNER/REPO --batch 25:2 --batch 100:4 --batch 200:6x3
    python3 surface_backfill.py OWNER/REPO --batch 25:2,100:4,200:6x3 --preview

A batch is MAX_REPOS[:PARALLEL][xCOUNT]: `200:6x3` is three runs of up to 200 repositories, 6 at a
time. OWNER/REPO is the repository that runs the org-scan workflow. Keep the command running until
the series ends; if it is interrupted, run it again with the batches that are left.

Needs Python 3.9+ and gh (https://cli.github.com), logged in with an account that can run workflows
in OWNER/REPO. No other dependencies.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

__version__ = "1.0.0"

WORKFLOW_NAME = "APIsec Surface org scan"
MAX_THROUGHPUT = 10
EXIT_OK, EXIT_STOPPED, EXIT_USAGE, EXIT_NOT_FOUND, EXIT_INTERRUPTED = 0, 1, 2, 3, 130
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}


class UsageError(Exception):
    """Exits 2: the arguments, gh or its login are not usable."""


class NotFoundError(Exception):
    """Exits 3: no matching repository or workflow."""


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


def _default_runner(args: list[str], timeout: float, stdin: bytes | None = None) -> tuple[int, bytes, str]:
    env = {"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1", "GH_PAGER": ""}
    proc = subprocess.run(
        args,
        capture_output=True,
        timeout=timeout,
        env={**os.environ, **env},
        input=stdin if stdin is not None else b"",
    )
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", errors="replace")


class Gh:
    """GitHub REST calls through the gh CLI, so the user's own gh login is used as is."""

    def __init__(self, hostname: str = "", runner=None, sleep=time.sleep, attempts: int = 5):
        self.hostname = hostname
        self.runner = runner or _default_runner
        self.sleep = sleep
        self.attempts = attempts
        self.exe = "gh"

    def call(self, path: str, method: str = "GET", body: dict | None = None) -> bytes:
        args = [self.exe, "api"]
        if self.hostname:
            args += ["--hostname", self.hostname]
        args += ["-X", method]
        stdin = None
        if body is not None:
            args += ["--input", "-"]
            stdin = json.dumps(body).encode()
        args.append(path)
        delay = 3.0
        for attempt in range(1, self.attempts + 1):
            try:
                rc, out, err = self.runner(args, 120, stdin)
            except subprocess.TimeoutExpired:
                rc, out, err = 1, b"", "gh timed out"
            if rc == 0:
                return out
            match = _STATUS_RE.search(err)
            status = int(match.group(1)) if match else None
            # Only reads are retried. A write that failed with a 5xx may have happened anyway, and a
            # second dispatch would queue a second run. 429 means it was refused before running.
            retry_ok = method == "GET" or status == 429
            transient = status in _RETRY_STATUS or (
                status in (None, 403) and _TRANSIENT_RE.search(err) is not None
            )
            if not (transient and retry_ok) or attempt == self.attempts:
                message = err.strip().splitlines()[-1] if err.strip() else f"gh exited {rc}"
                raise GhError(message, status, err + out.decode("utf-8", errors="replace"))
            self.sleep(max(delay, 61.0) if "rate limit" in err.lower() else delay)
            delay = min(delay * 3, 60.0)
        raise GhError("gh failed")  # unreachable

    def json(self, path: str, method: str = "GET", body: dict | None = None):
        out = self.call(path, method, body).decode("utf-8", errors="replace").strip()
        try:
            return json.loads(out) if out else None
        except json.JSONDecodeError as exc:
            raise GhError(f"unexpected response from {path}: {exc}") from exc

    def paged(self, path: str, key: str, limit: int = 1000) -> list:
        sep = "&" if "?" in path else "?"
        items: list = []
        page = 1
        while True:
            data = self.json(f"{path}{sep}per_page=100&page={page}") or {}
            batch = data.get(key) or []
            items.extend(batch)
            total = data.get("total_count")
            if len(batch) < 100 or (total is not None and len(items) >= total) or len(items) >= limit:
                return items[:limit]
            page += 1


def preflight(gh: Gh, repo: str) -> dict:
    if gh.runner is _default_runner:
        exe = shutil.which("gh")
        if not exe:
            raise UsageError(
                "The GitHub CLI (gh) is not installed or not on PATH. Install it from "
                "https://cli.github.com, run `gh auth login`, then run this again."
            )
        gh.exe = exe
    host = gh.hostname or "github.com"
    try:
        data = gh.json(f"repos/{repo}") or {}
    except GhError as exc:
        if exc.status == 401 or "auth login" in exc.detail or "not logged" in exc.detail.lower():
            raise UsageError(
                f"gh is not logged in to {host}. Run `gh auth login --hostname {host}`."
            ) from exc
        if exc.status == 403 and "SAML" in exc.detail:
            raise UsageError(
                f"Your gh token is not authorized for this organization's SSO. Run "
                f"`gh auth refresh --hostname {host}` and approve SSO for the org, then try again."
            ) from exc
        if exc.status == 404:
            raise NotFoundError(
                f"{repo} was not found on {host}, or your gh login cannot see it. Check the name, and "
                f"that `gh auth status` shows an account with access."
            ) from exc
        raise UsageError(f"Could not reach {repo} through gh: {exc}") from exc
    if data.get("permissions") and not data["permissions"].get("push"):
        raise UsageError(
            f"Your gh account can read {repo} but not run its workflows (needs write access). "
            f"Ask an admin of {repo} to run this, or to grant you write access."
        )
    return data


# =============================================================================
# Workflow
# =============================================================================


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
    names = ", ".join(f"'{w.get('name')}' ({w.get('path')})" for w in (named or workflows)) or "none"
    if named:
        raise UsageError(f"Several '{WORKFLOW_NAME}' workflows in {repo}: {names}. Pick one with --workflow.")
    raise NotFoundError(
        f"No '{WORKFLOW_NAME}' workflow found in {repo}. Workflows: {names}. "
        f"Pass the right repository, or pick one with --workflow."
    )


def dispatch_inputs(text: str) -> set[str]:
    """Names of the workflow_dispatch inputs in a workflow file, without a YAML parser.

    Reads the indented block under `workflow_dispatch:` and, inside its `inputs:`, the keys
    indented one level deeper.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        match = re.match(r"^(\s*)workflow_dispatch:\s*(?:#.*)?$", line)
        if not match:
            continue
        base = len(match.group(1))
        inputs_indent = None
        key_indent = None
        names: set[str] = set()
        for raw in lines[i + 1 :]:
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            if indent <= base:
                break
            stripped = raw.strip()
            if inputs_indent is None:
                if stripped.startswith("inputs:"):
                    inputs_indent = indent
                continue
            if indent <= inputs_indent:
                break
            if key_indent is None:
                key_indent = indent
            if indent == key_indent:
                key = re.match(r"^['\"]?([\w-]+)['\"]?\s*:", stripped)
                if key:
                    names.add(key.group(1))
        return names
    return set()


def workflow_text(gh: Gh, repo: str, workflow: dict, ref: str) -> str:
    data = gh.json(f"repos/{repo}/contents/{quote(workflow['path'])}?ref={quote(ref)}") or {}
    return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")


# =============================================================================
# Batches
# =============================================================================

_BATCH_RE = re.compile(r"^\s*(\d+)\s*(?::\s*(\d+))?\s*(?:[xX*]\s*(\d+))?\s*$")


@dataclass
class Batch:
    max_repos: int
    throughput: int | None = None


def parse_batches(values: list[str]) -> list[Batch]:
    batches: list[Batch] = []
    for value in values:
        for part in value.split(","):
            if not part.strip():
                continue
            match = _BATCH_RE.match(part)
            if not match:
                raise UsageError(
                    f"Not a batch: '{part.strip()}'. Use MAX_REPOS[:PARALLEL][xCOUNT], e.g. 100:4x3."
                )
            max_repos = int(match.group(1))
            throughput = int(match.group(2)) if match.group(2) else None
            count = int(match.group(3)) if match.group(3) else 1
            if throughput is not None and not 1 <= throughput <= MAX_THROUGHPUT:
                raise UsageError(f"Parallel scans must be 1 to {MAX_THROUGHPUT}: '{part.strip()}'.")
            if not 1 <= count <= 100:
                raise UsageError(f"A batch repeats 1 to 100 times: '{part.strip()}'.")
            batches += [Batch(max_repos, throughput) for _ in range(count)]
    if not batches:
        raise UsageError("Give at least one --batch, e.g. --batch 100:4x3.")
    if len(batches) > 100:
        raise UsageError(f"{len(batches)} runs is more than 100. Run the series in parts.")
    if any(b.max_repos == 0 for b in batches[:-1]):
        raise UsageError(
            "Only the last batch may have 0 (no limit) repositories: it scans everything that is left."
        )
    return batches


# =============================================================================
# THROUGHPUT variable
# =============================================================================


class ThroughputVar:
    """Sets the repository's THROUGHPUT variable for each run and puts back what was there.

    The original value is kept in a state file as well, so it is restored even if this process is
    killed: the next invocation reads it from there.
    """

    NAME = "THROUGHPUT"

    def __init__(self, gh: Gh, repo: str, state: Path):
        self.gh = gh
        self.repo = repo
        self.state = state
        self.original: str | None = None  # None: the variable did not exist
        self.current: str | None = None
        self.touched = False

    def _path(self) -> str:
        return f"repos/{self.repo}/actions/variables/{self.NAME}"

    def read(self) -> str | None:
        try:
            return (self.gh.json(self._path()) or {}).get("value")
        except GhError as exc:
            if exc.status == 404:
                return None
            if exc.status == 403:
                raise UsageError(
                    f"This workflow takes no throughput input, so parallel scans are set through the "
                    f"{self.NAME} repository variable, and your gh account cannot change variables in "
                    f"{self.repo} (needs admin). Add the throughput input to the workflow (see "
                    f"templates/apisec-scan.yml), or leave PARALLEL out of the batches."
                ) from exc
            raise

    def load(self) -> None:
        saved = _read_state(self.state).get("throughput_var")
        if saved and saved.get("repo") == self.repo and not saved.get("restored"):
            # A previous series was interrupted before it put the variable back.
            self.original = saved.get("original")
            self.touched = True
        else:
            self.original = self.read()
        self.current = self.read()

    def set(self, value: int) -> None:
        if not self.touched:
            self.touched = True
            self._save(restored=False)
        if self.current == str(value):
            return
        body = {"name": self.NAME, "value": str(value)}
        if self.current is None:
            self.gh.call(f"repos/{self.repo}/actions/variables", "POST", body)
        else:
            self.gh.call(self._path(), "PATCH", body)
        self.current = str(value)

    def restore(self) -> str:
        if not self.touched:
            return ""
        if self.original is None:
            if self.current is not None:
                self.gh.call(self._path(), "DELETE")
            message = f"Removed the {self.NAME} variable again (it was not set before)."
        else:
            if self.current != self.original:
                body = {"name": self.NAME, "value": self.original}
                if self.current is None:
                    self.gh.call(f"repos/{self.repo}/actions/variables", "POST", body)
                else:
                    self.gh.call(self._path(), "PATCH", body)
            message = f"Put the {self.NAME} variable back to {self.original}."
        self.current = self.original
        self.touched = False
        self._save(restored=True)
        return message

    def _save(self, restored: bool) -> None:
        state = _read_state(self.state)
        state["throughput_var"] = {"repo": self.repo, "original": self.original, "restored": restored}
        _write_state(self.state, state)


def _read_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(path: Path, state: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# =============================================================================
# Runs
# =============================================================================


@dataclass
class RunResult:
    batch: int
    max_repos: int
    throughput: int | None
    run_id: int = 0
    url: str = ""
    conclusion: str = ""
    plan: str = ""
    repos: int = 0
    succeeded: int = 0
    failed: int = 0
    started: str = ""
    minutes: float = 0.0
    note: str = ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Series:
    def __init__(
        self, gh: Gh, repo: str, workflow: dict, ref: str, *, poll: float = 30.0, say=None, clock=_now
    ):
        self.gh = gh
        self.repo = repo
        self.workflow = workflow
        self.ref = ref
        self.poll = poll
        self.say = say or (lambda _m: None)
        self.clock = clock

    def _runs(self, query: str = "") -> list[dict]:
        path = f"repos/{self.repo}/actions/workflows/{self.workflow['id']}/runs?per_page=30{query}"
        return (self.gh.json(path) or {}).get("workflow_runs") or []

    def active_runs(self) -> list[dict]:
        return [r for r in self._runs() if r.get("status") in ACTIVE]

    def wait_until_idle(self) -> None:
        """Waits for runs of the workflow that are already queued or running, e.g. the nightly one.

        The workflow's concurrency group keeps one run pending at most; starting another while one
        waits would cancel the waiting one.
        """
        announced = set()
        while True:
            active = self.active_runs()
            if not active:
                return
            for r in active:
                if r["id"] not in announced:
                    self.say(
                        f"Waiting for run {r['id']} ({r.get('event')}, {r.get('status')}) to finish first: "
                        f"{r.get('html_url')}"
                    )
                    announced.add(r["id"])
            self.gh.sleep(self.poll)

    def dispatch(self, inputs: dict[str, str]) -> int:
        since = self.clock()
        known = {r["id"] for r in self._runs("&event=workflow_dispatch")}
        body = {"ref": self.ref, "inputs": inputs, "return_run_details": True}
        path = f"repos/{self.repo}/actions/workflows/{self.workflow['id']}/dispatches"
        try:
            data = self.gh.json(path, "POST", body)
        except GhError as exc:
            if exc.status == 422 and "return_run_details" in exc.detail:
                # GitHub Enterprise Server releases that predate the run id in the response.
                del body["return_run_details"]
                data = self.gh.json(path, "POST", body)
            elif exc.status == 422:
                raise UsageError(f"GitHub refused to start the workflow: {exc.detail.strip()}") from exc
            elif exc.status in (403, 404):
                raise UsageError(
                    f"Your gh account cannot run workflows in {self.repo} ({exc}). It needs write access, "
                    f"and a token with the `workflow` scope: `gh auth refresh -s workflow`."
                ) from exc
            else:
                raise
        run_id = (data or {}).get("workflow_run_id")
        if run_id:
            return int(run_id)
        # No id in the response: find the new run. It shows up within seconds.
        created = quote(">=" + _iso(since.replace(microsecond=0)))
        for _ in range(40):
            self.gh.sleep(3)
            fresh = [
                r for r in self._runs(f"&event=workflow_dispatch&created={created}") if r["id"] not in known
            ]
            if fresh:
                return int(min(fresh, key=lambda r: r["id"])["id"])
        raise UsageError(
            "The workflow was started but its run did not appear within two minutes. Check the Actions "
            f"tab of {self.repo}, then run this again with the batches that are left."
        )

    def wait(self, run_id: int, label: str, max_hours: float) -> dict:
        start = self.clock()
        last_status = ""
        last_beat = start
        failures = 0
        while True:
            try:
                run = self.gh.json(f"repos/{self.repo}/actions/runs/{run_id}") or {}
                failures = 0
            except GhError as exc:
                # A laptop that slept, or a network blip: keep waiting, but not forever.
                failures += 1
                if failures >= 20:
                    raise
                self.say(f"{label}: could not check the run ({exc}); trying again.")
                self.gh.sleep(self.poll)
                continue
            status = run.get("status", "")
            now = self.clock()
            if status == "completed":
                return run
            if status != last_status:
                self.say(f"{label}: {status}  {run.get('html_url', '')}")
                last_status = status
            elif (now - last_beat).total_seconds() >= 300:
                last_beat = now
                self.say(f"{label}: {status}, {self._progress(run_id)}, {_minutes(now - start):.0f} min")
            if (now - start).total_seconds() > max_hours * 3600:
                raise TimeoutError(run_id)
            self.gh.sleep(self.poll)

    def _progress(self, run_id: int) -> str:
        try:
            jobs = self.gh.paged(f"repos/{self.repo}/actions/runs/{run_id}/jobs?filter=latest", "jobs")
        except GhError:
            return "progress unknown"
        scans = [j for j in jobs if _is_scan(j)]
        done = sum(1 for j in scans if j.get("status") == "completed")
        return f"{done}/{len(scans)} repositories done" if scans else "planning"

    def outcome(self, result: RunResult, run: dict) -> None:
        result.conclusion = run.get("conclusion") or ""
        result.url = run.get("html_url") or result.url
        started = run.get("run_started_at") or run.get("created_at") or ""
        result.started = started
        try:
            begin = datetime.fromisoformat(started.replace("Z", "+00:00"))
            end = datetime.fromisoformat((run.get("updated_at") or started).replace("Z", "+00:00"))
            result.minutes = round((end - begin).total_seconds() / 60, 1)
        except ValueError:
            pass
        jobs = self.gh.paged(f"repos/{self.repo}/actions/runs/{result.run_id}/jobs?filter=latest", "jobs")
        plan = next((j for j in jobs if _leaf(j) == "Plan"), None)
        result.plan = (plan or {}).get("conclusion") or "missing"
        scans = [j for j in jobs if _is_scan(j)]
        result.repos = len(scans)
        result.succeeded = sum(1 for j in scans if j.get("conclusion") == "success")
        result.failed = result.repos - result.succeeded


def _minutes(delta) -> float:
    return delta.total_seconds() / 60


def _leaf(job: dict) -> str:
    return (job.get("name") or "").rsplit(" / ", 1)[-1].strip()


def _is_scan(job: dict) -> bool:
    leaf = _leaf(job)
    return leaf.startswith("Scan ") and "${{" not in leaf


# =============================================================================
# CLI
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="surface_backfill.py",
        description="Run the APIsec Surface org scan as a series of batches, one after another.",
        epilog="Examples:\n"
        "  python3 surface_backfill.py acme/apisec-scan --batch 25:2,100:4,200:6x3 --preview\n"
        "  python3 surface_backfill.py acme/apisec-scan --batch 25:2 --batch 100:4 --batch 200:6x3\n"
        "\n"
        "A batch is MAX_REPOS[:PARALLEL][xCOUNT]. PARALLEL is 1-10; left out, the run uses the\n"
        "THROUGHPUT variable (default 2). 0 repositories means no limit (last batch only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("repo", help="OWNER/REPO that runs the org-scan workflow")
    p.add_argument(
        "--batch", action="append", default=[], metavar="SPEC", help="one or more batches (repeatable)"
    )
    p.add_argument("--preview", action="store_true", help="show what would run and change nothing")
    p.add_argument("--yes", "-y", action="store_true", help="start without asking for confirmation")
    p.add_argument(
        "--dry-run", action="store_true", help="analyze but do not upload (the workflow's dry_run)"
    )
    p.add_argument(
        "--workflow", default="", metavar="NAME|FILE|ID", help="the org-scan workflow, if not found"
    )
    p.add_argument("--ref", default="", help="branch to run the workflow from (default: the default branch)")
    p.add_argument("--poll", type=float, default=30.0, help="seconds between status checks (default 30)")
    p.add_argument(
        "--max-hours", type=float, default=24.0, help="stop waiting for one run after this (default 24)"
    )
    p.add_argument("--hostname", default="", help="GitHub Enterprise Server host (default github.com)")
    p.add_argument("--state", default="surface-backfill-state.json", help=argparse.SUPPRESS)
    p.add_argument("--restore-throughput", action="store_true", help="only put the THROUGHPUT variable back")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _say(message: str) -> None:
    stamp = datetime.now().strftime("%H:%M")
    print(f"[{stamp}] {message}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None, gh: Gh | None = None, clock=_now, stdin=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return _main(args, gh or Gh(hostname=args.hostname), clock, stdin or sys.stdin)
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
        return EXIT_INTERRUPTED


def _main(args: argparse.Namespace, gh: Gh, clock, stdin) -> int:
    repo = args.repo.strip().strip("/")
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo):
        raise UsageError(f"Expected OWNER/REPO, got: {args.repo}")
    if args.hostname:
        gh.hostname = args.hostname
    state = Path(args.state)

    info = preflight(gh, repo)
    var = ThroughputVar(gh, repo, state)
    if args.restore_throughput:
        var.load()
        print(var.restore() or "Nothing to restore.")
        return EXIT_OK

    batches = parse_batches(args.batch)
    ref = args.ref or info.get("default_branch") or "main"
    workflow = find_workflow(gh, repo, args.workflow)
    names = dispatch_inputs(workflow_text(gh, repo, workflow, ref))
    if "max_repos" not in names:
        raise UsageError(
            f"{workflow.get('path')} on {ref} has no max_repos input to run in batches. Update it from "
            f"templates/apisec-scan.yml."
        )
    use_input = "throughput" in names
    wants_parallel = any(b.throughput is not None for b in batches)
    if wants_parallel and not use_input:
        var.load()

    print(f"{workflow.get('name')} ({workflow.get('path')}) in {repo}, branch {ref}")
    print(f"{len(batches)} run(s), one after another; the series stops early when nothing is left to scan:")
    for i, b in enumerate(batches, 1):
        repos = "all remaining" if b.max_repos == 0 else f"up to {b.max_repos}"
        parallel = f"{b.throughput} at a time" if b.throughput else "THROUGHPUT variable's parallel scans"
        print(f"  {i:>3}. {repos} repositories, {parallel}")
    if wants_parallel and not use_input:
        was = "not set" if var.original is None else var.original
        print(
            f"The workflow has no throughput input, so each run sets the repository variable THROUGHPUT "
            f"(now {was}) and it is put back afterwards."
        )
    if args.dry_run and "dry_run" not in names:
        raise UsageError(f"{workflow.get('path')} has no dry_run input.")
    if args.dry_run:
        print(
            "dry_run is on: nothing is uploaded and no repository is marked scanned, so every run "
            "plans the same repositories."
        )
    if args.preview:
        return EXIT_OK
    if not args.yes:
        if not stdin.isatty():
            raise UsageError("Pass --yes to start without a prompt.")
        print("Start? [y/N] ", end="", flush=True)
        if stdin.readline().strip().lower() not in ("y", "yes"):
            print("Not started.")
            return EXIT_OK

    series = Series(gh, repo, workflow, ref, poll=max(5.0, args.poll), say=_say, clock=clock)
    results: list[RunResult] = []
    code = EXIT_OK
    first_start = clock()
    try:
        for i, b in enumerate(batches, 1):
            label = f"Run {i}/{len(batches)}"
            result = RunResult(batch=i, max_repos=b.max_repos, throughput=b.throughput)
            results.append(result)
            series.wait_until_idle()
            inputs = {"max_repos": str(b.max_repos)}
            if "dry_run" in names:
                inputs["dry_run"] = "true" if args.dry_run else "false"
            if b.throughput is not None:
                if use_input:
                    inputs["throughput"] = str(b.throughput)
                else:
                    var.set(b.throughput)
            result.run_id = series.dispatch(inputs)
            result.url = f"https://{gh.hostname or 'github.com'}/{repo}/actions/runs/{result.run_id}"
            _say(f"{label} started: {result.url}")
            try:
                run = series.wait(result.run_id, label, args.max_hours)
            except TimeoutError:
                result.note = f"still running after {args.max_hours:g} h"
                _say(f"{label} is still running after {args.max_hours:g} hours; stopping the series here.")
                code = EXIT_STOPPED
                break
            series.outcome(result, run)
            _say(
                f"{label} {result.conclusion}: {result.repos} repositories, {result.succeeded} scanned, "
                f"{result.failed} failed, {result.minutes:g} min"
            )
            if result.plan not in ("success", "skipped"):
                result.note = f"Plan job {result.plan}"
                _say(f"The Plan job did not succeed ({result.plan}), so later runs would fail too. Stopping.")
                code = EXIT_STOPPED
                break
            if result.conclusion == "cancelled":
                result.note = "cancelled"
                _say(f"{label} was cancelled. Stopping.")
                code = EXIT_STOPPED
                break
            if result.repos == 0:
                result.note = "nothing left to scan"
                _say("The plan was empty: every repository has been scanned. Done.")
                break
            if args.dry_run is False and b.max_repos and result.repos < b.max_repos and not result.failed:
                result.note = "reached the end of the organization"
                _say("This run scanned every repository that was left. Done.")
                break
    except KeyboardInterrupt:
        _say(
            "Interrupted. A run that already started keeps going on GitHub; stop it with `gh run cancel ID`."
        )
        code = EXIT_INTERRUPTED
    finally:
        try:
            message = var.restore()
            if message:
                _say(message)
        except GhError as exc:
            _say(
                f"Could not put the THROUGHPUT variable back ({exc}). Run this again with "
                f"--restore-throughput, or set it by hand in the repository settings."
            )
    _report(repo, results, first_start)
    return code


def _report(repo: str, results: list[RunResult], since: datetime) -> None:
    started = [r for r in results if r.run_id]
    if not started:
        return
    print("")
    print("  #    max  par  result     repos    ok failed    min  run")
    for r in started:
        par = str(r.throughput) if r.throughput else "-"
        print(
            f"{r.batch:>3}  {r.max_repos or 'all':>5}  {par:>3}  {r.conclusion or 'running':<10} "
            f"{r.repos:>5} "
            f"{r.succeeded:>5} {r.failed:>6} {r.minutes:>6g}  {r.url}" + (f"  ({r.note})" if r.note else "")
        )
    total_failed = sum(r.failed for r in started)
    print("")
    print(
        f"{sum(r.succeeded for r in started)} repositories scanned, {total_failed} failed in "
        f"{len(started)} run(s). "
        "Failed repositories are retried by the next run."
    )
    if total_failed:
        print(
            f"To see why they failed: python3 surface_failures.py {repo} --since {since.strftime('%Y-%m-%d')}"
        )
    _write_log(results)


def _write_log(results: list[RunResult]) -> None:
    path = Path("surface-backfill-runs.json")
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = []
    previous.append({"finished_at": _iso(_now()), "runs": [asdict(r) for r in results if r.run_id]})
    try:
        path.write_text(json.dumps(previous, indent=2), encoding="utf-8")
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
