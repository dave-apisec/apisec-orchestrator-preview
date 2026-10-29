"""tools/surface_backfill.py: runs the org scan as a series of batches from the customer's gh."""

import base64
import importlib.util
import io
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "surface_backfill.py"

_spec = importlib.util.spec_from_file_location("surface_backfill", SCRIPT)
sb = importlib.util.module_from_spec(_spec)
sys.modules["surface_backfill"] = sb
_spec.loader.exec_module(sb)

REPO = "acme/apisec-scan"
CALLER = (ROOT / "templates/apisec-scan.yml").read_text()
OLD_CALLER = CALLER.replace(
    "      throughput:\n        description: Max parallel scans (0 = THROUGHPUT variable, else 2)\n"
    "        type: number\n        default: 0\n",
    "",
)


class FakeGitHub:
    """Enough of the GitHub API for a series: dispatches create runs that finish after a few polls."""

    def __init__(self, workflow_text=CALLER, scans=(2, 2, 2, 2, 2), plan="success", variable=None, active=()):
        self.workflow_text = workflow_text
        self.scans = list(scans)  # repositories each successive run plans
        self.plan = plan
        self.variables = {} if variable is None else {"THROUGHPUT": variable}
        self.runs = {}
        self.calls = []
        self.dispatches = []
        self.time = datetime(2026, 10, 28, tzinfo=timezone.utc)
        self.next_id = 100
        self.return_run_id = True
        self.push = True
        self.variable_status = None
        for run_id in active:
            self.runs[run_id] = {"id": run_id, "status": "in_progress", "event": "schedule", "polls": 2}

    # clock and sleep
    def now(self):
        return self.time

    def sleep(self, seconds):
        self.time += timedelta(seconds=seconds)
        for run in self.runs.values():
            if run["status"] != "completed":
                run["polls"] -= 1
                run["status"] = "in_progress" if run["polls"] > 0 else "completed"

    # gh
    def __call__(self, args, _timeout, stdin=None):
        method = args[args.index("-X") + 1]
        path = args[-1]
        body = json.loads(stdin) if stdin else None
        self.calls.append((method, path, body))
        result = self.route(method, path, body)
        if isinstance(result, tuple):
            return result
        return 0, (b"" if result is None else json.dumps(result).encode()), ""

    def route(self, method, path, body):
        if path == f"repos/{REPO}":
            return {"default_branch": "main", "permissions": {"push": self.push}}
        if re.search(r"actions/workflows\?", path):
            return {"total_count": 1, "workflows": [{"id": 7, "name": sb.WORKFLOW_NAME, "path": "wf.yml"}]}
        if "/contents/" in path:
            return {"content": base64.b64encode(self.workflow_text.encode()).decode()}
        if path.endswith("/dispatches"):
            return self.dispatch(body)
        if re.search(r"workflows/7/runs", path):
            runs = [self.public(r) for r in sorted(self.runs.values(), key=lambda r: -r["id"])]
            if "event=workflow_dispatch" in path:
                runs = [r for r in runs if r["event"] == "workflow_dispatch"]
            return {"total_count": len(runs), "workflow_runs": runs}
        m = re.search(r"actions/runs/(\d+)/jobs", path)
        if m:
            return {"total_count": 0, "jobs": self.jobs(int(m.group(1)))}
        m = re.search(r"actions/runs/(\d+)$", path)
        if m:
            return self.public(self.runs[int(m.group(1))])
        if "actions/variables" in path:
            return self.variable(method, path, body)
        return 1, b"", f"gh: Not Found (HTTP 404) {path}"

    def dispatch(self, body):
        assert not any(r["status"] != "completed" for r in self.runs.values()), (
            "dispatched while a run was active"
        )
        run_id = self.next_id
        self.next_id += 1
        self.dispatches.append(body["inputs"])
        planned = self.scans.pop(0) if self.scans else 0
        self.runs[run_id] = {
            "id": run_id,
            "status": "queued",
            "event": "workflow_dispatch",
            "polls": 3,
            "planned": planned,
            "throughput_seen": body["inputs"].get("throughput", self.variables.get("THROUGHPUT")),
        }
        return {"workflow_run_id": run_id} if self.return_run_id else None

    def public(self, run):
        return {
            "id": run["id"],
            "status": run["status"],
            "event": run["event"],
            "conclusion": "success" if run["status"] == "completed" else None,
            "html_url": f"https://github.com/{REPO}/actions/runs/{run['id']}",
            "created_at": "2026-10-28T00:00:00Z",
            "run_started_at": "2026-10-28T00:00:00Z",
            "updated_at": "2026-10-28T00:10:00Z",
        }

    def jobs(self, run_id):
        run = self.runs[run_id]
        jobs = [{"name": "scan / Plan", "status": "completed", "conclusion": self.plan}]
        if run.get("planned"):
            jobs += [
                {"name": f"scan / Scan repo{i}", "status": "completed", "conclusion": "success"}
                for i in range(run["planned"])
            ]
        else:
            jobs.append({"name": "scan / Scan ${{ matrix.repo_name }}", "conclusion": "skipped"})
        return jobs

    def variable(self, method, path, body):
        if self.variable_status:
            return 1, b"", f"gh: Forbidden (HTTP {self.variable_status})"
        if method == "GET":
            if "THROUGHPUT" not in self.variables:
                return 1, b"", "gh: Not Found (HTTP 404)"
            return {"name": "THROUGHPUT", "value": self.variables["THROUGHPUT"]}
        if method in ("POST", "PATCH"):
            self.variables[body["name"]] = body["value"]
            return None
        if method == "DELETE":
            self.variables.pop("THROUGHPUT", None)
            return None
        raise AssertionError(method)


def run(fake, *argv, stdin=None):
    gh = sb.Gh(runner=fake, sleep=fake.sleep)
    return sb.main([REPO, *argv], gh=gh, clock=fake.now, stdin=stdin or io.StringIO(""))


# =============================================================================
# Parsing
# =============================================================================


def test_parse_batches():
    batches = sb.parse_batches(["25:2,100:4x3", "50", "0:6"])
    assert [(b.max_repos, b.throughput) for b in batches] == [
        (25, 2), (100, 4), (100, 4), (100, 4), (50, None), (0, 6),
    ]  # fmt: skip


@pytest.mark.parametrize("spec", ["", "abc", "10:11", "10:0", "10x0", "0:2,10:2", "10x101"])
def test_bad_batches(spec):
    with pytest.raises(sb.UsageError):
        sb.parse_batches([spec])


def test_dispatch_inputs_read_from_the_templates():
    assert sb.dispatch_inputs(CALLER) == {"dry_run", "force_full_scan", "max_repos", "throughput"}
    assert sb.dispatch_inputs(OLD_CALLER) == {"dry_run", "force_full_scan", "max_repos"}
    standalone = (ROOT / "templates/apisec-scan-standalone.yml").read_text()
    assert {"max_repos", "throughput"} <= sb.dispatch_inputs(standalone)
    assert sb.dispatch_inputs("on:\n  push:\n") == set()
    assert sb.dispatch_inputs("on: [workflow_dispatch]\n") == set()


def test_runs_on_python_3_9():
    import ast

    ast.parse(SCRIPT.read_text(encoding="utf-8"), feature_version=(3, 9))


# =============================================================================
# Series
# =============================================================================


def test_runs_one_after_another_with_the_throughput_input():
    fake = FakeGitHub()
    assert run(fake, "--batch", "2:1,2:3x2", "--yes") == 0
    assert fake.dispatches == [
        {"max_repos": "2", "dry_run": "false", "throughput": "1"},
        {"max_repos": "2", "dry_run": "false", "throughput": "3"},
        {"max_repos": "2", "dry_run": "false", "throughput": "3"},
    ]
    assert not any("actions/variables" in path for _, path, _ in fake.calls)
    log = json.loads(Path("surface-backfill-runs.json").read_text())
    assert [r["succeeded"] for r in log[0]["runs"]] == [2, 2, 2]


def test_without_the_input_the_variable_is_set_per_run_and_removed_after():
    fake = FakeGitHub(workflow_text=OLD_CALLER)
    assert run(fake, "--batch", "2:1,2:4", "--yes") == 0
    assert [r["throughput_seen"] for r in fake.runs.values()] == ["1", "4"]
    assert all("throughput" not in d for d in fake.dispatches)
    assert "THROUGHPUT" not in fake.variables


def test_an_existing_variable_is_put_back():
    fake = FakeGitHub(workflow_text=OLD_CALLER, variable="3")
    assert run(fake, "--batch", "2:6", "--yes") == 0
    assert fake.runs[100]["throughput_seen"] == "6"
    assert fake.variables["THROUGHPUT"] == "3"


def test_batches_without_parallel_leave_the_variable_alone():
    fake = FakeGitHub(workflow_text=OLD_CALLER, variable="3")
    assert run(fake, "--batch", "2x2", "--yes") == 0
    assert not any(m != "GET" and "variables" in p for m, p, _ in fake.calls)


def test_variable_without_admin_rights_is_refused_before_starting(capsys):
    fake = FakeGitHub(workflow_text=OLD_CALLER)
    fake.variable_status = 403
    assert run(fake, "--batch", "2:4", "--yes") == 2
    assert not fake.dispatches
    assert "throughput input" in capsys.readouterr().err


def test_stops_when_nothing_is_left_to_scan():
    fake = FakeGitHub(scans=(2, 0, 2))
    assert run(fake, "--batch", "2x3", "--yes") == 0
    assert len(fake.dispatches) == 2


def test_stops_when_a_run_scans_fewer_than_its_maximum():
    fake = FakeGitHub(scans=(5, 3, 5))
    assert run(fake, "--batch", "5x3", "--yes") == 0
    assert len(fake.dispatches) == 2


def test_stops_when_plan_fails_and_restores_the_variable():
    fake = FakeGitHub(workflow_text=OLD_CALLER, plan="failure", variable="2")
    assert run(fake, "--batch", "2:5x3", "--yes") == 1
    assert len(fake.dispatches) == 1
    assert fake.variables["THROUGHPUT"] == "2"


def test_waits_for_a_run_already_in_progress():
    fake = FakeGitHub(active=(42,))
    assert run(fake, "--batch", "2", "--yes") == 0
    assert fake.runs[42]["status"] == "completed"
    assert len(fake.dispatches) == 1


def test_finds_the_run_when_github_does_not_return_its_id():
    fake = FakeGitHub()
    fake.return_run_id = False
    assert run(fake, "--batch", "2x2", "--yes") == 0
    assert sorted(fake.runs) == [100, 101]
    assert all(r["status"] == "completed" for r in fake.runs.values())


def test_dispatch_is_never_retried():
    calls = []

    def runner(args, _timeout, stdin=None):
        calls.append(args)
        return 1, b"", "gh: Bad Gateway (HTTP 502)"

    with pytest.raises(sb.GhError):
        sb.Gh(runner=runner, sleep=lambda _: None).call(
            "repos/a/b/actions/workflows/1/dispatches", "POST", {}
        )
    assert len(calls) == 1


def test_preview_and_declined_prompt_start_nothing():
    fake = FakeGitHub()
    assert run(fake, "--batch", "2:2x3", "--preview") == 0
    tty = io.StringIO("n\n")
    tty.isatty = lambda: True
    assert run(fake, "--batch", "2:2", stdin=tty) == 0
    assert not fake.dispatches
    assert not any(m != "GET" for m, _, _ in fake.calls)


def test_no_prompt_possible_needs_yes(capsys):
    assert run(FakeGitHub(), "--batch", "2") == 2
    assert "--yes" in capsys.readouterr().err


def test_read_only_access_is_refused(capsys):
    fake = FakeGitHub()
    fake.push = False
    assert run(fake, "--batch", "2", "--yes") == 2
    assert "write access" in capsys.readouterr().err


def test_an_interrupted_series_restores_the_original_value_later(monkeypatch):
    fake = FakeGitHub(workflow_text=OLD_CALLER, variable="3")

    def interrupt(*_):
        raise KeyboardInterrupt

    restore = sb.ThroughputVar.restore
    monkeypatch.setattr(sb.ThroughputVar, "restore", interrupt)
    assert run(fake, "--batch", "2:7", "--yes") == 130
    monkeypatch.setattr(sb.ThroughputVar, "restore", restore)
    assert fake.variables["THROUGHPUT"] == "7"
    state = json.loads(Path("surface-backfill-state.json").read_text())
    assert state["throughput_var"] == {"repo": REPO, "original": "3", "restored": False}

    assert run(fake, "--batch", "2", "--restore-throughput") == 0
    assert fake.variables["THROUGHPUT"] == "3"
    assert json.loads(Path("surface-backfill-state.json").read_text())["throughput_var"]["restored"] is True
