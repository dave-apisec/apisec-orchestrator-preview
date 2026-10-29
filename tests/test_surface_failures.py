"""tools/surface_failures.py: the script customers run to send APIsec their failed org-scan jobs.

The fixtures are real job logs and annotations from org-scan runs, with names changed.
"""

import ast
import csv
import importlib.util
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "surface_failures"
SCRIPT = ROOT / "tools" / "surface_failures.py"
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)

_spec = importlib.util.spec_from_file_location("surface_failures", SCRIPT)
sf = importlib.util.module_from_spec(_spec)
sys.modules["surface_failures"] = sf
_spec.loader.exec_module(sf)


def _log(name):
    return sf.decode_log((FIXTURES / f"{name}.log").read_bytes())


def _annotations(name):
    return json.loads((FIXTURES / f"{name}.annotations.json").read_text())


def _failure(kind="scan", repo="svc", conclusion="failure", failed_steps=("Analyze",)):
    return sf.Failure(
        run_id=1,
        job_id=2,
        job_name=f"scan / Scan {repo}" if kind == "scan" else "scan / Plan",
        job_url="https://github.com/acme/org-scan/actions/runs/1/job/2",
        kind=kind,
        repo=repo if kind == "scan" else "",
        conclusion=conclusion,
        failed_steps=list(failed_steps),
        started_at="",
        completed_at="",
        runner="r",
    )


# =============================================================================
# Real failures, one per class
# =============================================================================


def test_analysis_crash_names_the_cli_error_not_the_orchestrator_wrapper():
    f = sf.analyze_job(_failure(), _annotations("crash"), _log("crash"))
    assert f.category == "analysis-crash"
    assert f.cause == "Analysis failed: substring not found"
    assert f.exit_code == 1
    assert f.dry_run == "False"


def test_rejected_upload_joins_the_wrapped_message_into_one_line():
    f = sf.analyze_job(_failure(), _annotations("upload_413"), _log("upload_413"))
    assert f.category == "manifest-too-large"
    assert f.exit_code == 2
    assert f.cause.startswith("Manifest upload failed")
    assert "141,982,152 bytes serialized" in f.cause
    assert "\n" not in f.cause


def test_timeout_reports_the_time_limit_not_the_cancellation_it_causes():
    f = sf.analyze_job(
        _failure(conclusion="cancelled", failed_steps=()), _annotations("timeout"), _log("timeout")
    )
    assert f.category == "timeout"
    assert f.cause == "The job has exceeded the maximum execution time of 30m0s"
    assert f.context


def test_job_that_never_started_is_explained_from_annotations_alone():
    f = sf.analyze_job(_failure(failed_steps=()), _annotations("billing"), None)
    assert f.category == "billing"
    assert "spending limit" in f.cause


def test_github_app_token_failure_in_plan():
    steps = ("Mint GitHub App token", "Explain GitHub App failure")
    f = sf.analyze_job(
        _failure(kind="plan", failed_steps=steps), _annotations("app_token"), _log("app_token")
    )
    assert f.category == "github-app-token"
    assert "could not get a token for 'acme-target'" in f.cause


def test_setup_python_failure_on_a_macos_runner():
    steps = ("Run actions/setup-python@v5",)
    f = sf.analyze_job(
        _failure(kind="plan", failed_steps=steps), _annotations("setup_python"), _log("setup_python")
    )
    assert f.category == "runner-setup"
    assert f.cause == "mkdir: /Users/runner: Permission denied"


def test_noise_annotations_are_dropped():
    f = sf.analyze_job(_failure(), _annotations("crash"), _log("crash"))
    assert not any(
        "Node.js" in a or "label will migrate" in a or "Process completed" in a for a in f.annotations
    )
    assert any("was not uploaded (exit 1)" in a for a in f.annotations)


def test_logs_lose_escape_codes_and_rich_tables():
    lines = _log("success")
    assert not any("\x1b" in line for line in lines)
    analyze = [s for s in sf.split_steps(lines) if sf._ANALYZE_RE.search(s.title)]
    assert len(analyze) == 1
    shown = sf.meaningful(analyze[0].output)
    assert not any(line[0] in "│┃┏┡└╭╰━" for line in shown)
    assert any(line.startswith("profile=surface") for line in shown)


@pytest.mark.parametrize(
    ("text", "exit_code", "category"),
    [
        ("Manifest upload failed: HTTP 500 Internal Server Error on POST /v1/x", 2, "apisec-server-error"),
        ("Manifest upload failed: [Errno 111] Connection refused", 2, "apisec-unreachable"),
        ("APIsec rejected the API key", 5, "apisec-auth"),
        ("OSError: [Errno 28] No space left on device", 1, "runner-resources"),
        ("Set the APISEC_ENDPOINT org variable to your APIsec API URL.", 1, "missing-setting"),
        (
            "repos/x was not scanned: could not check its APIsec application (HTTP 403)",
            1,
            "apisec-app-lookup",
        ),
        ("something new", 4, "config-invalid"),
        ("something new", 7, "unknown"),
    ],
)
def test_classification(text, exit_code, category):
    assert sf.classify(text, ["Analyze"], exit_code, "scan", "failure")[0] == category


def test_every_category_has_a_hint():
    assert all(rule.hint for rule in sf.RULES)
    assert len({rule.category for rule in sf.RULES}) == len(sf.RULES)


# =============================================================================
# Redaction
# =============================================================================


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("token ghp_" + "a" * 36, "ghp_"),
        ("ghs_" + "B" * 36, "ghs_"),
        ("github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "github_pat_"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", "abcdefghijklmnop"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36P", "eyJhbGci"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
        ("https://x-access-token:s3cr3tvalue@github.com/acme/api", "s3cr3tvalue"),
        ("https://bob:hunter2@proxy.local:8080", "hunter2"),
        ("APISEC_PAT=plainvalue123", "plainvalue123"),
        ("aws AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
        ("committed by jane.doe@acme.io", "jane.doe@acme.io"),
    ],
)
def test_redaction_removes_secrets(text, secret):
    r = sf.Redactor()
    assert secret not in r(text)
    assert r.count >= 1


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('{"APISEC_TOKEN": "abc123def"}', "abc123def"),
        ('{"password": "two words"}', "two words"),
        ("{'api_key': 'k3y'}", "k3y"),
        ("x-api-key: abc123def", "abc123def"),
        ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI", "wJalrXUtnFEMI"),
        ("SECRET_KEY=django-insecure", "django-insecure"),
        ("DB_PASS=hunter2", "hunter2"),
        ('TOKEN="two words"', "words"),
        ("--password hunter2", "hunter2"),
        ("--token=abc123def", "abc123def"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("authorization: bearer short1", "short1"),
        ("https://u:p@ss/w@host.example/x", "p@ss"),
        ("2026-10-21T08:00:00.1Z " + "A" * 64, "A" * 64),
        ("-----BEGIN PRIVATE KEY-----\nMIIEvQ\n[... 5 lines left out by surface_failures ...]", "MIIEvQ"),
        ("npm_" + "a" * 36, "npm_" + "a" * 36),
        ("sk-ant-" + "b" * 30, "b" * 30),
    ],
)
def test_redaction_review_cases(text, secret):
    assert secret not in sf.Redactor()(text)


@pytest.mark.parametrize(
    "text",
    [
        "Manifest upload failed: invalid token: HTTP 401 on POST /v1/x",
        "PATH=/usr/bin:/bin",
        "OAUTH_URL=https://login.example/authorize",
        "2026-10-21T08:06:28.7651325Z   APISEC_PAT: \n2026-10-21T08:06:28.7652766Z   RUN_PROFILE: surface",
        "permission-contents: read",
        "git config --local http.https://github.com/.extraheader AUTHORIZATION: basic ***",
    ],
)
def test_redaction_leaves_ordinary_text(text):
    assert sf.Redactor()(text) == text


def test_redaction_keeps_what_we_need_to_debug():
    text = (
        "git@github.com:acme/api.git actions/checkout@v4 APISEC_PAT: *** "
        "sha 3e3ca64b1a2c9f0e8d7c6b5a4f3e2d1c0b9a8f7e "
        "app 01a15dde-f5dd-790d-804c-248f32bfc09d token: ${{ steps.app-token.outputs.token }} "
        "https://api.apisecapps.com GITHUB_TOKEN Permissions"
    )
    r = sf.Redactor()
    assert r(text) == text
    assert r.count == 0


def test_redaction_can_be_turned_off():
    assert sf.Redactor(enabled=False)("ghp_" + "a" * 36) == "ghp_" + "a" * 36


# =============================================================================
# Helpers
# =============================================================================


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (".github-private", "github-private"),
        ("fx.weird--name.v2", "fx.weird--name.v2"),
        ("CON", "CON_"),
        ("nul.txt", "nul.txt_"),
        ("a/b:c*?", "a_b_c"),
        ("", "job"),
    ],
)
def test_safe_name(name, expected):
    assert sf.safe_name(name) == expected


def test_parse_run():
    assert sf.parse_run("123") == ("", "", sf.RunRef(123))
    assert sf.parse_run("https://github.com/acme/scan/actions/runs/9/attempts/2") == (
        "github.com",
        "acme/scan",
        sf.RunRef(9, 2),
    )
    with pytest.raises(sf.UsageError):
        sf.parse_run("https://github.com/acme/scan/pull/9")


def test_parse_since():
    assert sf.parse_since("7d", NOW) == datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
    assert sf.parse_since("2026-10-01", NOW) == datetime(2026, 10, 1, tzinfo=timezone.utc)
    with pytest.raises(sf.UsageError):
        sf.parse_since("last week", NOW)


def test_job_kind():
    assert sf.job_kind("scan / Scan fx.weird--name.v2") == ("scan", "fx.weird--name.v2")
    assert sf.job_kind("Scan api") == ("scan", "api")
    assert sf.job_kind("scan / Scan ${{ matrix.repo_name }}") == ("other", "")
    assert sf.job_kind("scan / Plan") == ("plan", "")
    assert sf.job_kind("scan / Update store") == ("update-store", "")


def test_huge_logs_keep_head_and_tail():
    lines = [f"line {i}" for i in range(100_000)]
    kept = sf.truncate(lines, limit=10_000)
    assert kept[0] == "line 0" and kept[-1] == "line 99999"
    assert "lines left out" in "".join(kept)
    assert sum(len(x) for x in kept) < 11_000
    assert sf.truncate(lines[:5]) == lines[:5]


def test_runs_on_python_3_9():
    ast.parse(SCRIPT.read_text(encoding="utf-8"), feature_version=(3, 9))


# =============================================================================
# gh
# =============================================================================


class FakeGh:
    """Answers `gh api` calls from a table of path regexes."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, args, _timeout):
        self.calls.append(args)
        path = args[-1]
        for pattern, answer in self.routes:
            if re.search(pattern, path):
                result = answer(args) if callable(answer) else answer
                if isinstance(result, tuple):
                    return result
                body = result if isinstance(result, bytes) else json.dumps(result).encode()
                return 0, body, ""
        return 1, b"", f"gh: Not Found (HTTP 404) {path}"


def test_paged_reads_every_page():
    jobs = [{"id": i} for i in range(250)]

    def page(args):
        n = int(re.search(r"[?&]page=(\d+)", args[-1]).group(1))
        return {"total_count": 250, "jobs": jobs[(n - 1) * 100 : n * 100]}

    gh = sf.Gh(runner=FakeGh([(r"jobs", page)]))
    assert len(gh.paged("repos/a/b/actions/runs/1/jobs?filter=latest", "jobs")) == 250


def test_transient_errors_are_retried():
    answers = [(1, b"", "gh: HTTP 502"), (1, b"", "gh: API rate limit exceeded (HTTP 403)"), (0, b"{}", "")]
    sleeps = []
    gh = sf.Gh(runner=lambda *_: answers.pop(0), sleep=sleeps.append)
    assert gh.json("repos/a/b") == {}
    assert len(sleeps) == 2


def test_rate_limits_wait_at_least_a_minute():
    answers = [(1, b"", "gh: You have exceeded a secondary rate limit (HTTP 403)"), (0, b"{}", "")]
    sleeps = []
    sf.Gh(runner=lambda *_: answers.pop(0), sleep=sleeps.append).json("repos/a/b")
    assert sleeps and sleeps[0] >= 60


def test_not_logged_in_is_recognized_from_any_line_of_gh_output(tmp_path, capsys):
    err = "To get started with GitHub CLI, please run:  gh auth login\nAlternatively, populate GH_TOKEN."
    gh = sf.Gh(runner=lambda *_: (1, b"", err))
    assert sf.main([REPO, "--out", str(tmp_path)], gh=gh, now=NOW) == 2
    assert "gh auth login --hostname" in capsys.readouterr().err


def test_permanent_errors_are_not_retried():
    calls = []

    def runner(*_):
        calls.append(1)
        return 1, b"", "gh: Not Found (HTTP 404)"

    with pytest.raises(sf.GhError) as exc:
        sf.Gh(runner=runner, sleep=lambda _: None).json("repos/a/b")
    assert exc.value.status == 404
    assert len(calls) == 1


def test_old_gh_without_the_escape_flag_still_gets_the_log():
    def runner(args, _):
        if "--allow-escape-sequences" in args:
            return 1, b"", "unknown flag: --allow-escape-sequences"
        return 0, b"log", ""

    assert sf.Gh(runner=runner).raw("repos/a/b/actions/jobs/1/logs", log=True) == b"log"


# =============================================================================
# End to end
# =============================================================================

REPO = "acme/org-scan"
BIG_RUN = 39561938488
BY_JOB = {119095142417: "crash", 119095151009: "upload_413", 119095158996: "timeout"}


def _big_run_routes(secret_in_log=""):
    listing = json.loads((FIXTURES / "big_run.jobs.json").read_text())

    def jobs(args):
        n = int(re.search(r"[?&]page=(\d+)", args[-1]).group(1))
        return {"total_count": listing["total_count"], "jobs": listing["jobs"][(n - 1) * 100 : n * 100]}

    def annotations(args):
        job = int(re.search(r"check-runs/(\d+)/", args[-1]).group(1))
        return _annotations(BY_JOB.get(job, "billing"))

    def logs(args):
        job = int(re.search(r"jobs/(\d+)/logs", args[-1]).group(1))
        if job not in BY_JOB:
            return 1, b"<Error><Code>BlobNotFound</Code></Error>", "gh: HTTP 404"
        return (FIXTURES / f"{BY_JOB[job]}.log").read_bytes() + secret_in_log.encode()

    run = {
        "id": BIG_RUN,
        "html_url": f"https://github.com/{REPO}/actions/runs/{BIG_RUN}",
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "created_at": "2026-10-21T07:26:05Z",
        "conclusion": "failure",
    }
    workflows = {
        "total_count": 1,
        "workflows": [{"id": 7, "name": "APIsec Surface org scan", "path": "x.yml"}],
    }
    return [
        (rf"^repos/{REPO}$", {"full_name": REPO}),
        (r"actions/workflows\?", workflows),
        (r"actions/workflows/7/runs", {"total_count": 1, "workflow_runs": [run]}),
        (rf"actions/runs/{BIG_RUN}/jobs", jobs),
        (rf"actions/runs/{BIG_RUN}$", run),
        (r"check-runs/\d+/annotations", annotations),
        (r"actions/jobs/\d+/logs", logs),
    ]


def test_end_to_end_bundle(tmp_path, capsys):
    token = "ghp_" + "Z" * 36
    fake = FakeGh(_big_run_routes(secret_in_log=f"\n2026-10-21T08:00:00Z leaked {token}\n"))
    rc = sf.main([REPO, "--out", str(tmp_path)], gh=sf.Gh(runner=fake, sleep=lambda _: None), now=NOW)
    assert rc == 0

    bundle = tmp_path / "surface-failures-acme-org-scan-20261028-120000"
    rows = list(csv.DictReader((bundle / "failures.csv").open(encoding="utf-8")))
    assert len(rows) == 46
    counts = {}
    for row in rows:
        counts[row["category"]] = counts.get(row["category"], 0) + 1
    assert counts == {"billing": 43, "timeout": 1, "manifest-too-large": 1, "analysis-crash": 1}
    assert all(row["cause"] for row in rows)

    data = json.loads((bundle / "failures.json").read_text())
    assert data["schema_version"] == 1
    assert data["runs"][0]["scan_jobs"] == 157
    assert data["redaction"]["replacements"] >= 3

    with zipfile.ZipFile(f"{bundle}.zip") as z:
        names = z.namelist()
        assert f"{bundle.name}/summary.md" in names
        assert f"{bundle.name}/logs/{BIG_RUN}/cx-jaxrs-modeshape.log" in names
        assert not any(token in z.read(n).decode("utf-8", "replace") for n in names)

    summary = (bundle / "summary.md").read_text(encoding="utf-8")
    assert "### analysis-crash (1)" in summary
    assert "Analysis failed: substring not found" in summary
    assert "Send this file to APIsec" in capsys.readouterr().out


def test_run_url_alone_is_enough(tmp_path):
    fake = FakeGh(_big_run_routes())
    url = f"https://github.com/{REPO}/actions/runs/{BIG_RUN}"
    rc = sf.main([url, "--out", str(tmp_path), "--no-zip"], gh=sf.Gh(runner=fake), now=NOW)
    assert rc == 0
    assert not any("actions/workflows" in c[-1] for c in fake.calls)
    assert not list(tmp_path.glob("*.zip"))


def test_plan_failure_is_one_failure_not_one_per_skipped_repo(tmp_path):
    jobs = [
        {
            "id": 1,
            "name": "scan / Plan",
            "conclusion": "failure",
            "steps": [{"name": "Mint GitHub App token", "conclusion": "failure"}],
        },  # fmt: skip
        {"id": 2, "name": "scan / Scan ${{ matrix.repo_name }}", "conclusion": "skipped", "steps": []},
        {"id": 3, "name": "scan / Update store", "conclusion": "skipped", "steps": []},
    ]
    routes = [
        (rf"^repos/{REPO}$", {}),
        (r"actions/runs/5/jobs", {"total_count": 3, "jobs": jobs}),
        (r"actions/runs/5$", {"id": 5, "conclusion": "failure", "created_at": "2026-10-26T00:00:00Z"}),
        (r"check-runs/1/annotations", _annotations("app_token")),
        (r"actions/jobs/1/logs", (FIXTURES / "app_token.log").read_bytes()),
    ]
    rc = sf.main([REPO, "--run", "5", "--out", str(tmp_path)], gh=sf.Gh(runner=FakeGh(routes)), now=NOW)
    assert rc == 0
    data = json.loads(next(tmp_path.glob("*/failures.json")).read_text())
    assert [f["category"] for f in data["failures"]] == ["github-app-token"]
    assert data["runs"][0]["plan_failed"] is True


def test_no_org_scan_workflow_exits_3(tmp_path, capsys):
    routes = [
        (rf"^repos/{REPO}$", {}),
        (
            r"actions/workflows\?",
            {"total_count": 1, "workflows": [{"id": 1, "name": "CI", "path": "ci.yml"}]},
        ),
        (r"contents/", {"content": ""}),
    ]
    assert sf.main([REPO, "--out", str(tmp_path)], gh=sf.Gh(runner=FakeGh(routes)), now=NOW) == 3
    assert "'CI' (ci.yml)" in capsys.readouterr().err


def test_unknown_repo_exits_3(tmp_path):
    assert sf.main(["acme/nope", "--out", str(tmp_path)], gh=sf.Gh(runner=FakeGh([])), now=NOW) == 3


def test_not_logged_in_exits_2(tmp_path, capsys):
    gh = sf.Gh(runner=lambda *_: (1, b"", "gh: Bad credentials (HTTP 401)"))
    assert sf.main([REPO, "--out", str(tmp_path)], gh=gh, now=NOW) == 2
    assert "gh auth login" in capsys.readouterr().err


def test_run_from_another_repo_is_refused(tmp_path):
    url = "https://github.com/other/repo/actions/runs/1"
    assert sf.main([REPO, "--run", url, "--out", str(tmp_path)], gh=sf.Gh(runner=FakeGh([])), now=NOW) == 2


def _two_run_routes(second):
    routes = _big_run_routes()
    runs = [
        {"id": BIG_RUN, "conclusion": "failure"},
        {"id": 77, "conclusion": "success"},
    ]
    routes.insert(2, (r"actions/workflows/7/runs", {"total_count": 2, "workflow_runs": runs}))
    routes.insert(0, (r"actions/runs/77", second))
    return routes


def test_since_reads_successful_runs_and_drops_those_without_failures(tmp_path, capsys):
    clean = lambda args: (  # noqa: E731
        {"total_count": 1, "jobs": [{"id": 9, "name": "scan / Scan a", "conclusion": "success"}]}
        if "jobs" in args[-1]
        else {"id": 77, "conclusion": "success", "created_at": "2026-10-22T00:00:00Z"}
    )
    fake = FakeGh(_two_run_routes(clean))
    rc = sf.main([REPO, "--since", "30d", "--out", str(tmp_path)], gh=sf.Gh(runner=fake), now=NOW)
    assert rc == 0
    assert any("actions/runs/77/jobs" in c[-1] for c in fake.calls)
    data = json.loads(next(tmp_path.glob("*/failures.json")).read_text())
    assert [r["run_id"] for r in data["runs"]] == [BIG_RUN]
    assert "1 of 2 runs had no failed jobs" in capsys.readouterr().err


def test_one_unreadable_run_does_not_lose_the_others(tmp_path):
    fake = FakeGh(_two_run_routes((1, b"", "gh: Server Error (HTTP 500)")))
    rc = sf.main(
        [REPO, "--since", "30d", "--out", str(tmp_path)], gh=sf.Gh(runner=fake, sleep=lambda _: None), now=NOW
    )
    assert rc == 0
    data = json.loads(next(tmp_path.glob("*/failures.json")).read_text())
    assert len(data["failures"]) == 46
    assert any("Run 77" in p for p in data["collection_problems"])


def test_a_job_that_breaks_the_parser_is_still_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(sf, "decode_log", lambda raw: 1 / 0)
    fake = FakeGh(_big_run_routes())
    assert sf.main([REPO, "--out", str(tmp_path)], gh=sf.Gh(runner=fake), now=NOW) == 0
    data = json.loads(next(tmp_path.glob("*/failures.json")).read_text())
    assert len(data["failures"]) == 46
    assert any("ZeroDivisionError" in p for p in data["collection_problems"])


def test_no_failures_writes_nothing(tmp_path, capsys):
    jobs = {"total_count": 1, "jobs": [{"id": 9, "name": "scan / Scan a", "conclusion": "success"}]}
    routes = [
        (rf"^repos/{REPO}$", {}),
        (r"actions/runs/5/jobs", jobs),
        (r"actions/runs/5$", {"id": 5, "conclusion": "success", "created_at": "2026-10-26T00:00:00Z"}),
    ]
    assert (
        sf.main([REPO, "--run", "5", "--out", str(tmp_path)], gh=sf.Gh(runner=FakeGh(routes)), now=NOW) == 0
    )
    assert "No failed jobs in run 5" in capsys.readouterr().out
    assert not list(tmp_path.iterdir())
