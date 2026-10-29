"""The workflow files customers run must stay consistent with the package."""

import subprocess
import sys
from pathlib import Path

import yaml

from apisec_orgscan import __version__

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/scan.yml"
CALLER = ROOT / "templates/apisec-scan.yml"
STANDALONE = ROOT / "templates/apisec-scan-standalone.yml"


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_reusable_workflow_installs_newest_release_of_this_major_line():
    major, minor = __version__.split(".")[:2]
    spec = f"apisec-orgscan>={major}.{minor},<{int(major) + 1}"
    assert _load(WORKFLOW)["env"]["ORGSCAN_SPEC"] == spec
    assert _load(STANDALONE)["env"]["ORGSCAN_SPEC"] == spec


def test_later_jobs_install_the_orgscan_version_plan_resolved():
    # A release published mid-run must not mix versions within the run.
    jobs = _load(WORKFLOW)["jobs"]
    resolve = next(s for s in jobs["plan"]["steps"] if s.get("id") == "orgscan")
    assert '--upgrade "$ORGSCAN_SPEC"' in resolve["run"]
    assert jobs["plan"]["outputs"]["orgscan_version"] == "${{ steps.orgscan.outputs.version }}"
    for name in ("scan", "update-store"):
        installs = [s for s in jobs[name]["steps"] if "pip install" in s.get("run", "")]
        assert len(installs) == 1
        assert '"apisec-orgscan==$ORGSCAN_VERSION"' in installs[0]["run"]
        assert installs[0]["env"]["ORGSCAN_VERSION"] == "${{ needs.plan.outputs.orgscan_version }}"


def test_standalone_is_generated_from_reusable_workflow():
    result = subprocess.run([sys.executable, str(ROOT / "scripts/sync_templates.py"), "--check"])
    assert result.returncode == 0


def test_standalone_runs_the_same_jobs():
    assert _load(STANDALONE)["jobs"] == _load(WORKFLOW)["jobs"]


def test_caller_passes_secrets_by_name():
    # `secrets: inherit` only works within one org; customers call across orgs.
    job = _load(CALLER)["jobs"]["scan"]
    assert job["uses"] == "apisec-inc/apisec-orchestrator/.github/workflows/scan.yml@v1"
    assert job["secrets"] == {
        "APISEC_TOKEN": "${{ secrets.APISEC_TOKEN }}",
        "ORG_READ_TOKEN": "${{ secrets.ORG_READ_TOKEN }}",
        "ORCHESTRATOR_APP_PRIVATE_KEY": "${{ secrets.ORCHESTRATOR_APP_PRIVATE_KEY }}",
    }


def test_caller_secrets_exist_on_reusable_workflow():
    called = _load(WORKFLOW)[True]["workflow_call"]["secrets"]
    assert set(_load(CALLER)["jobs"]["scan"]["secrets"]) <= set(called)


def _mint_step(job):
    steps = [s for s in job["steps"] if s.get("uses", "").startswith("actions/create-github-app-token@")]
    assert len(steps) == 1
    return steps[0]


def test_jobs_needing_github_access_mint_their_own_app_token():
    # Installation tokens last an hour; minting per job keeps long runs working.
    jobs = _load(WORKFLOW)["jobs"]
    for name in ("plan", "scan"):
        step = _mint_step(jobs[name])
        assert step["id"] == "app-token"
        assert step["if"] == "env.USE_APP == 'true'"
        assert "secrets.ORCHESTRATOR_APP_PRIVATE_KEY" in jobs[name]["env"]["USE_APP"]
        assert step["with"]["permission-contents"] == "read"
    assert _mint_step(jobs["scan"])["with"]["repositories"] == "${{ matrix.repo_name }}"
    assert "app-token" not in str(jobs["update-store"])


def test_github_access_prefers_app_token_then_pat_then_job_token():
    jobs = _load(WORKFLOW)["jobs"]
    plan_env = next(s for s in jobs["plan"]["steps"] if s.get("id") == "plan")["env"]
    assert plan_env["APP_TOKEN"] == "${{ steps.app-token.outputs.token }}"
    checkout = next(s for s in jobs["scan"]["steps"] if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["token"] == (
        "${{ steps.app-token.outputs.token || secrets.ORG_READ_TOKEN || github.token }}"
    )


def test_caller_inputs_exist_on_reusable_workflow():
    called = _load(WORKFLOW)[True]["workflow_call"]["inputs"]
    assert set(_load(CALLER)["jobs"]["scan"]["with"]) <= set(called)


def test_caller_converts_number_inputs():
    # Dispatch inputs arrive as strings; workflow_call number inputs reject them.
    called = _load(WORKFLOW)[True]["workflow_call"]["inputs"]
    for name, value in _load(CALLER)["jobs"]["scan"]["with"].items():
        if called[name]["type"] == "number":
            assert value.startswith("${{ fromJSON("), name


def test_callers_grant_permissions_the_store_needs():
    for path in (CALLER, STANDALONE):
        assert _load(path)["permissions"] == {"contents": "read", "actions": "read"}


def test_scan_names_the_repo_it_checked_out():
    # Surface finds the repo's application by this name, not the caller repo's.
    analyze = next(s for s in _load(WORKFLOW)["jobs"]["scan"]["steps"] if s.get("name") == "Analyze")
    assert '--repo-full-name "$REPO_FULL_NAME"' in analyze["run"]
    assert analyze["env"]["REPO_FULL_NAME"] == "${{ matrix.repo_full_name }}"
    assert analyze["env"]["SCANNED_BEFORE"] == "${{ matrix.scanned_before }}"
