"""``apisec-orgscan``: the commands each job of the org-scan workflow runs.

  plan    restore the store, list the org, write the scan matrix and settings
  scan    run Surface analysis on one checked-out repo
  record  note a successful scan of one repo
  merge   fold this run's notes into the store

Everything is read from environment variables the workflow maps from inputs,
secrets and org variables, so nothing tenant-specific lives in this package.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Mapping

from . import __version__, apisec, repos, settings, store


def _write_outputs(outputs: Mapping[str, str]) -> None:
    lines = "".join(f"{k}={v}\n" for k, v in outputs.items())
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(lines)
    else:
        sys.stdout.write(lines)


def _warn(message: str) -> None:
    print(f"::warning title=APIsec Surface::{message}", file=sys.stderr)


def _error(message: str) -> int:
    print(f"::error title=APIsec Surface::{message}", file=sys.stderr)
    return 1


def github_credential(env: Mapping[str, str]) -> tuple[str, str]:
    """(kind, token) for listing repos: GitHub App token, then PAT, then the job token."""
    if env.get("APP_TOKEN"):
        return "app", env["APP_TOKEN"]
    if env.get("ORG_READ_TOKEN"):
        return "pat", env["ORG_READ_TOKEN"]
    return "job", env.get("GITHUB_TOKEN", "")


def cmd_plan(_: argparse.Namespace, env: Mapping[str, str]) -> int:
    org = env.get("TARGET_ORG", "").strip()
    if not org:
        return _error("TARGET_ORG is empty; refusing to guess which org to scan.")
    kind, token = github_credential(env)
    if kind == "job":
        _warn(
            "Neither a GitHub App (ORCHESTRATOR_APP_ID + ORCHESTRATOR_APP_PRIVATE_KEY) nor "
            "ORG_READ_TOKEN is set; only public repos and this repo can be scanned."
        )

    run_settings, warnings = settings.resolve(env)
    for warning in warnings:
        _warn(warning)

    host_repo = env.get("GITHUB_REPOSITORY", "").strip()
    store.restore(host_repo, env.get("GITHUB_TOKEN", ""))
    cache = store.load()
    print(f"Store: {len(cache)} repos known.", file=sys.stderr)

    if kind == "app":
        org_repos = repos.list_installation_repos(token)
        print(f"GitHub App installation on '{org}': {len(org_repos)} repos selected.", file=sys.stderr)
        if not org_repos:
            return _error(
                f"The GitHub App installation on '{org}' has no repositories selected; "
                "choose the repos to scan in the app's installation settings."
            )
    else:
        org_repos = repos.list_org_repos(org, token)
        print(
            f"Org '{org}': {len(org_repos)} repos ({'ORG_READ_TOKEN' if kind == 'pat' else 'job token'}).",
            file=sys.stderr,
        )

    exclude = {name.strip() for name in env.get("EXCLUDE_REPOS", "").split(",") if name.strip()}
    if host_repo:
        exclude.add(host_repo)
    empty = repos.find_empty(org_repos, token)
    if empty:
        print(f"Skipping empty repos: {', '.join(sorted(empty))}", file=sys.stderr)

    limit = settings.max_repos(env)
    cap = min(limit, repos.MATRIX_HARD_LIMIT) if limit else repos.MATRIX_HARD_LIMIT
    force = settings.truthy(env.get("FORCE_FULL_SCAN"))
    candidates = repos.select_candidates(org_repos, cache, force, cap, frozenset(exclude), empty)

    print(
        f"Scan plan: {len(candidates)} repo(s), max-parallel {run_settings['throughput']}, "
        f"Surface CLI {run_settings['cli_version']}"
        f"{' (full scan)' if force else ''}",
        file=sys.stderr,
    )
    for c in candidates:
        print(f"  {c['repo_full_name']}", file=sys.stderr)

    matrix = json.dumps({"include": candidates}, separators=(",", ":"), ensure_ascii=True)
    _write_outputs({"count": str(len(candidates)), "matrix": matrix, **run_settings})
    return 0


def _link_before_scan(endpoint: str, pat: str, repo: apisec.Repo, old: str, new: str, seen: bool) -> bool:
    """Point ``new`` at the repo's existing application. True if ``old`` still needs binding after."""
    bound = apisec.lookup(endpoint, pat, [old, new])
    if bound is None:
        # Token may not look bindings up; only a repo this workflow uploaded is known to have one.
        if seen:
            apisec.bind(endpoint, pat, repo, new, apisec.resolve(endpoint, pat, repo, old))
            print(f"Bound {new} to the application of {old}.", file=sys.stderr)
        return True
    old_app, new_app = bound.get(old), bound.get(new)
    if old_app and not new_app:
        apisec.bind(endpoint, pat, repo, new, old_app)
        print(f"Bound {new} to application {old_app} ({old}).", file=sys.stderr)
    elif old_app and new_app and old_app != new_app:
        _warn(
            f"{repo.full_name} has two APIsec applications: {old_app} ({old}) and {new_app} ({new}). "
            f"This scan updates {new_app}."
        )
    return not old_app


def cmd_scan(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    endpoint = env.get("APISEC_ENDPOINT", "").strip()
    if not endpoint:
        return _error("Set the APISEC_ENDPOINT org variable to your APIsec API URL.")
    dry_run = settings.truthy(env.get("DRY_RUN"))
    pat = env.get("APISEC_PAT", "")
    if not dry_run and not pat:
        return _error("Set the APISEC_TOKEN secret, or run with dry_run.")

    child = dict(env)
    child.pop("APISEC_CANONICAL_REPO_ID", None)
    old_id = apisec.numeric_id(args.repo_id)
    if args.repo_full_name:
        # Surface CLI 1.2 takes the repo id from GITHUB_REPOSITORY, which in
        # this job names the repo running the workflow, not the one scanned.
        child["GITHUB_REPOSITORY"] = args.repo_full_name
        new_id = apisec.name_id(args.repo_full_name, env.get("GITHUB_SERVER_URL", ""))
    else:
        # Called by a workflow from before 1.1, which does not pass the name.
        child["APISEC_CANONICAL_REPO_ID"] = old_id
        new_id = None
    child["APISEC_REGISTRATION_CODE"] = env.get("APISEC_REGISTRATION_CODE", "").strip() or "ci-orchestrator"
    child["APISEC_RUN_PROFILE"] = env.get("RUN_PROFILE") or "surface"
    if env.get("APISEC_LLM_ENRICHMENT", "").strip():
        child["APISEC_SURFACE_LLM_EXTRACTION"] = env["APISEC_LLM_ENRICHMENT"].strip()

    repo = apisec.Repo(args.path, args.repo_full_name, env.get("GITHUB_SERVER_URL", "")) if new_id else None
    bind_old_after = False
    if repo and not dry_run:
        try:
            bind_old_after = _link_before_scan(
                endpoint, pat, repo, old_id, new_id, settings.truthy(env.get("SCANNED_BEFORE"))
            )
        except apisec.ApisecError as exc:
            return _error(f"{args.path} was not scanned: could not check its APIsec application ({exc}).")

    cmd = [
        "apisec-surface",
        "analyze",
        args.path,
        "--no-detect-monorepo",
        "--skip-if-no-routes",
        "--api-url",
        endpoint,
    ]
    if dry_run:
        cmd.append("--dry-run")
    print(
        f"profile={child['APISEC_RUN_PROFILE']} dry_run={dry_run} repo_id={new_id or old_id}", file=sys.stderr
    )
    rc = subprocess.call(cmd, env=child)
    if rc:
        if dry_run:
            _error(f"{args.path} failed to analyze (exit {rc}).")
        else:
            _error(f"{args.path} was not uploaded (exit {rc}); it is retried next run.")
    elif bind_old_after:
        # Lets scanners that still send the numeric id (the APIsec GitHub Action) find it too.
        try:
            app_id = apisec.resolve(endpoint, pat, repo, new_id)
            apisec.bind(endpoint, pat, repo, old_id, app_id)
            print(f"Bound {old_id} to application {app_id}.", file=sys.stderr)
        except apisec.ApisecError as exc:
            _warn(f"{args.path} was uploaded, but {old_id} could not be bound to its application ({exc}).")
    return rc


def cmd_record(args: argparse.Namespace, _: Mapping[str, str]) -> int:
    store.record(args.repo_id, args.pushed_at)
    return 0


def cmd_merge(_: argparse.Namespace, env: Mapping[str, str]) -> int:
    store.restore(env.get("GITHUB_REPOSITORY", ""), env.get("GITHUB_TOKEN", ""))
    current = store.load()
    applied = store.merge(current)
    store.save(current)
    print(f"Store: {applied} update(s) applied, {len(current)} repos known.", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apisec-orgscan")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan").set_defaults(fn=cmd_plan)
    scan = sub.add_parser("scan")
    scan.add_argument("path")
    scan.add_argument("--repo-id", required=True)
    scan.add_argument("--repo-full-name", default="")
    scan.set_defaults(fn=cmd_scan)
    record = sub.add_parser("record")
    record.add_argument("--repo-id", required=True)
    record.add_argument("--pushed-at", required=True)
    record.set_defaults(fn=cmd_record)
    sub.add_parser("merge").set_defaults(fn=cmd_merge)
    args = parser.parse_args(argv)
    return args.fn(args, os.environ)


if __name__ == "__main__":
    sys.exit(main())
