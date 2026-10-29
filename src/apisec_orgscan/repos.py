"""Pick the repositories that changed since the last scan."""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

from . import github

# GitHub Actions caps a matrix at 256 entries; never emit more than this.
MATRIX_HARD_LIMIT = 256


def list_org_repos(org: str, token: str) -> list[dict]:
    return github.get_paginated(
        f"{github.API}/orgs/{org}/repos?type=all&per_page=100&sort=pushed&direction=desc",
        token,
    )


def list_installation_repos(token: str) -> list[dict]:
    """Repos a GitHub App installation token can see: the installation's selection.

    This endpoint ignores sort parameters, so sort here the way list_org_repos
    does; select_candidates keeps the most recently pushed repos when capped.
    """
    found = github.get_paginated(f"{github.API}/installation/repositories?per_page=100", token)
    return sorted(found, key=lambda r: r.get("pushed_at") or "", reverse=True)


def is_empty_repo(full_name: str, token: str) -> bool:
    """True only when the repo has no commits (GitHub answers 409)."""
    try:
        with urllib.request.urlopen(
            github.request(f"{github.API}/repos/{full_name}/commits?per_page=1", token)
        ):
            return False
    except urllib.error.HTTPError as exc:
        return exc.code == 409


def select_candidates(
    repos: list[dict],
    cache: dict,
    force_full_scan: bool,
    cap: int,
    exclude_full_names: frozenset[str] = frozenset(),
    empty_full_names: frozenset[str] = frozenset(),
) -> list[dict]:
    """Matrix ``include`` entries for repos that need scanning.

    ``cache`` maps repo id to ``{"pushed_at": ...}`` from the previous run.
    """
    candidates = []
    skip = exclude_full_names | empty_full_names
    for repo in repos:
        if repo.get("archived") or repo.get("disabled") or repo.get("full_name") in skip:
            continue
        repo_id = str(repo["id"])
        pushed_at = repo.get("pushed_at") or ""
        if not force_full_scan and cache.get(repo_id, {}).get("pushed_at") == pushed_at:
            continue
        candidates.append(
            {
                "repo_id": repo_id,
                "repo_full_name": repo["full_name"],
                "repo_name": repo["name"],
                "pushed_at": pushed_at,
                # Uploaded by an earlier run, so APIsec holds it under its numeric id.
                "scanned_before": "true" if repo_id in cache else "false",
            }
        )
        if len(candidates) >= cap:
            print(f"  Reached cap of {cap} repos; re-run for the remainder.", file=sys.stderr)
            break
    return candidates


def find_empty(repos: list[dict], token: str) -> frozenset[str]:
    # GitHub reports size in whole KB, so a repo holding only a small OpenAPI
    # file shows size 0 too; confirm emptiness before skipping.
    return frozenset(
        r["full_name"] for r in repos if r.get("size", 1) == 0 and is_empty_repo(r["full_name"], token)
    )
