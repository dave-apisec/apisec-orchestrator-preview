"""Resolve run settings: workflow input, then org variable, then default."""

from __future__ import annotations

import importlib.metadata
import re
import subprocess
import sys
from collections.abc import Callable, Mapping

# Scans run the newest Surface CLI in this range. The floor is the first
# release that finds each repo's application by its GITHUB_REPOSITORY; older
# ones create a new application on every run. A new major may change the
# `analyze` interface, so it waits for an apisec-orgscan release that supports it.
CLI_MIN_VERSION = "1.2.0"
CLI_REQUIREMENT = f"apisec-surface>={CLI_MIN_VERSION},<2"
DEFAULT_THROUGHPUT = 2
MAX_THROUGHPUT = 10
RUN_PROFILES = ("surface", "legacy")


def _int(raw: str | None) -> int:
    try:
        return int(float(raw or 0))
    except ValueError:
        return 0


def throughput(env: Mapping[str, str]) -> int:
    t = _int(env.get("IN_THROUGHPUT")) or _int(env.get("THROUGHPUT")) or DEFAULT_THROUGHPUT
    return max(1, min(t, MAX_THROUGHPUT))


def run_profile(env: Mapping[str, str]) -> tuple[str, str | None]:
    """Return (profile, warning)."""
    raw = (env.get("IN_RUN_PROFILE") or env.get("APISEC_RUN_PROFILE") or "surface").strip().lower()
    if raw in RUN_PROFILES:
        return raw, None
    return "surface", f"'{raw}' is not surface or legacy; using surface."


def max_repos(env: Mapping[str, str]) -> int:
    return max(0, _int(env.get("MAX_REPOS")))


def truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() == "true"


def newest_cli_version() -> str | None:
    """Install the newest compatible CLI here and return its version, or None.

    Installing lets pip make the choice (index, mirrors, yanked releases,
    Python support) without parsing its output.
    """
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", CLI_REQUIREMENT],
            check=True,
            timeout=600,
        )
        return importlib.metadata.version("apisec-surface")
    except (OSError, subprocess.SubprocessError, importlib.metadata.PackageNotFoundError):
        return None


def _release(version: str) -> tuple[int, ...] | None:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    return tuple(int(part) for part in match.groups()) if match else None


def cli_version(
    env: Mapping[str, str], newest: Callable[[], str | None] | None = None
) -> tuple[str, str | None]:
    """Return (version, warning).

    APISEC_CLI_VERSION pins a release. Otherwise the newest compatible one is
    resolved here, once per run, so every scan job installs the same release
    even if another is published mid-run.
    """
    pinned = env.get("APISEC_CLI_VERSION", "").strip()
    if pinned:
        release = _release(pinned)
        if release and release < _release(CLI_MIN_VERSION):
            return CLI_MIN_VERSION, (
                f"APISEC_CLI_VERSION {pinned} would create a new application on every run; "
                f"using {CLI_MIN_VERSION}, the oldest release this workflow supports."
            )
        return pinned, None
    found = (newest or newest_cli_version)()
    if found:
        return found, None
    return CLI_MIN_VERSION, (f"Could not resolve the newest {CLI_REQUIREMENT}; using {CLI_MIN_VERSION}.")


def resolve(
    env: Mapping[str, str], newest: Callable[[], str | None] | None = None
) -> tuple[dict[str, str], list[str]]:
    """Settings the scan jobs need, plus warnings for the run log."""
    profile, profile_warning = run_profile(env)
    version, version_warning = cli_version(env, newest)
    settings = {
        "run_profile": profile,
        "cli_version": version,
        "throughput": str(throughput(env)),
    }
    return settings, [w for w in (profile_warning, version_warning) if w]
