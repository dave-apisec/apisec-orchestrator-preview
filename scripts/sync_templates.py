"""Keep the workflow files in step with the package version.

Sets ``ORGSCAN_SPEC`` to the package's major line with this minor as the floor
(``>=1.1,<2``) and regenerates the standalone template from the workflow's jobs.
Run after bumping ``__version__``; ``--check`` fails if anything is out of date.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/scan.yml"
STANDALONE = ROOT / "templates/apisec-scan-standalone.yml"
INIT = ROOT / "src/apisec_orgscan/__init__.py"

STANDALONE_HEADER = """\
name: APIsec Surface org scan

# Same scan as apisec-scan.yml, for orgs that only allow workflows from their own
# GitHub organization. Setup and secrets: apisec-inc/apisec-orchestrator#setup

on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:
    inputs:
      dry_run:
        description: Analyze but do not upload
        type: boolean
        default: false
      force_full_scan:
        description: Ignore the change cache and scan every repository
        type: boolean
        default: false
      max_repos:
        description: Maximum repositories this run (0 = no limit)
        type: number
        default: 0
      throughput:
        description: Max parallel scans (0 = THROUGHPUT variable, else 2)
        type: number
        default: 0
      runner:
        description: github-hosted | self-hosted (blank = ORCHESTRATOR_RUNNER variable)
        type: string
        default: ''
      run_profile:
        description: surface | legacy (blank = APISEC_RUN_PROFILE variable)
        type: string
        default: ''

permissions:
  contents: read
  actions: read

concurrency:
  group: apisec-surface-scan
  cancel-in-progress: false

env:
  ORGSCAN_SPEC: {spec}

"""


def version() -> str:
    match = re.search(r'__version__ = "([^"]+)"', INIT.read_text(encoding="utf-8"))
    assert match, "no __version__ in __init__.py"
    return match.group(1)


def expected() -> dict[Path, str]:
    major, minor = version().split(".")[:2]
    spec = f"apisec-orgscan>={major}.{minor},<{int(major) + 1}"
    workflow = re.sub(
        r"ORGSCAN_SPEC: apisec-orgscan\S+",
        f"ORGSCAN_SPEC: {spec}",
        WORKFLOW.read_text(encoding="utf-8"),
    )
    jobs = workflow[workflow.index("\njobs:\n") + 1 :]
    return {
        WORKFLOW: workflow,
        STANDALONE: STANDALONE_HEADER.format(spec=spec) + jobs,
    }


def main(argv: list[str]) -> int:
    stale = [
        path
        for path, text in expected().items()
        if not path.exists() or path.read_text(encoding="utf-8") != text
    ]
    if "--check" in argv:
        for path in stale:
            print(f"{path.relative_to(ROOT)} is out of date; run scripts/sync_templates.py", file=sys.stderr)
        return 1 if stale else 0
    for path, text in expected().items():
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"Synced to {version()}: {', '.join(str(p.relative_to(ROOT)) for p in stale) or 'no changes'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
