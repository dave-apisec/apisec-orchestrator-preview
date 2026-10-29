# surface_failures.py

Finds out why jobs in an APIsec Surface org scan failed, and packs the answer into one zip to send
to APIsec.

An org scan runs one job per repository, so a run can have hundreds of jobs. This script reads every
failed job of a run, works out which repository it scanned and why it failed, and writes a summary
with what to do about each failure, plus the job logs.

It only reads from GitHub, through the GitHub CLI you are already logged in with. Tokens, private
keys, credentials in URLs and email addresses are removed before anything is written.

## Requirements

- Python 3.9 or later (the `python3` that comes with macOS works)
- The [GitHub CLI](https://cli.github.com), logged in with an account that can read the repository
  that runs the org scan: `gh auth login`. On GitHub Enterprise Server, log in to your host
  (`gh auth login --hostname github.example.com`) and pass `--hostname`.

Nothing else needs installing.

## Usage

`OWNER/REPO` is the repository that holds the `APIsec Surface org scan` workflow (not the
repositories it scans).

```
python3 surface_failures.py OWNER/REPO                 # the newest completed run
python3 surface_failures.py OWNER/REPO --since 7d      # every failed run in the last 7 days
python3 surface_failures.py https://github.com/OWNER/REPO/actions/runs/123456   # one run
```

On Windows, use `py surface_failures.py ...`.

It prints a count of failures by category and the path of the zip:

```
Run 123456 (2026-10-21, failure): 157 repos, 46 failed jobs
  billing              29
  manifest-too-large   7
  timeout              6
  analysis-crash       3
  apisec-server-error  1

Summary: ./surface-failures-acme-apisec-scan-20261028-182922/summary.md
Send this file to APIsec: ./surface-failures-acme-apisec-scan-20261028-182922.zip
```

Open `summary.md` to see each failure and what to do about it. Many have a fix on your side (for
example billing, GitHub App access or a missing variable). Send the zip to APIsec for the rest.

| Option | |
|---|---|
| `--run ID\|URL` | Collect this run (repeatable) |
| `--since 24h\|7d\|2w\|DATE` | Every failed run since then, newest first, at most `--max-runs` (20) |
| `--workflow NAME\|FILE` | The org-scan workflow, if it was renamed and is not found |
| `--all-attempts` | Include jobs from earlier attempts of a re-run run |
| `--hostname HOST` | GitHub Enterprise Server host |
| `--out DIR` | Where to write the bundle (default: current directory) |
| `--no-zip` | Write the folder only |
| `--no-redact` | Keep tokens and emails in the output. Do not share the result |

Exit codes: `0` bundle written (whether or not jobs failed), `2` bad arguments or gh not usable,
`3` repository, workflow or run not found, `1` an unexpected error (send the output to APIsec).

## What is in the zip

| File | |
|---|---|
| `summary.md` | Runs, failures grouped by category with what to do, then each failure in detail |
| `failures.csv` | One row per failed job |
| `failures.json` | The same, for tools |
| `logs/<run>/<repo>.log` | The job log, redacted. Jobs that never started have no log |
| `README.txt` | What the bundle holds and how many values were redacted |

Repository names and host names are kept, because APIsec needs them to reproduce a failure.
