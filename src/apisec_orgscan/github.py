"""GitHub REST helpers: bounded retries on real rate limits, loud failures otherwise."""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"

# A genuine rate limit is retried, but only a bounded number of times so a
# misbehaving response can never loop forever.
MAX_RETRIES = 5

# Never sleep longer than this on a primary-limit reset (guards against a bogus
# reset timestamp pinning the job for an hour).
MAX_RATE_LIMIT_SLEEP = 300


def request(url: str, token: str) -> urllib.request.Request:
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    # Unredirected so the token is not forwarded when GitHub redirects a
    # download to blob storage.
    req.add_unredirected_header("Authorization", f"Bearer {token}")
    return req


def rate_limit_wait(exc: urllib.error.HTTPError) -> int | None:
    """Seconds to wait if ``exc`` is a genuine rate limit, else None.

    GitHub returns 403 for several distinct reasons. Only real throttling is
    retried; everything else (chiefly permission errors, which no amount of
    waiting fixes) fails loudly.

      * Primary rate limit:   403/429 with x-ratelimit-remaining: 0.
      * Secondary rate limit: 403/429 carrying a Retry-After header.
    """
    if exc.code not in (403, 429):
        return None
    if exc.headers.get("x-ratelimit-remaining") == "0":
        reset = exc.headers.get("x-ratelimit-reset", "")
        if reset.isdigit():
            return min(max(int(reset) - int(time.time()), 0), MAX_RATE_LIMIT_SLEEP) + 1
        return 60
    retry_after = exc.headers.get("Retry-After", "")
    if retry_after.isdigit():
        return int(retry_after)
    return None


def get_page(url: str, token: str) -> tuple[list, str | None]:
    """Fetch one page. Returns (items, next_url)."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(request(url, token)) as resp:
                page = json.loads(resp.read())
                if isinstance(page, list):
                    items = page
                elif isinstance(page.get("repositories"), list):
                    # /installation/repositories wraps each page in an object.
                    items = page["repositories"]
                else:
                    items = [page]
                return items, next_link(resp.headers.get("Link", ""))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                print(f"  404 on {url}; skipping", file=sys.stderr)
                return [], None
            wait = rate_limit_wait(exc)
            if wait is not None and attempt < MAX_RETRIES:
                print(f"  Rate-limited (attempt {attempt}/{MAX_RETRIES}); sleeping {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            body = exc.read().decode("utf-8", "replace")[:500] if exc.fp else ""
            remaining = exc.headers.get("x-ratelimit-remaining")
            sys.exit(
                f"GitHub API error {exc.code} on {url}\n"
                f"  x-ratelimit-remaining: {remaining}\n"
                f"  retry-after: {exc.headers.get('Retry-After')}\n"
                f"  body: {body}\n"
                f"  Hint: if remaining is not 0 this is NOT rate limiting. The token most likely "
                f"lacks access to this resource; check that the GitHub App is installed on the org, "
                f"or that the fine-grained PAT is approved for the org, with Metadata: read."
            )
    return [], None


def get_paginated(url: str, token: str) -> list:
    results: list = []
    next_url: str | None = url
    while next_url:
        items, next_url = get_page(next_url, token)
        results.extend(items)
        time.sleep(0.05)  # stay inside secondary rate limits
    return results


def next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        if 'rel="next"' in part:
            return part.split(";")[0].strip().strip("<>")
    return None
