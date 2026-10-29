"""Change detection (select_candidates) and the GitHub fetch/error-handling layer."""

import time

import pytest
from conftest import FakeResp, http_error

from apisec_orgscan import github, repos
from apisec_orgscan.repos import MATRIX_HARD_LIMIT, select_candidates


def repo(rid, name="r", pushed="2026-01-01T00:00:00Z", **extra):
    d = {"id": rid, "full_name": f"org/{name}", "name": name, "pushed_at": pushed, "size": 10}
    d.update(extra)
    return d


def test_never_seen_repo_is_selected():
    out = select_candidates([repo(1)], cache={}, force_full_scan=False, cap=256)
    assert out == [
        {
            "repo_id": "1",
            "repo_full_name": "org/r",
            "repo_name": "r",
            "pushed_at": "2026-01-01T00:00:00Z",
            "scanned_before": "false",
        }
    ]


def test_unchanged_repo_is_skipped():
    cache = {"1": {"pushed_at": "2026-01-01T00:00:00Z"}}
    assert select_candidates([repo(1)], cache=cache, force_full_scan=False, cap=256) == []


def test_changed_repo_is_selected():
    cache = {"1": {"pushed_at": "2025-12-01T00:00:00Z"}}
    assert len(select_candidates([repo(1)], cache=cache, force_full_scan=False, cap=256)) == 1


def test_force_full_scan_ignores_cache():
    cache = {"1": {"pushed_at": "2026-01-01T00:00:00Z"}}
    assert len(select_candidates([repo(1)], cache=cache, force_full_scan=True, cap=256)) == 1


def test_excluded_repo_is_skipped():
    out = select_candidates(
        [repo(1, name="apisec-scan"), repo(2, name="api")],
        cache={},
        force_full_scan=True,
        cap=256,
        exclude_full_names=frozenset({"org/apisec-scan"}),
    )
    assert [c["repo_name"] for c in out] == ["api"]


def test_archived_disabled_and_empty_repos_skipped():
    out = select_candidates(
        [repo(1, archived=True), repo(2, disabled=True), repo(3, name="empty", size=0), repo(4)],
        cache={},
        force_full_scan=False,
        cap=256,
        empty_full_names=frozenset({"org/empty"}),
    )
    assert [c["repo_id"] for c in out] == ["4"]


def test_size_zero_repo_with_commits_is_selected():
    # GitHub rounds size to KB: a repo with only a small openapi.yaml reports 0.
    assert len(select_candidates([repo(1, size=0)], cache={}, force_full_scan=False, cap=256)) == 1


def test_find_empty_only_checks_size_zero(monkeypatch):
    checked = []
    monkeypatch.setattr(repos, "is_empty_repo", lambda name, _t: checked.append(name) or name == "org/a")
    empty = repos.find_empty([repo(1, name="a", size=0), repo(2, name="b", size=0), repo(3, name="c")], "t")
    assert empty == {"org/a"}
    assert checked == ["org/a", "org/b"]


def test_is_empty_repo_true_only_on_409(monkeypatch):
    def _raise(code):
        def _f(_req):
            raise http_error(code)

        return _f

    monkeypatch.setattr(repos.urllib.request, "urlopen", _raise(409))
    assert repos.is_empty_repo("org/r", "tok") is True
    monkeypatch.setattr(repos.urllib.request, "urlopen", _raise(404))
    assert repos.is_empty_repo("org/r", "tok") is False
    monkeypatch.setattr(repos.urllib.request, "urlopen", lambda _req: FakeResp(b"[]"))
    assert repos.is_empty_repo("org/r", "tok") is False


def test_cap_limits_matrix_size():
    out = select_candidates([repo(i) for i in range(1, 11)], cache={}, force_full_scan=False, cap=3)
    assert len(out) == 3


def test_matrix_hard_limit_constant():
    assert MATRIX_HARD_LIMIT == 256


def test_missing_pushed_at_defaults_to_empty_and_still_selects():
    r = repo(1)
    del r["pushed_at"]
    assert select_candidates([r], cache={}, force_full_scan=False, cap=256)[0]["pushed_at"] == ""


# A permission 403 must never be misread as a rate limit and retried forever.


def test_permission_403_is_not_treated_as_rate_limit():
    assert github.rate_limit_wait(http_error(403, {"x-ratelimit-remaining": "5000"})) is None


def test_primary_rate_limit_waits_until_reset_bounded():
    reset = str(int(time.time()) + 10)
    wait = github.rate_limit_wait(http_error(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}))
    assert 1 <= wait <= github.MAX_RATE_LIMIT_SLEEP + 1


def test_primary_rate_limit_bogus_reset_falls_back_to_60():
    assert github.rate_limit_wait(http_error(403, {"x-ratelimit-remaining": "0"})) == 60


def test_secondary_rate_limit_uses_retry_after():
    exc = http_error(403, {"x-ratelimit-remaining": "4999", "Retry-After": "30"})
    assert github.rate_limit_wait(exc) == 30


def test_429_with_exhausted_quota_is_a_rate_limit():
    assert github.rate_limit_wait(http_error(429, {"x-ratelimit-remaining": "0"})) == 60


def test_non_rate_limit_status_returns_none():
    assert github.rate_limit_wait(http_error(500)) is None


def test_get_page_permission_403_exits_loudly(monkeypatch):
    def _raise(_req):
        raise http_error(403, {"x-ratelimit-remaining": "5000"}, b'{"message":"Resource not accessible"}')

    monkeypatch.setattr(github.urllib.request, "urlopen", _raise)
    with pytest.raises(SystemExit) as ei:
        github.get_page("https://api.github.com/orgs/x/repos", "tok")
    assert "NOT rate limiting" in str(ei.value)


def test_get_page_success_returns_items_and_next(monkeypatch):
    monkeypatch.setattr(github.urllib.request, "urlopen", lambda _req: FakeResp(b'[{"id": 1}]'))
    assert github.get_page("https://api.github.com/x", "tok") == ([{"id": 1}], None)


def test_get_page_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def _flaky(_req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http_error(429, {"x-ratelimit-remaining": "0"})
        return FakeResp(b'[{"id": 7}]')

    monkeypatch.setattr(github.urllib.request, "urlopen", _flaky)
    monkeypatch.setattr(github.time, "sleep", lambda _s: None)
    assert github.get_page("https://api.github.com/x", "tok")[0] == [{"id": 7}]
    assert calls["n"] == 2


def test_get_page_gives_up_after_max_retries(monkeypatch):
    def _always_limited(_req):
        raise http_error(429, {"x-ratelimit-remaining": "0"})

    monkeypatch.setattr(github.urllib.request, "urlopen", _always_limited)
    monkeypatch.setattr(github.time, "sleep", lambda _s: None)
    with pytest.raises(SystemExit):
        github.get_page("https://api.github.com/x", "tok")


def test_get_page_404_skips_gracefully(monkeypatch):
    def _raise(_req):
        raise http_error(404)

    monkeypatch.setattr(github.urllib.request, "urlopen", _raise)
    assert github.get_page("https://api.github.com/x", "tok") == ([], None)


def test_paginated_follows_next_link(monkeypatch):
    pages = iter(
        [
            FakeResp(b'[{"id": 1}]', link='<https://api.github.com/x?page=2>; rel="next"'),
            FakeResp(b'[{"id": 2}]'),
        ]
    )
    monkeypatch.setattr(github.urllib.request, "urlopen", lambda _req: next(pages))
    monkeypatch.setattr(github.time, "sleep", lambda _s: None)
    assert [r["id"] for r in github.get_paginated("https://api.github.com/x", "tok")] == [1, 2]


def test_token_is_not_forwarded_on_redirect():
    req = github.request("https://api.github.com/x", "secret")
    assert req.get_header("Authorization") == "Bearer secret"
    assert "Authorization" not in req.headers


def test_get_page_unwraps_installation_repositories_across_pages(monkeypatch):
    pages = iter(
        [
            FakeResp(
                b'{"total_count": 2, "repositories": [{"id": 1}]}',
                link='<https://api.github.com/installation/repositories?page=2>; rel="next"',
            ),
            FakeResp(b'{"total_count": 2, "repositories": [{"id": 2}]}'),
        ]
    )
    monkeypatch.setattr(github.urllib.request, "urlopen", lambda _req: next(pages))
    monkeypatch.setattr(github.time, "sleep", lambda _s: None)
    url = "https://api.github.com/installation/repositories"
    assert [r["id"] for r in github.get_paginated(url, "tok")] == [1, 2]


def test_get_page_single_object_is_one_item(monkeypatch):
    monkeypatch.setattr(github.urllib.request, "urlopen", lambda _req: FakeResp(b'{"id": 3}'))
    assert github.get_page("https://api.github.com/x", "tok") == ([{"id": 3}], None)


def test_installation_repos_sorted_most_recently_pushed_first(monkeypatch):
    found = [
        repo(1, pushed="2026-01-01T00:00:00Z"),
        repo(2, pushed="2026-03-01T00:00:00Z"),
        repo(3, pushed=None),
    ]
    seen = {}
    monkeypatch.setattr(github, "get_paginated", lambda url, token: seen.setdefault("url", url) and found)
    assert [r["id"] for r in repos.list_installation_repos("tok")] == [2, 1, 3]
    assert seen["url"] == f"{github.API}/installation/repositories?per_page=100"


def test_repo_in_the_store_is_marked_scanned_before():
    cache = {"1": {"pushed_at": "2025-01-01T00:00:00Z"}}
    out = select_candidates([repo(1)], cache=cache, force_full_scan=False, cap=256)
    assert out[0]["scanned_before"] == "true"
