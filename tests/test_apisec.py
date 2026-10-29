from conftest import FakeResp, http_error

from apisec_orgscan import apisec


def test_name_id_matches_surface_cli():
    assert apisec.name_id("Acme/Payments-API") == "github:acme/payments-api"
    assert apisec.name_id("acme/api", "https://github.com/") == "github:acme/api"
    assert apisec.name_id("acme/api", "https://GHE.example.com") == "github:ghe.example.com/acme/api"


def test_registration_body_names_the_repo(tmp_path):
    body = apisec.Repo(str(tmp_path), "acme/api").body("github:acme/api", "app-1")
    assert body["repoName"] == "api"
    assert body["repoUrl"] == "https://github.com/acme/api"
    assert body["existingAppId"] == "app-1"
    assert all(body[k] for k in ("branch", "commitSha", "scmProvider"))


def test_lookup_without_permission_returns_none(monkeypatch):
    def denied(*_, **__):
        raise http_error(403)

    monkeypatch.setattr(apisec.urllib.request, "urlopen", denied)
    assert apisec.lookup("https://a", "t", ["github:1"]) is None


def test_lookup_maps_each_id_to_its_application(monkeypatch):
    body = (
        b'{"repos":[{"canonicalRepoId":"github:1","status":"BOUND","applicationId":"app"},'
        b'{"canonicalRepoId":"github:a/b","status":"UNBOUND","applicationId":null}]}'
    )
    monkeypatch.setattr(apisec.urllib.request, "urlopen", lambda *_, **__: FakeResp(body))
    assert apisec.lookup("https://a", "t", ["github:1", "github:a/b"]) == {
        "github:1": "app",
        "github:a/b": None,
    }
