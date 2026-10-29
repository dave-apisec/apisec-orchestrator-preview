import pytest

from apisec_orgscan import settings


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, 2),
        ({"THROUGHPUT": "5"}, 5),
        ({"IN_THROUGHPUT": "3", "THROUGHPUT": "5"}, 3),
        ({"IN_THROUGHPUT": "0", "THROUGHPUT": "5"}, 5),
        ({"IN_THROUGHPUT": "", "THROUGHPUT": ""}, 2),
        ({"THROUGHPUT": "50"}, 10),
        ({"THROUGHPUT": "-4"}, 1),
        ({"THROUGHPUT": "lots"}, 2),
        ({"IN_THROUGHPUT": "4.0"}, 4),
    ],
)
def test_throughput_precedence_and_bounds(env, expected):
    assert settings.throughput(env) == expected


def test_run_profile_input_beats_variable():
    assert settings.run_profile({"IN_RUN_PROFILE": "legacy", "APISEC_RUN_PROFILE": "surface"}) == (
        "legacy",
        None,
    )
    assert settings.run_profile({"APISEC_RUN_PROFILE": "Legacy"}) == ("legacy", None)
    assert settings.run_profile({}) == ("surface", None)


def test_invalid_run_profile_falls_back_with_warning():
    profile, warning = settings.run_profile({"APISEC_RUN_PROFILE": "fast"})
    assert profile == "surface"
    assert "fast" in warning


def test_cli_version_defaults_to_newest_compatible_release():
    resolved, warnings = settings.resolve({}, newest=lambda: "1.9.0")
    assert resolved["cli_version"] == "1.9.0"
    assert warnings == []


def test_cli_version_variable_pins_without_lookup():
    resolved, _ = settings.resolve(
        {"APISEC_CLI_VERSION": " 1.2.3 "}, newest=lambda: pytest.fail("looked up newest")
    )
    assert resolved["cli_version"] == "1.2.3"


def test_cli_version_pin_older_than_minimum_uses_minimum_with_warning():
    resolved, warnings = settings.resolve({"APISEC_CLI_VERSION": "1.1.0"}, newest=lambda: "1.9.0")
    assert resolved["cli_version"] == settings.CLI_MIN_VERSION == "1.2.0"
    assert "APISEC_CLI_VERSION 1.1.0" in warnings[0]


def test_cli_version_falls_back_to_minimum_with_warning():
    resolved, warnings = settings.resolve({}, newest=lambda: None)
    assert resolved["cli_version"] == settings.CLI_MIN_VERSION
    assert settings.CLI_REQUIREMENT in warnings[0]


def test_cli_requirement_stays_within_major_1():
    assert settings.CLI_REQUIREMENT == f"apisec-surface>={settings.CLI_MIN_VERSION},<2"


def test_newest_cli_version_upgrades_then_reads_installed_version(monkeypatch):
    ran = []
    monkeypatch.setattr(settings.subprocess, "run", lambda cmd, **_: ran.append(cmd))
    monkeypatch.setattr(settings.importlib.metadata, "version", lambda name: "1.2.0")
    assert settings.newest_cli_version() == "1.2.0"
    assert ran[0][-3:] == ["--quiet", "--upgrade", settings.CLI_REQUIREMENT]


def test_newest_cli_version_none_when_install_fails(monkeypatch):
    def _fail(cmd, **_):
        raise settings.subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(settings.subprocess, "run", _fail)
    assert settings.newest_cli_version() is None


@pytest.mark.parametrize(("raw", "expected"), [("", 0), (None, 0), ("25", 25), ("-1", 0), ("x", 0)])
def test_max_repos(raw, expected):
    assert settings.max_repos({"MAX_REPOS": raw} if raw is not None else {}) == expected


@pytest.mark.parametrize(("raw", "expected"), [("true", True), ("True", True), ("false", False), ("", False)])
def test_truthy(raw, expected):
    assert settings.truthy(raw) is expected
