import datetime

import check_pip_audit


# --- load_ignores -----------------------------------------------------

def test_load_ignores_missing_file_returns_empty_list(tmp_path):
    assert check_pip_audit.load_ignores(tmp_path / "does-not-exist.toml") == []


def test_load_ignores_parses_valid_file(tmp_path):
    path = tmp_path / "ignores.toml"
    path.write_text(
        '[[ignore]]\n'
        'id = "GHSA-aaaa-bbbb-cccc"\n'
        'expires = "2026-08-01"\n'
        'reason = "No fix released yet."\n'
    )
    ignores = check_pip_audit.load_ignores(path)
    assert ignores == [{
        "id": "GHSA-aaaa-bbbb-cccc",
        "expires": "2026-08-01",
        "reason": "No fix released yet.",
    }]


def test_load_ignores_file_with_no_entries_returns_empty_list(tmp_path):
    path = tmp_path / "ignores.toml"
    path.write_text("# nothing ignored yet\n")
    assert check_pip_audit.load_ignores(path) == []


def test_load_ignores_supports_multiple_entries(tmp_path):
    path = tmp_path / "ignores.toml"
    path.write_text(
        '[[ignore]]\n'
        'id = "GHSA-aaaa-bbbb-cccc"\n'
        'expires = "2026-08-01"\n'
        'reason = "First."\n'
        '\n'
        '[[ignore]]\n'
        'id = "GHSA-dddd-eeee-ffff"\n'
        'expires = "2026-09-01"\n'
        'reason = "Second."\n'
    )
    ignores = check_pip_audit.load_ignores(path)
    assert [e["id"] for e in ignores] == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]


# --- expired_ignores ----------------------------------------------------

def test_expired_ignores_none_when_all_in_future():
    ignores = [{"id": "X", "expires": "2099-01-01"}]
    assert check_pip_audit.expired_ignores(ignores, today=datetime.date(2026, 1, 1)) == []


def test_expired_ignores_flags_past_dates():
    ignores = [{"id": "X", "expires": "2020-01-01"}]
    assert check_pip_audit.expired_ignores(ignores, today=datetime.date(2026, 1, 1)) == ignores


def test_expired_ignores_boundary_expires_today_is_not_expired():
    """The expiry date is the last day the suppression is still valid -
    it lapses the day after, not on the day itself."""
    ignores = [{"id": "X", "expires": "2026-01-01"}]
    assert check_pip_audit.expired_ignores(ignores, today=datetime.date(2026, 1, 1)) == []


def test_expired_ignores_boundary_day_after_expiry_is_expired():
    ignores = [{"id": "X", "expires": "2026-01-01"}]
    assert check_pip_audit.expired_ignores(ignores, today=datetime.date(2026, 1, 2)) == ignores


def test_expired_ignores_mixed_list_only_flags_expired_ones():
    ignores = [
        {"id": "OLD", "expires": "2020-01-01"},
        {"id": "FRESH", "expires": "2099-01-01"},
    ]
    expired = check_pip_audit.expired_ignores(ignores, today=datetime.date(2026, 1, 1))
    assert [e["id"] for e in expired] == ["OLD"]


# --- main -----------------------------------------------------------------

def test_main_refuses_to_run_pip_audit_when_an_ignore_has_expired(monkeypatch, capsys):
    monkeypatch.setattr(check_pip_audit, "load_ignores", lambda: [
        {"id": "GHSA-expired", "expires": "2020-01-01", "reason": "stale"},
    ])
    called = []
    monkeypatch.setattr(check_pip_audit.subprocess, "run", lambda cmd: called.append(cmd))

    exit_code = check_pip_audit.main()

    assert exit_code == 1
    assert called == []  # pip-audit never invoked
    assert "GHSA-expired" in capsys.readouterr().err


def test_main_builds_expected_command_with_no_ignores(monkeypatch):
    monkeypatch.setattr(check_pip_audit, "load_ignores", lambda: [])
    captured_cmd = {}

    class FakeResult:
        returncode = 0

    def fake_run(cmd):
        captured_cmd["cmd"] = cmd
        return FakeResult()

    monkeypatch.setattr(check_pip_audit.subprocess, "run", fake_run)

    exit_code = check_pip_audit.main()

    assert exit_code == 0
    assert captured_cmd["cmd"] == [
        "pip-audit",
        "-r", "requirements.txt",
        "-r", "requirements-dashboard.txt",
        "-r", "requirements-dev.txt",
    ]


def test_main_passes_ignore_vuln_flags_for_active_ignores(monkeypatch):
    monkeypatch.setattr(check_pip_audit, "load_ignores", lambda: [
        {"id": "GHSA-active", "expires": "2099-01-01", "reason": "no fix yet"},
    ])
    captured_cmd = {}

    class FakeResult:
        returncode = 0

    def fake_run(cmd):
        captured_cmd["cmd"] = cmd
        return FakeResult()

    monkeypatch.setattr(check_pip_audit.subprocess, "run", fake_run)

    check_pip_audit.main()

    assert "--ignore-vuln" in captured_cmd["cmd"]
    assert "GHSA-active" in captured_cmd["cmd"]


def test_main_returns_pip_audits_exit_code(monkeypatch):
    monkeypatch.setattr(check_pip_audit, "load_ignores", lambda: [])

    class FakeResult:
        returncode = 3

    monkeypatch.setattr(check_pip_audit.subprocess, "run", lambda cmd: FakeResult())

    assert check_pip_audit.main() == 3
