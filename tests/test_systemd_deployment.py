"""Structural checks for the systemd deployment (systemd/, docker/entrypoint.sh).

Not full integration tests (no real systemd or root in CI) - these guard
against the kind of drift that's easy to introduce silently: a new env var
added to entrypoint.sh or webapp.py without updating the matching
systemd/*.env.example template, a typo breaking install.sh's bash syntax,
or a unit file losing a hardening directive during an edit.
"""

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEMD_DIR = REPO_ROOT / "systemd"

UNIT_FILES = [
    "network-traffic-analyzer.service",
    "network-traffic-dashboard.service",
]


def _bash_syntax_ok(path):
    result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return True


def _env_keys(path):
    """Env var names declared (commented-out defaults count) in a KEY=... file."""
    keys = set()
    for line in path.read_text().splitlines():
        stripped = line.lstrip("#").strip()
        match = re.match(r"^([A-Z_][A-Z0-9_]*)=", stripped)
        if match:
            keys.add(match.group(1))
    return keys


def test_install_sh_has_valid_bash_syntax():
    _bash_syntax_ok(SYSTEMD_DIR / "install.sh")


def test_install_sh_is_executable():
    mode = (SYSTEMD_DIR / "install.sh").stat().st_mode
    assert mode & 0o111, "install.sh must be executable"


def test_install_sh_requires_root():
    text = (SYSTEMD_DIR / "install.sh").read_text()
    assert 'id -u' in text and "Run as root" in text


def test_entrypoint_sh_has_valid_bash_syntax():
    _bash_syntax_ok(REPO_ROOT / "docker" / "entrypoint.sh")


def test_entrypoint_sh_still_defaults_app_dir_to_docker_path():
    # Shared verbatim with Docker (see the comment at the top of the file) -
    # changing this default would silently break the Docker deployment.
    text = (REPO_ROOT / "docker" / "entrypoint.sh").read_text()
    assert 'APP_DIR="${APP_DIR:-/app}"' in text


def test_capture_env_example_covers_every_entrypoint_var():
    entrypoint_text = (REPO_ROOT / "docker" / "entrypoint.sh").read_text()
    # Top-of-file `VAR="${VAR:-default}"` declarations are the vars the
    # script actually reads from the environment (as opposed to the
    # script's own local loop variables like run_id/run_dir/elapsed).
    declared = set(re.findall(
        r'^([A-Z_][A-Z0-9_]*)="\$\{\1(?::-[^}]*)?\}"', entrypoint_text, re.MULTILINE
    ))
    assert declared, "regex found no env vars in entrypoint.sh - check it still matches the script"

    template_keys = _env_keys(SYSTEMD_DIR / "capture.env.example")
    missing = declared - template_keys
    assert not missing, f"capture.env.example is missing: {sorted(missing)}"


def test_capture_env_example_covers_notification_vars():
    # notifications.config_from_env() reads these directly from os.environ
    # rather than through entrypoint.sh, so the regex above can't see them.
    notifications_text = (REPO_ROOT / "notifications.py").read_text()
    referenced = set(re.findall(r'env\.get\("([A-Z_][A-Z0-9_]*)"|env\["([A-Z_][A-Z0-9_]*)"\]',
                                 notifications_text))
    referenced = {a or b for a, b in referenced}
    assert referenced, "regex found no env vars in notifications.py - check it still matches the module"

    template_keys = _env_keys(SYSTEMD_DIR / "capture.env.example")
    missing = referenced - template_keys
    assert not missing, f"capture.env.example is missing: {sorted(missing)}"


def test_dashboard_env_example_covers_webapp_vars():
    sources = "".join(
        (REPO_ROOT / name).read_text()
        for name in ("webapp.py", "alert_rules.py", "device_names.py")
    )
    referenced = set(re.findall(r'os\.environ(?:\.get)?\(?"([A-Z_][A-Z0-9_]*)"', sources))
    assert referenced, "regex found no env vars - check it still matches the modules"

    template_keys = _env_keys(SYSTEMD_DIR / "dashboard.env.example")
    missing = referenced - template_keys
    assert not missing, f"dashboard.env.example is missing: {sorted(missing)}"


def test_service_units_have_required_directives():
    for name in UNIT_FILES:
        text = (SYSTEMD_DIR / name).read_text()
        assert "[Service]" in text
        assert "[Install]" in text
        assert "ExecStart=" in text
        assert "WantedBy=multi-user.target" in text


def test_service_units_are_hardened():
    for name in UNIT_FILES:
        text = (SYSTEMD_DIR / name).read_text()
        assert "NoNewPrivileges=yes" in text
        assert "ProtectSystem=strict" in text
        assert "ProtectHome=yes" in text
        assert "ReadWritePaths=" in text
        assert re.search(r"^User=\S+$", text, re.MULTILINE), f"{name} must run as a non-root User="
        assert "User=root" not in text


def test_capture_service_grants_only_packet_capture_capabilities():
    text = (SYSTEMD_DIR / "network-traffic-analyzer.service").read_text()
    assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in text
    assert "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" in text


def test_dashboard_service_grants_no_capabilities():
    text = (SYSTEMD_DIR / "network-traffic-dashboard.service").read_text()
    assert "AmbientCapabilities" not in text
    assert "CapabilityBoundingSet" not in text


def test_service_units_run_as_different_users():
    analyzer_text = (SYSTEMD_DIR / "network-traffic-analyzer.service").read_text()
    dashboard_text = (SYSTEMD_DIR / "network-traffic-dashboard.service").read_text()
    analyzer_user = re.search(r"^User=(\S+)$", analyzer_text, re.MULTILINE).group(1)
    dashboard_user = re.search(r"^User=(\S+)$", dashboard_text, re.MULTILINE).group(1)
    assert analyzer_user != dashboard_user

    # Both share the same group so they can read each other's writable
    # state via group permissions, per the README's "Why it's set up this
    # way" explanation.
    analyzer_group = re.search(r"^Group=(\S+)$", analyzer_text, re.MULTILINE).group(1)
    dashboard_group = re.search(r"^Group=(\S+)$", dashboard_text, re.MULTILINE).group(1)
    assert analyzer_group == dashboard_group


def test_env_example_files_are_referenced_by_install_sh():
    install_text = (SYSTEMD_DIR / "install.sh").read_text()
    assert "capture.env.example" in install_text
    assert "dashboard.env.example" in install_text
