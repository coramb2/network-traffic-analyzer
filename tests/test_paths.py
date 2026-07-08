import os

import pytest

from paths import safe_output_path


@pytest.fixture(autouse=True)
def in_tmp_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_relative_path_resolves_under_cwd(tmp_path):
    resolved = safe_output_path("report.json")
    assert resolved == str(tmp_path / "report.json")


def test_nested_relative_path_resolves_under_cwd(tmp_path):
    resolved = safe_output_path("subdir/report.json")
    assert resolved == str(tmp_path / "subdir" / "report.json")


def test_rejects_absolute_path_outside_cwd():
    with pytest.raises(ValueError):
        safe_output_path("/etc/passwd")


def test_rejects_parent_directory_traversal():
    with pytest.raises(ValueError):
        safe_output_path("../../etc/passwd")


def test_rejects_traversal_that_stays_syntactically_inside(tmp_path):
    """'a/../../x' can look contained before resolution but escapes cwd
    once '..' components are actually collapsed."""
    with pytest.raises(ValueError):
        safe_output_path("a/../../escaped.json")


def test_rejects_symlink_escaping_cwd(tmp_path):
    outside = tmp_path.parent / "outside_target.json"
    outside.write_text("secret")
    link = tmp_path / "innocent_looking.json"
    link.symlink_to(outside)

    with pytest.raises(ValueError):
        safe_output_path("innocent_looking.json")


def test_allows_symlink_pointing_inside_cwd(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}")
    link = tmp_path / "alias.json"
    link.symlink_to(real)

    resolved = safe_output_path("alias.json")
    assert os.path.realpath(resolved) == str(real)
