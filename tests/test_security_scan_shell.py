from scripts.security_scan import _check_shell_script


def test_sudo_rm_rf_root_is_critical() -> None:
    issues = _check_shell_script("installer.sh", "sudo rm -rf /\n")
    assert any(issue["type"] == "dangerous_sudo_rm" for issue in issues)


def test_sudo_rm_rf_specific_directory_is_not_root_wipe() -> None:
    issues = _check_shell_script("installer.sh", "sudo rm -rf /usr/local/go\n")
    assert not any(issue["type"] == "dangerous_sudo_rm" for issue in issues)
