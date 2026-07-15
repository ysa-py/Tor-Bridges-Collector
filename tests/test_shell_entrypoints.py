import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_shell_entrypoints.sh"


def test_shebang_file_without_extension_requires_executable_bit(tmp_path):
    script = tmp_path / "entrypoint"
    script.write_text("#!/usr/bin/env bash\necho hello\n", encoding="utf-8")

    result = subprocess.run(
        [str(CHECK_SCRIPT), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert f"Missing executable bit for shebang script: {script}" in result.stdout
