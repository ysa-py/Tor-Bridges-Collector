import os
import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_SCRIPT = REPO_ROOT / "scripts" / "zero_error_engine_v5.sh"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_missing_internal_go_package_fails_without_generating_placeholder(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/example/project.git"],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
    )

    (project / "go.mod").write_text("module github.com/example/project\n\ngo 1.22\n", encoding="utf-8")
    cmd_dir = project / "cmd" / "app"
    cmd_dir.mkdir(parents=True)
    (cmd_dir / "main.go").write_text(
        textwrap.dedent(
            """
            package main

            import _ "github.com/example/project/internal/missing"

            func main() {}
            """
        ).lstrip(),
        encoding="utf-8",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "go", "#!/usr/bin/env bash\nexit 0\n")
    env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}

    result = subprocess.run(
        ["bash", str(ENGINE_SCRIPT)],
        cwd=project,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 1
    assert "Missing Go package for import: github.com/example/project/internal/missing" in output
    assert "Expected at least one .go file in: ./internal/missing" in output
    assert "placeholder stubs are not generated" in output
    assert not (project / "internal" / "missing").exists()
    assert "TODO: Replace with actual implementation." not in "\n".join(
        path.read_text(encoding="utf-8") for path in project.rglob("*.go")
    )
