import os
import subprocess
from pathlib import Path

import pytest

import build


def test_run_passes_argument_vector_without_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    build.run(["tool", "value with spaces"], cwd=tmp_path)

    assert captured["command"] == ["tool", "value with spaces"]
    assert captured.get("shell", False) is False
    assert captured["cwd"] == tmp_path


def test_run_merges_environment_and_supports_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = build.run(["tool"], env={"PHANTOM_TEST": "enabled"}, capture_output=True)

    child_env = captured["env"]
    assert isinstance(child_env, dict)
    assert child_env["PHANTOM_TEST"] == "enabled"
    assert child_env.get("PATH") == os.environ.get("PATH")
    assert captured["capture_output"] is True
    assert result.stdout == "ok\n"


def test_run_raises_build_error_for_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(build.BuildError, match="exit code 7"):
        build.run(["tool", "arg"])
