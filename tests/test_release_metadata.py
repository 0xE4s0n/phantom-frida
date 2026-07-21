import hashlib
import json
from pathlib import Path

import pytest

import build


def test_release_assets_record_revisions_and_checksums(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "oemcodec-server-17.16.3-android-arm64.gz"
    artifact.write_bytes(b"artifact")
    revisions = iter(["builder-sha", "frida-sha", "core-sha"])
    monkeypatch.setattr(build, "git_revision", lambda _path: next(revisions))

    info_path, sums_path = build.write_release_assets(
        tmp_path,
        builder_dir=tmp_path / "builder",
        frida_dir=tmp_path / "frida",
        name="oemcodec",
        port=27142,
        version="17.16.3",
        architectures=["android-arm64"],
    )

    info = json.loads(info_path.read_text(encoding="utf-8"))
    assert info["builder_commit"] == "builder-sha"
    assert info["frida_commit"] == "frida-sha"
    assert info["frida_core_commit"] == "core-sha"
    assert info["ndk_version"] == "r29"
    assert info["port"] == 27142
    assert hashlib.sha256(b"artifact").hexdigest() in sums_path.read_text(
        encoding="utf-8"
    )


def test_release_assets_are_sorted_and_exclude_metadata_from_checksums(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "z-gadget.gz").write_bytes(b"gadget")
    (tmp_path / "a-server.gz").write_bytes(b"server")
    monkeypatch.setattr(build, "git_revision", lambda _path: "revision")

    info_path, sums_path = build.write_release_assets(
        tmp_path,
        builder_dir=tmp_path,
        frida_dir=tmp_path,
        name="oemcodec",
        port=None,
        version="17.16.3",
        architectures=["android-arm64"],
    )

    lines = sums_path.read_text(encoding="utf-8").splitlines()
    assert [line.split("  ", 1)[1] for line in lines] == ["a-server.gz", "z-gadget.gz"]
    assert info_path.name not in sums_path.read_text(encoding="utf-8")
    assert sums_path.name not in sums_path.read_text(encoding="utf-8")


def test_build_info_records_workflow_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(build, "git_revision", lambda _path: "revision")
    monkeypatch.setenv("GITHUB_REPOSITORY", "TheQmaks/phantom-frida")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")

    info = build.create_build_info(
        builder_dir=tmp_path,
        frida_dir=tmp_path,
        name="oemcodec",
        port=None,
        version="17.16.3",
        architectures=["android-arm64"],
    )

    assert info["workflow_url"] == (
        "https://github.com/TheQmaks/phantom-frida/actions/runs/12345"
    )
