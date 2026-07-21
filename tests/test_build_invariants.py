from pathlib import Path
from types import SimpleNamespace

import pytest

import build


def test_verify_binary_rejects_known_runtime_markers(tmp_path: Path) -> None:
    binary = tmp_path / "server"
    binary.write_bytes(b"prefix\x00/frida-zymbiote-123\x00re/frida/HelperBackend\x00")

    with pytest.raises(build.BuildError, match="frida-zymbiote"):
        build.verify_binary(binary)


def test_collect_artifacts_requires_server_and_gadget(tmp_path: Path) -> None:
    with pytest.raises(build.BuildError, match="Server artifact"):
        build.collect_artifacts(
            tmp_path,
            "android-arm64",
            "oemcodec",
            "17.16.3",
            tmp_path / "stage",
            True,
        )


def test_collect_artifacts_rejects_missing_gadget(tmp_path: Path) -> None:
    server_dir = tmp_path / "build/subprojects/frida-core/server"
    server_dir.mkdir(parents=True)
    (server_dir / "oemcodec-server").write_bytes(b"clean-server")

    with pytest.raises(build.BuildError, match="Gadget artifact"):
        build.collect_artifacts(
            tmp_path,
            "android-arm64",
            "oemcodec",
            "17.16.3",
            tmp_path / "stage",
            True,
        )


def test_collect_artifacts_returns_only_verified_staged_outputs(tmp_path: Path) -> None:
    core_build = tmp_path / "build/subprojects/frida-core"
    server_dir = core_build / "server"
    gadget_dir = core_build / "lib/gadget"
    server_dir.mkdir(parents=True)
    gadget_dir.mkdir(parents=True)
    (server_dir / "oemcodec-server").write_bytes(b"clean-server")
    (gadget_dir / "liboemcodec-gadget.so").write_bytes(b"clean-gadget")
    output_dir = tmp_path / "stage"

    outputs = build.collect_artifacts(
        tmp_path,
        "android-arm64",
        "oemcodec",
        "17.16.3",
        output_dir,
        True,
    )

    assert {path.parent for path in outputs} == {output_dir}
    assert {path.name for path in outputs} == {
        "oemcodec-server-17.16.3-android-arm64",
        "oemcodec-server-17.16.3-android-arm64.gz",
        "oemcodec-gadget-17.16.3-android-arm64.so",
        "oemcodec-gadget-17.16.3-android-arm64.so.gz",
    }
    assert not list(output_dir.glob(".staging-*"))


def test_collect_artifacts_does_not_promote_failed_stage(tmp_path: Path) -> None:
    core_build = tmp_path / "build/subprojects/frida-core"
    server_dir = core_build / "server"
    gadget_dir = core_build / "lib/gadget"
    server_dir.mkdir(parents=True)
    gadget_dir.mkdir(parents=True)
    (server_dir / "oemcodec-server").write_bytes(b"/frida-zymbiote-invalid")
    (gadget_dir / "liboemcodec-gadget.so").write_bytes(b"clean-gadget")
    output_dir = tmp_path / "stage"

    with pytest.raises(build.BuildError, match="frida-zymbiote"):
        build.collect_artifacts(
            tmp_path,
            "android-arm64",
            "oemcodec",
            "17.16.3",
            output_dir,
            True,
        )

    assert output_dir.is_dir()
    assert not list(output_dir.iterdir())


def test_rename_does_not_descend_into_build_directory(tmp_path: Path) -> None:
    source = tmp_path / "src"
    generated = tmp_path / "build"
    source.mkdir()
    generated.mkdir()
    (source / "frida-agent.txt").write_text("source", encoding="utf-8")
    (generated / "frida-agent.txt").write_text("generated", encoding="utf-8")

    build.rename_frida_files(tmp_path, "oemcodec")

    assert (source / "oemcodec-agent.txt").exists()
    assert (generated / "frida-agent.txt").exists()


def test_rebuild_helper_dex_fails_without_javac(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = tmp_path / "subprojects/frida-core/src/android-helper/re/frida"
    helper.mkdir(parents=True)
    (helper / "Helper.java").write_text(
        "package re.frida; public class Helper {}", encoding="utf-8"
    )
    (helper.parent.parent / "helper.dex").write_bytes(b"old-dex")
    monkeypatch.setattr(build.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="missing"),
    )

    with pytest.raises(build.BuildError, match="javac"):
        build.rebuild_helper_dex(tmp_path, "oemcodec")


@pytest.mark.parametrize("tool", ["javac", "jar", "java"])
def test_require_executable_names_missing_tool(tool: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build.shutil, "which", lambda _name: None)

    with pytest.raises(build.BuildError, match=tool):
        build.require_executable(tool)


def test_find_android_jar_fails_when_sdk_has_no_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", (tmp_path,))

    with pytest.raises(build.BuildError, match="android.jar"):
        build.find_android_jar()


def test_find_android_jar_uses_sdk_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    android_jar = tmp_path / "platforms/android-36/android.jar"
    android_jar.parent.mkdir(parents=True)
    android_jar.write_bytes(b"jar")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())

    assert build.find_android_jar() == android_jar


def test_find_android_jar_ignores_unrelated_recursive_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    android_jar = tmp_path / "platforms/android-36/android.jar"
    android_jar.parent.mkdir(parents=True)
    android_jar.write_bytes(b"platform")
    unrelated = tmp_path / "zzz/vendor/android.jar"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_bytes(b"unrelated")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())

    assert build.find_android_jar() == android_jar


def test_find_d8_fails_when_sdk_has_no_build_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", (tmp_path,))
    monkeypatch.setattr(build.shutil, "which", lambda _name: None)

    with pytest.raises(build.BuildError, match="d8"):
        build.find_d8_command()


def test_find_d8_uses_sdk_jar_entry_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d8_jar = tmp_path / "build-tools/36.0.0/lib/d8.jar"
    d8_jar.parent.mkdir(parents=True)
    d8_jar.write_bytes(b"jar")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())
    monkeypatch.setattr(
        build.shutil,
        "which",
        lambda name: "/usr/bin/java" if name == "java" else None,
    )

    assert build.find_d8_command() == [
        "/usr/bin/java",
        "-cp",
        str(d8_jar),
        "com.android.tools.r8.D8",
    ]


def test_find_d8_ignores_unrelated_recursive_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d8_jar = tmp_path / "build-tools/36.0.0/lib/d8.jar"
    d8_jar.parent.mkdir(parents=True)
    d8_jar.write_bytes(b"jar")
    unrelated = tmp_path / "zzz/vendor/d8"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_bytes(b"unrelated")
    unrelated.chmod(0o755)
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path))
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setattr(build, "ANDROID_FALLBACK_ROOTS", ())
    monkeypatch.setattr(
        build.shutil,
        "which",
        lambda name: "/usr/bin/java" if name == "java" else None,
    )

    assert build.find_d8_command() == [
        "/usr/bin/java",
        "-cp",
        str(d8_jar),
        "com.android.tools.r8.D8",
    ]


def test_port_only_patch_preserves_extended_identifiers(tmp_path: Path) -> None:
    marker = tmp_path / "subprojects/frida-core/marker.vala"
    marker.parent.mkdir(parents=True)
    marker.write_text('27042 "FridaServer" ".frida"', encoding="utf-8")

    build.apply_port_patches(tmp_path, 27142)

    patched = marker.read_text(encoding="utf-8")
    assert patched == '27142 "FridaServer" ".frida"'


def test_validate_ndk_requires_exact_revision(tmp_path: Path) -> None:
    ndk = tmp_path / "android-ndk-r29"
    ndk.mkdir()
    (ndk / "source.properties").write_text(
        "Pkg.Desc = Android NDK\nPkg.Revision = 28.2.13676358\n",
        encoding="utf-8",
    )

    with pytest.raises(build.BuildError, match="revision"):
        build.validate_ndk(ndk)


def test_validate_ndk_accepts_documented_revision(tmp_path: Path) -> None:
    ndk = tmp_path / "android-ndk-r29"
    ndk.mkdir()
    (ndk / "source.properties").write_text(
        "Pkg.Desc = Android NDK\nPkg.Revision = 29.0.14206865\n",
        encoding="utf-8",
    )

    assert build.validate_ndk(ndk) == ndk


def test_ensure_ndk_rejects_cached_archive_with_wrong_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "android-ndk-r29-linux.zip"
    archive.write_bytes(b"not the Google NDK archive")
    commands: list[list[str]] = []
    monkeypatch.setattr(build, "run", lambda command, **_kwargs: commands.append(command))

    with pytest.raises(build.BuildError, match="checksum"):
        build.ensure_ndk(tmp_path)

    assert commands == []
