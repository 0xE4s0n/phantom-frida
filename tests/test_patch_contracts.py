from pathlib import Path

import pytest

import build
from patches import get_source_patches

FIXTURE_DIR = Path("tests/fixtures/frida-17.16.3")


def apply_text_patches(text: str, name: str) -> str:
    for old, new in get_source_patches(name, name.capitalize()):
        text = text.replace(old, new)
    return text


def make_core_fixture(tmp_path: Path) -> Path:
    core = tmp_path / "subprojects" / "frida-core"
    linux = core / "src" / "linux"
    helpers = linux / "helpers"
    helpers.mkdir(parents=True)
    (linux / "linux-host-session.vala").write_text(
        (FIXTURE_DIR / "linux-host-session.vala").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (helpers / "zymbiote.c").write_text(
        (FIXTURE_DIR / "zymbiote.c").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (core / "lib/base").mkdir(parents=True)
    (core / "lib/base/session.vala").write_text(
        "The frida-server is not running.\n"
        'throw new Error ("Unable to communicate with remote frida-server");\n',
        encoding="utf-8",
    )
    (core / "src/socket").mkdir(parents=True)
    (core / "src/socket/socket-host-session.vala").write_text(
        "\n".join(["frida-server"] * 4),
        encoding="utf-8",
    )
    exit_monitor = core / "lib/payload/exit-monitor.vala"
    exit_monitor.parent.mkdir(parents=True)
    exit_monitor.write_text(
        (FIXTURE_DIR / "exit-monitor.vala").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    exceptor = tmp_path / "subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c"
    exceptor.parent.mkdir(parents=True)
    exceptor.write_text(
        (FIXTURE_DIR / "gumexceptor-posix.c").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return tmp_path


def test_global_patches_preserve_upstream_glib_flavor_fixture() -> None:
    source = (FIXTURE_DIR / "compat-meson.build").read_text(encoding="utf-8")
    assert apply_text_patches(source, "oemcodec") == source


@pytest.mark.parametrize(
    "identifier",
    ['"/re/frida/GadgetSession"', '"re.frida.HostSession"', '"Frida"'],
)
def test_global_patches_preserve_stock_client_identifiers(identifier: str) -> None:
    assert apply_text_patches(identifier, "oemcodec") == identifier


def test_required_patches_rename_jni_and_every_zymbiote_template(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)

    build.apply_required_file_patches(root, "oemcodec")

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in root.rglob("*.*") if path.is_file()
    )
    assert "re/frida/HelperBackend" not in combined
    assert "/frida-zymbiote-" not in combined
    assert "re/oemcodec/HelperBackend" in combined
    assert combined.count("/oemcodec-zymbiote-") == 3
    assert "frida-server" not in combined
    assert combined.count("oemcodec-server") == 6
    assert "interceptor.attach" not in combined
    assert "gum_exceptor_backend_replacement_signal, NULL" not in combined
    assert "Signal interception intentionally disabled" in combined


def test_required_patch_fails_when_upstream_contract_drifts(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)
    target = root / "subprojects/frida-core/src/linux/linux-host-session.vala"
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            "re/frida/HelperBackend", "changed/upstream/Class"
        ),
        encoding="utf-8",
    )

    with pytest.raises(build.BuildError, match="re/frida/HelperBackend"):
        build.apply_required_file_patches(root, "oemcodec")


def test_zymbiote_artifacts_patch_the_fixed_socket_field(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)
    old_socket = b"/frida-zymbiote-" + (b"0" * 32)
    old_field = old_socket.ljust(64, b"\0")
    artifacts = root / "subprojects/frida-core/src/linux/helpers/artifacts/native"
    for architecture in ("arm", "arm64", "x86", "x86_64"):
        target = artifacts / architecture / "zymbiote.elf"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"ELF-prefix" + old_field + b"ELF-suffix")

    build.patch_zymbiote_artifacts(root, "oemcodec")

    expected_socket = b"/oemcodec-zymbiote-" + (b"0" * 32)
    expected_field = expected_socket.ljust(64, b"\0")
    for target in artifacts.glob("*/zymbiote.elf"):
        data = target.read_bytes()
        assert len(data) == len(b"ELF-prefix" + old_field + b"ELF-suffix")
        assert old_socket not in data
        assert expected_field in data


def test_zymbiote_artifacts_fail_when_upstream_binary_drifts(tmp_path: Path) -> None:
    root = make_core_fixture(tmp_path)
    artifacts = root / "subprojects/frida-core/src/linux/helpers/artifacts/native"
    for architecture in ("arm", "arm64", "x86", "x86_64"):
        target = artifacts / architecture / "zymbiote.elf"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"unexpected")

    with pytest.raises(build.BuildError, match="arm/zymbiote.elf"):
        build.patch_zymbiote_artifacts(root, "oemcodec")
