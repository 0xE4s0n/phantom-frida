import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from scripts import android_smoke


def test_proc_scan_rejects_zymbiote_socket() -> None:
    with pytest.raises(android_smoke.SmokeFailure, match="frida-zymbiote"):
        android_smoke.assert_clean_proc_text("unix", "@/frida-zymbiote-deadbeef")


def test_proc_scan_accepts_custom_runtime_names() -> None:
    android_smoke.assert_clean_proc_text(
        "unix", "@/oemcodec-zymbiote-deadbeef\n/data/local/tmp/oemcodec-server"
    )


def test_proc_scan_uses_portable_single_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[str] = []

    def fake_root_shell(_serial: str, command: str) -> SimpleNamespace:
        commands.append(command)
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(android_smoke, "root_shell", fake_root_shell)

    android_smoke._scan_process_procfs("SERIAL-1", 123)

    assert commands == [
        "cat /proc/net/unix",
        "cat /proc/123/maps",
        "ls -l /proc/123/fd",
        "cat /proc/123/task/*/comm",
    ]


def test_gadget_port_does_not_collide_with_server() -> None:
    assert android_smoke.choose_gadget_port(27142) == 27143
    assert android_smoke.choose_gadget_port(65535) == 27043
    assert android_smoke.choose_gadget_port(27041) == 27043


def test_require_single_device_returns_only_authorized_serial() -> None:
    output = "List of devices attached\nSERIAL-1\tdevice product:test\n\n"
    assert android_smoke.require_single_device(output) == "SERIAL-1"


@pytest.mark.parametrize(
    "output,count",
    [
        ("List of devices attached\n", 0),
        ("List of devices attached\nSERIAL\tunauthorized\n", 0),
        ("List of devices attached\nONE\tdevice\nTWO\tdevice\n", 2),
    ],
)
def test_require_single_device_rejects_invalid_device_count(output: str, count: int) -> None:
    with pytest.raises(android_smoke.SmokeFailure, match=f"found {count}"):
        android_smoke.require_single_device(output)


def test_server_start_command_uses_fixed_adb_argument_vector() -> None:
    assert android_smoke.server_start_command(
        "SERIAL-1", "/data/local/tmp/phantom-frida-test/oemcodec-server", 27142
    ) == [
        "adb",
        "-s",
        "SERIAL-1",
        "shell",
        "su",
        "-c",
        (
            "/data/local/tmp/phantom-frida-test/oemcodec-server "
            "-l 0.0.0.0:27142 -D </dev/null "
            ">/data/local/tmp/phantom-frida-test/server.log 2>&1"
        ),
    ]


def test_validate_config_normalizes_builder_inputs(tmp_path: Path) -> None:
    server = tmp_path / "server"
    gadget = tmp_path / "gadget.so"
    ndk = tmp_path / "ndk"
    server.write_bytes(b"server")
    gadget.write_bytes(b"gadget")
    ndk.mkdir()

    config = android_smoke.validate_config(
        server=server,
        gadget=gadget,
        name="OemCodec",
        port=27142,
        package="com.example.app",
        ndk=ndk,
    )

    assert config.name == "oemcodec"
    assert config.port == 27142


@pytest.mark.parametrize("package", ["", "single", "com.example;id", "9com.example"])
def test_validate_config_rejects_unsafe_package(tmp_path: Path, package: str) -> None:
    server = tmp_path / "server"
    gadget = tmp_path / "gadget.so"
    ndk = tmp_path / "ndk"
    server.write_bytes(b"server")
    gadget.write_bytes(b"gadget")
    ndk.mkdir()

    with pytest.raises(android_smoke.SmokeFailure, match="package"):
        android_smoke.validate_config(
            server=server,
            gadget=gadget,
            name="oemcodec",
            port=27142,
            package=package,
            ndk=ndk,
        )


def test_remote_device_retry_does_not_register_duplicate_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeDevice:
        calls = 0

        def enumerate_processes(self) -> list[str]:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("not ready")
            return ["process"]

    class FakeManager:
        calls = 0
        device = FakeDevice()

        def add_remote_device(self, _address: str) -> FakeDevice:
            self.calls += 1
            return self.device

    manager = FakeManager()
    monkeypatch.setattr(android_smoke.time, "sleep", lambda _seconds: None)

    device, processes = android_smoke._wait_for_remote_device(manager, "127.0.0.1:27142", timeout=1)

    assert device is manager.device
    assert processes == ["process"]
    assert manager.calls == 1


def test_host_frida_version_must_match_build_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = tmp_path / "server"
    gadget = tmp_path / "gadget.so"
    ndk = tmp_path / "ndk"
    server.write_bytes(b"server")
    gadget.write_bytes(b"gadget")
    ndk.mkdir()
    (tmp_path / "build-info.json").write_text('{"frida_version": "17.16.3"}', encoding="utf-8")
    config = android_smoke.validate_config(
        server=server,
        gadget=gadget,
        name="oemcodec",
        port=27142,
        package="com.example.app",
        ndk=ndk,
    )
    fake_frida = ModuleType("frida")
    fake_frida.__version__ = "17.7.2"
    monkeypatch.setattr(
        android_smoke.importlib,
        "import_module",
        lambda _name: fake_frida,
    )

    with pytest.raises(android_smoke.SmokeFailure, match="version mismatch"):
        android_smoke._load_matching_frida(config)


def test_agent_is_bundled_with_frida_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "agent.js"
    script.write_text("export const value = 1;", encoding="utf-8")
    bridge = tmp_path / "node_modules/frida-java-bridge"
    bridge.mkdir(parents=True)
    calls: dict[str, str] = {}

    class FakeCompiler:
        def on(self, _event: str, _callback: object) -> None:
            return None

        def build(self, entrypoint: str, *, project_root: str) -> str:
            calls["entrypoint"] = entrypoint
            calls["project_root"] = project_root
            return "bundled-agent"

    class FakeFrida:
        @staticmethod
        def Compiler() -> FakeCompiler:
            return FakeCompiler()

    monkeypatch.setattr(android_smoke, "JAVA_BRIDGE_DIR", bridge)

    assert android_smoke._compile_agent(FakeFrida(), script) == "bundled-agent"
    assert calls["entrypoint"] == str(script)
    assert calls["project_root"] == str(android_smoke.REPOSITORY_ROOT)


def test_acceptance_agent_uses_frida_17_file_and_java_wrapper_apis() -> None:
    source = (android_smoke.REPOSITORY_ROOT / "test_comprehensive.js").read_text(encoding="utf-8")

    assert ".readAllText()" not in source
    assert source.count("File.readAllText(") == 2
    assert "Java.cast(iterator.next(), Thread).getName()" in source


def test_report_writer_omits_device_serial(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"

    android_smoke._write_report(
        report_path,
        {"status": "passed", "device_serial": "SECRET-SERIAL"},
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    assert "device_serial" not in report
