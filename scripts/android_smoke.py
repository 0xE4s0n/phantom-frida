#!/usr/bin/env python3
"""Run rooted Android acceptance checks for custom Frida server and Gadget builds."""

import argparse
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if os.fspath(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(REPOSITORY_ROOT))
build: Any = importlib.import_module("build")

REMOTE_DIR = "/data/local/tmp/phantom-frida-test"
JAVA_BRIDGE_DIR = REPOSITORY_ROOT / "node_modules" / "frida-java-bridge"
PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
SCRIPT_TIMEOUT_SECONDS = 45


class SmokeFailure(RuntimeError):
    """A rooted-device acceptance failure."""


@dataclass(frozen=True)
class AndroidSmokeConfig:
    server: Path
    gadget: Path
    name: str
    port: int
    package: str
    ndk: Path


def choose_gadget_port(server_port: int) -> int:
    candidate = server_port + 1
    return candidate if candidate <= 65535 and candidate != 27042 else 27043


def assert_clean_proc_text(label: str, text: str) -> None:
    forbidden = ("frida-zymbiote", "frida-server", "frida-helper")
    lowered = text.lower()
    matches = [marker for marker in forbidden if marker in lowered]
    if matches:
        raise SmokeFailure(f"{label} contains forbidden marker(s): {', '.join(matches)}")


def require_single_device(adb_output: str) -> str:
    devices = [
        fields[0]
        for line in adb_output.splitlines()[1:]
        if len(fields := line.split()) >= 2 and fields[1] == "device"
    ]
    if len(devices) != 1:
        raise SmokeFailure(f"Expected exactly one authorized adb device, found {len(devices)}")
    return devices[0]


def server_start_command(serial: str, remote_server: str, port: int) -> list[str]:
    return [
        "adb",
        "-s",
        serial,
        "shell",
        "su",
        "-c",
        f"{remote_server} -l 0.0.0.0:{port} -D",
    ]


def validate_config(
    *,
    server: Path,
    gadget: Path,
    name: str,
    port: int,
    package: str,
    ndk: Path,
) -> AndroidSmokeConfig:
    try:
        normalized_name = build.validate_custom_name(name)
        validated_port = build.validate_port(port)
    except RuntimeError as error:
        raise SmokeFailure(str(error)) from error

    if validated_port is None:
        raise SmokeFailure("A server port is required")
    if PACKAGE_PATTERN.fullmatch(package) is None:
        raise SmokeFailure(f"Invalid Android package: {package!r}")

    resolved_server = server.resolve()
    resolved_gadget = gadget.resolve()
    resolved_ndk = ndk.resolve()
    if not resolved_server.is_file():
        raise SmokeFailure(f"Server artifact is missing: {resolved_server}")
    if not resolved_gadget.is_file():
        raise SmokeFailure(f"Gadget artifact is missing: {resolved_gadget}")
    if not resolved_ndk.is_dir():
        raise SmokeFailure(f"Android NDK directory is missing: {resolved_ndk}")
    if resolved_server.suffix == ".gz" or resolved_gadget.suffix == ".gz":
        raise SmokeFailure("Pass uncompressed server and Gadget artifacts")

    return AndroidSmokeConfig(
        server=resolved_server,
        gadget=resolved_gadget,
        name=normalized_name,
        port=validated_port,
        package=package,
        ndk=resolved_ndk,
    )


def run_command(
    command: Sequence[str | os.PathLike[str]], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    argv = [os.fspath(part) for part in command]
    print(f"+ {subprocess.list2cmdline(argv)}", flush=True)
    try:
        result = subprocess.run(argv, capture_output=True, text=True)
    except OSError as error:
        raise SmokeFailure(f"Unable to run {argv[0]}: {error}") from error
    if check and result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        suffix = f": {details}" if details else ""
        raise SmokeFailure(f"Command failed with exit code {result.returncode}: {argv[0]}{suffix}")
    return result


def adb(
    serial: str, *arguments: str | os.PathLike[str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    return run_command(["adb", "-s", serial, *arguments], check=check)


def root_shell(
    serial: str, command: str, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return adb(serial, "shell", "su", "-c", command, check=check)


def _load_matching_frida(config: AndroidSmokeConfig) -> ModuleType:
    metadata_path = config.server.parent / "build-info.json"
    if not metadata_path.is_file():
        raise SmokeFailure(f"build-info.json is required beside the server: {metadata_path}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        expected = str(metadata["frida_version"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SmokeFailure(f"Invalid build metadata: {metadata_path}: {error}") from error

    try:
        frida_module = importlib.import_module("frida")
    except ImportError as error:
        raise SmokeFailure(f"Install the matching Frida Python package ({expected})") from error
    actual = str(getattr(frida_module, "__version__", "unknown"))
    if actual != expected:
        raise SmokeFailure(f"Frida version mismatch: build requires {expected}, host has {actual}")
    return frida_module


def _compile_agent(frida_module: Any, script_path: Path) -> str:
    if not script_path.is_file():
        raise SmokeFailure(f"Frida acceptance script is missing: {script_path}")
    if not JAVA_BRIDGE_DIR.is_dir():
        raise SmokeFailure("frida-java-bridge is missing; run npm ci in the repository")

    diagnostics: list[str] = []
    compiler = frida_module.Compiler()
    compiler.on("diagnostics", lambda diagnostic: diagnostics.append(str(diagnostic)))
    try:
        bundle = compiler.build(
            os.fspath(script_path),
            project_root=os.fspath(REPOSITORY_ROOT),
        )
    except Exception as error:
        detail = f"; diagnostics: {' | '.join(diagnostics)}" if diagnostics else ""
        raise SmokeFailure(f"Could not bundle Frida acceptance agent: {error}{detail}") from error
    if not bundle:
        raise SmokeFailure("Frida compiler returned an empty acceptance agent")
    return str(bundle)


def _prepare_remote_files(config: AndroidSmokeConfig, serial: str) -> tuple[str, str]:
    remote_server = f"{REMOTE_DIR}/{config.name}-server"
    remote_gadget = f"{REMOTE_DIR}/lib{config.name}-gadget.so"
    adb(serial, "shell", "mkdir", "-p", REMOTE_DIR)
    adb(serial, "push", config.server, remote_server)
    adb(serial, "push", config.gadget, remote_gadget)
    adb(serial, "shell", "chmod", "755", remote_server)
    return remote_server, remote_gadget


def _configure_forward(serial: str, port: int) -> None:
    adb(serial, "forward", "--remove", f"tcp:{port}", check=False)
    adb(serial, "forward", f"tcp:{port}", f"tcp:{port}")


def _wait_for_remote_device(
    manager: Any, address: str, *, timeout: float = 20
) -> tuple[Any, list[Any]]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    device: Any = None
    while time.monotonic() < deadline:
        try:
            if device is None:
                device = manager.add_remote_device(address)
            return device, list(device.enumerate_processes())
        except Exception as error:  # external Frida exceptions vary by version
            last_error = error
            time.sleep(0.5)
    raise SmokeFailure(f"Frida endpoint {address} did not become ready: {last_error}")


def _run_script_acceptance(
    device: Any, serial: str, package: str, agent_source: str
) -> dict[str, object]:
    pid: int | None = None
    session: Any = None
    outcome: dict[str, Any] = {}
    completed = threading.Event()

    def on_message(message: dict[str, Any], _data: bytes | None) -> None:
        if message.get("type") == "error":
            outcome["error"] = message.get("stack") or message.get("description") or message
            completed.set()
            return
        payload = message.get("payload")
        if (
            message.get("type") == "send"
            and isinstance(payload, dict)
            and payload.get("type") == "phantom-frida-result"
        ):
            outcome["payload"] = payload
            completed.set()

    try:
        pid = int(device.spawn([package]))
        session = device.attach(pid)
        script = session.create_script(agent_source)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        if not completed.wait(SCRIPT_TIMEOUT_SECONDS):
            raise SmokeFailure(f"Frida script timed out after {SCRIPT_TIMEOUT_SECONDS} seconds")
        if "error" in outcome:
            raise SmokeFailure(f"Frida script error: {outcome['error']}")
        payload = outcome.get("payload")
        if not isinstance(payload, dict):
            raise SmokeFailure("Frida script returned no structured result")
        failures = payload.get("failures")
        if not isinstance(failures, list):
            raise SmokeFailure("Frida script result has no failures array")
        if failures:
            raise SmokeFailure(f"Frida script assertions failed: {failures}")
        if payload.get("javaAvailable") is not True:
            raise SmokeFailure("Java bridge is unavailable in the selected application")

        _scan_process_procfs(serial, pid)
        return {
            "pid": pid,
            "java_available": True,
            "script_failures": [],
        }
    except SmokeFailure:
        raise
    except Exception as error:
        raise SmokeFailure(f"Frida server acceptance failed: {error}") from error
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if pid is not None:
            try:
                device.kill(pid)
            except Exception:
                pass


def _scan_process_procfs(serial: str, pid: int) -> None:
    commands = {
        "unix": "cat /proc/net/unix",
        "maps": f"cat /proc/{pid}/maps",
        "fds": f"ls -l /proc/{pid}/fd",
        "threads": (f'for file in /proc/{pid}/task/*/comm; do cat "$file"; done'),
    }
    for label, command in commands.items():
        result = root_shell(serial, command)
        assert_clean_proc_text(label, result.stdout)


def _find_ndk_clang(ndk: Path) -> Path:
    candidates = sorted(
        candidate
        for prebuilt in (ndk / "toolchains" / "llvm" / "prebuilt").glob("*")
        for candidate in (prebuilt / "bin" / "clang", prebuilt / "bin" / "clang.exe")
        if candidate.is_file()
    )
    if not candidates:
        raise SmokeFailure(f"NDK clang is missing under {ndk}")
    return candidates[0]


def _compile_gadget_loader(
    config: AndroidSmokeConfig, abi: str, api_level: int, output: Path
) -> None:
    target_by_abi = {
        "arm64-v8a": "aarch64-linux-android",
        "armeabi-v7a": "armv7a-linux-androideabi",
        "x86_64": "x86_64-linux-android",
        "x86": "i686-linux-android",
    }
    target = target_by_abi.get(abi)
    if target is None:
        raise SmokeFailure(f"Unsupported Android ABI for Gadget loader: {abi}")
    source = REPOSITORY_ROOT / "tests" / "android" / "gadget-loader.c"
    if not source.is_file():
        raise SmokeFailure(f"Gadget loader source is missing: {source}")
    run_command(
        [
            _find_ndk_clang(config.ndk),
            f"--target={target}{max(api_level, 21)}",
            "-fPIE",
            "-pie",
            source,
            "-ldl",
            "-o",
            output,
        ]
    )


def _exercise_gadget(
    config: AndroidSmokeConfig,
    serial: str,
    manager: Any,
    remote_gadget: str,
) -> dict[str, object]:
    gadget_port = choose_gadget_port(config.port)
    _configure_forward(serial, gadget_port)
    abi = adb(serial, "shell", "getprop", "ro.product.cpu.abi").stdout.strip()
    api_text = adb(serial, "shell", "getprop", "ro.build.version.sdk").stdout.strip()
    try:
        api_level = int(api_text)
    except ValueError as error:
        raise SmokeFailure(f"Invalid Android API level reported by device: {api_text!r}") from error

    remote_loader = f"{REMOTE_DIR}/gadget-loader"
    remote_config = f"{REMOTE_DIR}/lib{config.name}-gadget.config.so"
    remote_log = f"{REMOTE_DIR}/gadget-loader.log"
    with tempfile.TemporaryDirectory(prefix="phantom-frida-gadget-") as temporary:
        temporary_dir = Path(temporary)
        loader = temporary_dir / "gadget-loader"
        gadget_config = temporary_dir / "gadget.config.so"
        _compile_gadget_loader(config, abi, api_level, loader)
        gadget_config.write_text(
            json.dumps(
                {
                    "interaction": {
                        "type": "listen",
                        "address": "0.0.0.0",
                        "port": gadget_port,
                        "on_load": "resume",
                    }
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        adb(serial, "push", loader, remote_loader)
        adb(serial, "push", gadget_config, remote_config)
    adb(serial, "shell", "chmod", "755", remote_loader)
    root_shell(
        serial,
        f"{remote_loader} {remote_gadget} >{remote_log} 2>&1 &",
    )

    _, processes = _wait_for_remote_device(manager, f"127.0.0.1:{gadget_port}")
    if not processes:
        raise SmokeFailure("Stock Frida enumerated no process through Gadget")
    assert_clean_proc_text("gadget unix", root_shell(serial, "cat /proc/net/unix").stdout)
    return {
        "abi": abi,
        "api_level": api_level,
        "port": gadget_port,
        "process_count": len(processes),
    }


def _cleanup(config: AndroidSmokeConfig, serial: str) -> None:
    remote_server = f"{REMOTE_DIR}/{config.name}-server"
    remote_loader = f"{REMOTE_DIR}/gadget-loader"
    root_shell(serial, f"pkill -9 -f {remote_server} || true", check=False)
    root_shell(serial, f"pkill -9 -f {remote_loader} || true", check=False)
    for port in (config.port, choose_gadget_port(config.port)):
        adb(serial, "forward", "--remove", f"tcp:{port}", check=False)


def run_android_smoke(config: AndroidSmokeConfig, script_path: Path) -> dict[str, object]:
    frida_module = _load_matching_frida(config)
    agent_source = _compile_agent(frida_module, script_path)
    serial = require_single_device(run_command(["adb", "devices", "-l"]).stdout)
    root_result = root_shell(serial, "id")
    if "uid=0" not in root_result.stdout:
        raise SmokeFailure(f"adb device does not provide root through su: {root_result.stdout}")
    package_result = adb(serial, "shell", "pm", "path", config.package)
    if "package:" not in package_result.stdout:
        raise SmokeFailure(f"Android package is not installed: {config.package}")

    remote_server, remote_gadget = _prepare_remote_files(config, serial)
    manager = frida_module.get_device_manager()
    report: dict[str, object] = {
        "device_serial": serial,
        "frida_version": str(frida_module.__version__),
        "package": config.package,
        "server_port": config.port,
    }
    try:
        _configure_forward(serial, config.port)
        run_command(server_start_command(serial, remote_server, config.port))
        server_device, processes = _wait_for_remote_device(manager, f"127.0.0.1:{config.port}")
        if not processes:
            raise SmokeFailure("Stock Frida enumerated no processes through the server")
        report["server_process_count"] = len(processes)
        report["server"] = _run_script_acceptance(
            server_device, serial, config.package, agent_source
        )
        report["gadget"] = _exercise_gadget(config, serial, manager, remote_gadget)
        report["status"] = "passed"
        return report
    finally:
        _cleanup(config, serial)


def _write_report(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        **payload,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--gadget", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument(
        "--script",
        type=Path,
        default=REPOSITORY_ROOT / "test_comprehensive.js",
    )
    parser.add_argument("--report", type=Path, default=Path("android-smoke-report.json"))
    args = parser.parse_args(argv)

    try:
        config = validate_config(
            server=args.server,
            gadget=args.gadget,
            name=args.name,
            port=args.port,
            package=args.package,
            ndk=args.ndk,
        )
        report = run_android_smoke(config, args.script.resolve())
    except SmokeFailure as error:
        _write_report(args.report.resolve(), {"status": "failed", "error": str(error)})
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    _write_report(args.report.resolve(), report)
    print(f"[OK] Android smoke test passed; report: {args.report.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
