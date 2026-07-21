#!/usr/bin/env python3
"""
Custom Frida Builder — build anti-detection Frida server from source.

Extended beyond ajeossida with additional stealth techniques.
Verified against Frida 17.7.2 source code.

Usage (run in WSL Ubuntu):
    python3 build.py --version 17.7.2
    python3 build.py --version 17.7.2 --name stealth --port 27142
    python3 build.py --version 17.7.2 --arch android-arm64,android-arm --extended
    python3 build.py --version 17.7.2 --skip-build  # only patch, don't compile

Requirements:
    - Ubuntu 22.04+ (WSL works)
    - Python 3.10+
    - Git
    - ~20GB free disk space
    - Internet connection (clones Frida + downloads NDK)
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from patches import (
    DETECTION_VECTORS,
    LIBC_HOOK_PATCHES,
    MEMFD_PATCHES,
    SELINUX_PATCHES,
    get_binary_patches,
    get_binary_string_patches,
    get_internal_patches,
    get_port_patches,
    get_required_file_patches,
    get_rollback_patches,
    get_source_patches,
    get_stability_patches_17,
    get_targeted_patches,
    get_temp_path_patches,
)

# --- Constants ---

NDK_VERSION = "r29"
NDK_URL = f"https://dl.google.com/android/repository/android-ndk-{NDK_VERSION}-linux.zip"
ALL_ARCHS = ["android-arm64", "android-arm", "android-x86_64", "android-x86"]
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]{2,31}$")
ANDROID_FALLBACK_ROOTS = (
    Path("/usr/local/lib/android/sdk"),
    Path("/usr/local/lib/android"),
)
FORBIDDEN_BINARY_MARKERS = (
    b"frida\x00",
    b"frida-zymbiote",
    b"re/frida/HelperBackend",
    b"frida-server",
    b"frida-helper",
)


class BuildError(RuntimeError):
    """Expected build failure that should be shown without a traceback."""


def log(msg: str, level: str = "INFO"):
    colors = {
        "INFO": "\033[36m",
        "OK": "\033[32m",
        "WARN": "\033[33m",
        "ERROR": "\033[31m",
        "STEP": "\033[35m",
        "HEADER": "\033[1;37m",
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    print(f"{color}[{level}]{reset} {msg}", flush=True)


def run(
    command: Sequence[str | os.PathLike[str]],
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run an argument vector with inherited environment plus overrides."""
    if isinstance(command, (str, bytes)):
        raise BuildError("Commands must be passed as an argument vector")

    argv = [os.fspath(part) for part in command]
    if not argv:
        raise BuildError("Command argument vector must not be empty")

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    rendered_command = shlex.join(argv)
    log(f"$ {rendered_command}", "INFO")
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=full_env,
            capture_output=capture_output,
            text=True,
        )
    except OSError as error:
        raise BuildError(f"Unable to run command: {rendered_command}: {error}") from error
    if check and result.returncode != 0:
        raise BuildError(
            f"Command failed with exit code {result.returncode}: {rendered_command}"
        )
    return result


def validate_version(value: str) -> str:
    """Accept only concrete Frida release tags such as 17.16.3."""
    if VERSION_PATTERN.fullmatch(value) is None:
        raise BuildError("Frida version must use the numeric X.Y.Z release format")
    return value


def validate_custom_name(value: str) -> str:
    """Normalize and validate the identifier used in paths, packages, and symbols."""
    normalized = value.lower()
    if NAME_PATTERN.fullmatch(normalized) is None:
        raise BuildError(
            "Custom name must be 3-32 lowercase letters or digits and start with a letter"
        )
    return normalized


def validate_port(value: int | None) -> int | None:
    """Validate an optional TCP port."""
    if value is not None and not 1 <= value <= 65535:
        raise BuildError("Port must be between 1 and 65535")
    return value


def parse_architectures(value: str) -> list[str]:
    """Parse and validate the requested Android architecture list."""
    architectures = [architecture.strip() for architecture in value.split(",")]
    invalid = [architecture for architecture in architectures if architecture not in ALL_ARCHS]
    if invalid:
        shown = invalid[0] or "<empty>"
        raise BuildError(
            f"Unknown architecture: {shown}. Valid: {', '.join(ALL_ARCHS)}"
        )
    return architectures


def require_executable(name: str) -> str:
    """Resolve a mandatory executable or fail with its name."""
    path = shutil.which(name)
    if path is None:
        raise BuildError(f"Required executable is missing: {name}")
    return path


def _android_sdk_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    roots.extend(ANDROID_FALLBACK_ROOTS)
    return tuple(dict.fromkeys(roots))


def find_android_jar() -> Path:
    """Find the newest available Android platform API JAR."""
    candidates = {
        candidate
        for root in _android_sdk_roots()
        if root.exists()
        for candidate in root.rglob("android.jar")
        if candidate.is_file()
    }
    if not candidates:
        raise BuildError("Required Android SDK platform file is missing: android.jar")
    return sorted(candidates, key=os.fspath, reverse=True)[0]


def find_d8_command() -> list[str]:
    """Resolve D8 as an executable or its JAR entry point."""
    executable = shutil.which("d8")
    if executable is not None:
        return [executable]

    roots = [root for root in _android_sdk_roots() if root.exists()]
    executables = {
        candidate
        for root in roots
        for candidate in root.rglob("d8")
        if candidate.is_file() and os.access(candidate, os.X_OK)
    }
    if executables:
        return [os.fspath(sorted(executables, key=os.fspath, reverse=True)[0])]

    jars = {
        candidate
        for root in roots
        for candidate in root.rglob("d8.jar")
        if candidate.is_file()
    }
    if jars:
        d8_jar = sorted(jars, key=os.fspath, reverse=True)[0]
        return [
            require_executable("java"),
            "-cp",
            os.fspath(d8_jar),
            "com.android.tools.r8.D8",
        ]

    raise BuildError("Required Android build tool is missing: d8")


def detect_frida_major(version: str) -> int:
    return int(version.split(".")[0])


# ============================================================================
# File operations
# ============================================================================

def replace_in_file(filepath: Path, old: str, new: str) -> int:
    """Replace string in a single file. Returns number of replacements."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, IsADirectoryError, OSError):
        return 0
    if old not in content:
        return 0
    count = content.count(old)
    content = content.replace(old, new)
    filepath.write_text(content, encoding="utf-8")
    return count


def replace_in_tree(root: Path, old: str, new: str,
                    include_build: bool = False) -> int:
    """Recursively replace string in all text files under root."""
    total = 0
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv"}
    if not include_build:
        skip_dirs.add("build")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            # Skip binary files by extension
            if fpath.suffix in {".o", ".a", ".so", ".gz", ".zip", ".png", ".jpg", ".pyc",
                                ".dex", ".jar", ".class", ".elf", ".wasm", ".dylib", ".dll"}:
                continue
            total += replace_in_file(fpath, old, new)

    return total


# ============================================================================
# NDK
# ============================================================================

def ensure_ndk(work_dir: Path) -> Path:
    """Download and extract Android NDK if needed."""
    ndk_dir = work_dir / f"android-ndk-{NDK_VERSION}"
    if ndk_dir.exists():
        log(f"NDK already at {ndk_dir}", "OK")
        return ndk_dir

    ndk_zip = work_dir / f"android-ndk-{NDK_VERSION}-linux.zip"
    if not ndk_zip.exists():
        log(f"Downloading NDK {NDK_VERSION} (~1.5 GB)...", "STEP")
        run(["curl", "-L", "-o", ndk_zip, NDK_URL], cwd=work_dir)

    log("Extracting NDK...", "STEP")
    run(["unzip", "-q", ndk_zip], cwd=work_dir)

    if ndk_dir.exists():
        log(f"NDK ready at {ndk_dir}", "OK")
        ndk_zip.unlink(missing_ok=True)
        return ndk_dir
    raise BuildError(f"NDK extraction did not create expected directory: {ndk_dir}")


# ============================================================================
# Clone
# ============================================================================

def clone_frida(version: str, work_dir: Path) -> Path:
    """Clone Frida source at the specified version tag."""
    frida_dir = work_dir / "frida"
    if frida_dir.exists():
        log(f"Frida source already at {frida_dir}", "OK")
        return frida_dir

    log(f"Cloning Frida {version} (with submodules)...", "STEP")
    run(
        [
            "git",
            "clone",
            "--recurse-submodules",
            "--branch",
            version,
            "--depth",
            "1",
            "https://github.com/frida/frida.git",
            frida_dir,
        ],
        cwd=work_dir,
    )
    log(f"Frida {version} cloned", "OK")
    return frida_dir


# ============================================================================
# PHASE 1: Source-level patches (before build)
# ============================================================================

def rename_frida_files(frida_dir: Path, custom_name: str):
    """
    Rename files on disk whose names contain 'frida-helper' or 'frida-agent' etc.
    After global source patches rename references in meson.build/Vala/C files,
    the actual files on disk must also be renamed to match.

    IMPORTANT: Skip build system files (.symbols, .version, .def, .plist, .xcent)
    because rollback patches revert their references to original names.
    Also skip releng/frida_version.py (not renamed by our patches).
    """
    rename_patterns = [
        ("frida-helper", f"{custom_name}-helper"),
        ("frida-agent", f"{custom_name}-agent"),
        ("frida-gadget", f"{custom_name}-gadget"),
        ("frida-server", f"{custom_name}-server"),
    ]

    # Build system file extensions that rollback patches keep with original names
    skip_extensions = {".symbols", ".version", ".def", ".plist", ".xcent"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "build"}
    # Specific files to never rename
    skip_names = {"frida_version.py", "frida-version.py"}
    renamed_count = 0

    for dirpath, dirnames, filenames in os.walk(frida_dir, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname in skip_names:
                continue
            # Skip build system files (rollback patches keep their original names)
            if Path(fname).suffix in skip_extensions:
                continue
            new_fname = fname
            for old_pat, new_pat in rename_patterns:
                if old_pat in new_fname:
                    new_fname = new_fname.replace(old_pat, new_pat)
            if new_fname != fname:
                old_path = Path(dirpath) / fname
                new_path = Path(dirpath) / new_fname
                if old_path.exists() and not new_path.exists():
                    old_path.rename(new_path)
                    renamed_count += 1

    if renamed_count:
        log(f"  Renamed {renamed_count} files on disk", "OK")


def _require_success(
    tool: str, result: subprocess.CompletedProcess[str]
) -> None:
    if result.returncode == 0:
        return
    details = (result.stderr or result.stdout or "").strip()
    suffix = f": {details}" if details else ""
    raise BuildError(f"{tool} failed with exit code {result.returncode}{suffix}")


def rebuild_helper_dex(frida_dir: Path, custom_name: str) -> Path:
    """Rebuild the Android helper DEX with renamed Java package.

    The pre-compiled helper.dex in the repo contains 're.frida.Helper'.
    We need to recompile it with the new package name so that:
    1. The DEX string table doesn't contain 'frida' (binary sweep safe)
    2. The class name matches what the renamed Vala code expects
    """
    helper_dir = frida_dir / "subprojects" / "frida-core" / "src" / "android-helper"
    old_pkg_dir = helper_dir / "re" / "frida"
    new_pkg_dir = helper_dir / "re" / custom_name
    java_file = old_pkg_dir / "Helper.java"

    if not java_file.exists():
        # Package might already be renamed (e.g., from cache)
        java_file = new_pkg_dir / "Helper.java"
        if not java_file.exists():
            raise BuildError(f"Required Android helper source is missing: {java_file}")

    # Rename directory: re/frida/ -> re/{name}/
    if old_pkg_dir.exists() and new_pkg_dir.exists():
        raise BuildError(f"Both helper package directories exist: {old_pkg_dir}, {new_pkg_dir}")
    if old_pkg_dir.exists():
        old_pkg_dir.rename(new_pkg_dir)
        log(f"  Renamed {old_pkg_dir.name}/ -> {new_pkg_dir.name}/", "OK")

    java_file = new_pkg_dir / "Helper.java"
    if not java_file.exists():
        raise BuildError(f"Required Android helper source is missing after rename: {java_file}")

    # The Java source was already patched by replace_in_tree:
    #   "package re.frida;" -> "package re.{name};"
    #   "re.frida.Helper" -> "re.{name}.Helper"
    # Verify:
    content = java_file.read_text(encoding="utf-8")
    if f"package re.{custom_name};" not in content:
        content = content.replace("package re.frida;", f"package re.{custom_name};")
        if f"package re.{custom_name};" not in content:
            raise BuildError(f"Could not patch Android helper package in {java_file}")
        java_file.write_text(content, encoding="utf-8")

    dex_file = helper_dir / "helper.dex"
    if not dex_file.is_file():
        raise BuildError(f"Required precompiled Android helper DEX is missing: {dex_file}")

    javac_path = require_executable("javac")
    jar_path = require_executable("jar")
    android_jar = find_android_jar()
    d8_command = find_d8_command()

    log(f"  Recompiling helper DEX (android.jar: {android_jar.name})...", "STEP")
    with TemporaryDirectory(dir=helper_dir, prefix=".dex-build-") as temporary:
        build_dir = Path(temporary)
        java_build = build_dir / "java"
        dex_build = build_dir / "dex"
        java_build.mkdir()
        dex_build.mkdir()

        javac_result = run(
            [
                javac_path,
                "-cp",
                f".{os.pathsep}{android_jar}",
                "-bootclasspath",
                android_jar,
                "-source",
                "1.8",
                "-target",
                "1.8",
                "-Xlint:-options",
                java_file,
                "-d",
                java_build,
            ],
            cwd=helper_dir,
            check=False,
            capture_output=True,
        )
        _require_success("javac", javac_result)

        class_files = list((java_build / "re" / custom_name).glob("*.class"))
        if not class_files:
            raise BuildError(f"javac generated no helper classes under re/{custom_name}")
        log(f"  Compiled {len(class_files)} helper class files", "OK")

        jar_file = build_dir / f"{custom_name}-helper.jar"
        jar_result = run(
            [jar_path, "cfe", jar_file, f"re.{custom_name}.Helper", "-C", java_build, "."],
            cwd=helper_dir,
            check=False,
            capture_output=True,
        )
        _require_success("jar", jar_result)

        d8_result = run(
            [*d8_command, "--lib", android_jar, "--output", dex_build, jar_file],
            cwd=helper_dir,
            check=False,
            capture_output=True,
        )
        _require_success("d8", d8_result)

        new_dex = dex_build / "classes.dex"
        if not new_dex.is_file():
            raise BuildError(f"d8 did not generate expected output: {new_dex}")
        shutil.copy2(new_dex, dex_file)

    log(
        f"  Helper DEX rebuilt: {dex_file.stat().st_size} bytes "
        f"(package: re.{custom_name})",
        "OK",
    )
    return dex_file


def apply_required_file_patches(frida_dir: Path, custom_name: str) -> None:
    """Apply source contracts that must match the supported Frida source shape."""
    for patch in get_required_file_patches(custom_name):
        target = frida_dir / patch.relative_path
        if not target.is_file():
            raise BuildError(f"Required patch file is missing: {patch.relative_path}")

        count = replace_in_file(target, patch.old, patch.new)
        if count < patch.minimum:
            raise BuildError(
                f"Required pattern {patch.old!r} occurred {count} times in "
                f"{patch.relative_path}; expected at least {patch.minimum}"
            )
        log(f"  [required] {patch.relative_path}: {patch.old} ({count})", "OK")


def apply_source_patches(frida_dir: Path, custom_name: str):
    """Apply global recursive string replacements across the source tree."""
    log("=" * 60, "HEADER")
    log("PHASE 1: Global source patches", "STEP")
    log("=" * 60, "HEADER")

    apply_required_file_patches(frida_dir, custom_name)

    cap_name = custom_name[0].upper() + custom_name[1:]

    patches = get_source_patches(custom_name, cap_name)
    for old, new in patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  {old} -> {new} ({count})", "OK")
        else:
            log(f"  {old} -> (not found)", "WARN")

    # Rollback accidental renames of build system files
    log("Rolling back build file renames...", "STEP")
    rollbacks = get_rollback_patches(custom_name)
    for old, new in rollbacks:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  [rollback] {old} ({count})", "INFO")

    # Rename actual files on disk to match source references
    rename_frida_files(frida_dir, custom_name)

    # Rebuild helper DEX with renamed Java package
    rebuild_helper_dex(frida_dir, custom_name)

    log("Global source patches complete", "OK")


def apply_targeted_patches(frida_dir: Path, custom_name: str, frida_major: int):
    """Apply patches to specific files (memfd, libc hooks, SELinux, build system)."""
    log("=" * 60, "HEADER")
    log("PHASE 2: Targeted file patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]
    core_dir = frida_dir / "subprojects" / "frida-core"
    gum_dir = frida_dir / "subprojects" / "frida-gum"

    # --- memfd_create: hide agent name in /proc/pid/fd ---
    memfd_cfg = MEMFD_PATCHES.get(frida_major, MEMFD_PATCHES[17])
    memfd_file = core_dir / memfd_cfg["file"]
    if memfd_file.exists():
        count = replace_in_file(memfd_file, memfd_cfg["old"], memfd_cfg["new"])
        if count:
            log(f"  memfd_create -> 'jit-cache' in {memfd_cfg['file']}", "OK")
        else:
            log(f"  memfd_create: pattern not found in {memfd_cfg['file']}", "WARN")
    else:
        log(f"  memfd file missing: {memfd_cfg['file']}", "WARN")

    # --- Disable exit monitor (prevents detection via hooked exit/_exit/abort) ---
    exit_monitor = core_dir / "lib" / "payload" / "exit-monitor.vala"
    if exit_monitor.exists():
        for old, new in LIBC_HOOK_PATCHES["exit_monitor"]:
            count = replace_in_file(exit_monitor, old, new)
            if count:
                log(f"  exit-monitor: disabled interceptor.attach ({count})", "OK")

    # --- Disable signal/sigaction hooking ---
    exceptor = gum_dir / "gum" / "backend-posix" / "gumexceptor-posix.c"
    if exceptor.exists():
        for old, new in LIBC_HOOK_PATCHES["exceptor"]:
            count = replace_in_file(exceptor, old, new)
            if count:
                log(f"  gumexceptor: disabled hook ({count})", "OK")

    # --- SELinux labels (in linjector.vala for 17.x) ---
    for old, new in SELINUX_PATCHES(custom_name):
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  SELinux: {old} -> {new} ({count})", "OK")

    # --- Build system files ---
    targets = {
        "server_meson": core_dir / "server" / "meson.build",
        "compat_build": core_dir / "compat" / "build.py",
        "core_meson": core_dir / "meson.build",
        "gadget_meson": core_dir / "lib" / "gadget" / "meson.build",
        "agent_meson": core_dir / "lib" / "agent" / "meson.build",
    }

    for target_name, target_file in targets.items():
        if target_file.exists():
            patches = get_targeted_patches(custom_name, cap_name, target_name)
            applied = 0
            for old, new in patches:
                applied += replace_in_file(target_file, old, new)
            if applied:
                log(f"  {target_name}: {applied} patches", "OK")
        else:
            log(f"  {target_name}: file not found", "WARN")

    log("Targeted patches complete", "OK")


def apply_port_patches(frida_dir: Path, port: int | None) -> None:
    """Apply only the configured listening-port replacement."""
    if port is not None and port != 27042:
        port_patches = get_port_patches(port)
        for patch in port_patches:
            for fpath in patch["files"]:
                full_path = frida_dir / fpath
                if full_path.exists():
                    count = replace_in_file(full_path, patch["pattern"], patch["replacement"])
                    if count:
                        log(f"  Port: {patch['description']} in {Path(fpath).name} ({count})", "OK")
        # Also do a global sweep for the port number in less obvious places
        count = replace_in_tree(frida_dir / "subprojects" / "frida-core", "27042", str(port))
        if count:
            log(f"  Port: global sweep found {count} more occurrences", "OK")


def apply_extended_patches(frida_dir: Path, custom_name: str, port: int | None):
    """Apply extended anti-detection patches beyond ajeossida."""
    log("=" * 60, "HEADER")
    log("PHASE 2.5: Extended anti-detection patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]

    apply_port_patches(frida_dir, port)

    # --- D-Bus interface names ---
    # NOTE: Transport/D-Bus interface renames (re.frida.HostSession etc.) are DISABLED.
    # These interface names are part of the Frida client-server protocol.
    # Renaming them on the server breaks communication with the standard frida client.
    # They are NOT visible to other apps (only over USB/TCP channel), so not a detection vector.
    # The D-Bus service name (re.frida.server) IS renamed by global source patches — that's safe.

    # --- Internal identifiers (C symbols, GType names) ---
    internal_patches = get_internal_patches(custom_name, cap_name)
    for old, new in internal_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Internal: {old} -> {new} ({count})", "OK")

    # --- Temp file paths ---
    temp_patches = get_temp_path_patches(custom_name)
    for old, new in temp_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Temp paths: {old} -> {new} ({count})", "OK")

    log("Extended patches complete", "OK")


def apply_stability_fixes(frida_dir: Path, frida_major: int):
    """Apply optional stability/crash fixes."""
    log("Applying stability fixes...", "STEP")

    core_dir = frida_dir / "subprojects" / "frida-core"

    if frida_major >= 17:
        patches = get_stability_patches_17(frida_dir)
        for patch in patches:
            fpath = frida_dir / patch["file"]
            if fpath.exists():
                count = replace_in_file(fpath, patch["old"], patch["new"])
                if count:
                    log(f"  {patch['description']}", "OK")
                else:
                    log(f"  Pattern not found: {patch['description']}", "WARN")

    # DirListCloaker interceptor detach — safe to disable to prevent crash
    cloak = core_dir / "lib" / "payload" / "cloak.vala"
    if cloak.exists():
        # 17.x: DirListCloaker uses Gum.Interceptor.detach in destructor
        old = "Gum.Interceptor.obtain ().detach (listener);"
        new = "// Gum.Interceptor.obtain ().detach (listener);"
        count = replace_in_file(cloak, old, new)
        if count:
            log(f"  cloak.vala: disabled interceptor detach ({count})", "OK")

    log("Stability fixes complete", "OK")


# ============================================================================
# PHASE 3: Post-build patches (after first compilation)
# ============================================================================

def apply_post_build_patches(frida_dir: Path, custom_name: str):
    """Patch frida_agent_main symbol (generated during first build).

    Must include build/ directory because:
    - agent-glue.c (source) CALLS frida_agent_main
    - meson-generated_agent.c (build output) DEFINES frida_agent_main
    Both must be renamed together, otherwise linker error.
    """
    log("PHASE 3: Post-build patches (frida_agent_main)...", "STEP")
    count = replace_in_tree(frida_dir, "frida_agent_main", f"{custom_name}_agent_main",
                            include_build=True)
    log(f"  frida_agent_main -> {custom_name}_agent_main ({count})", "OK")


# ============================================================================
# PHASE 4: Binary-level patches (after second compilation)
# ============================================================================

def find_dex_regions(data: bytes) -> list[tuple[int, int]]:
    """Find embedded DEX sections in binary data by scanning for DEX magic.
    Returns list of (start, end) byte ranges to protect from modification."""
    regions = []
    dex_magics = [b'dex\n035\x00', b'dex\n037\x00', b'dex\n038\x00', b'dex\n039\x00']
    for magic in dex_magics:
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos == -1:
                break
            # Read header_size and file_size from DEX header
            if pos + 0x28 < len(data):
                file_size = struct.unpack_from('<I', data, pos + 0x20)[0]
                header_size = struct.unpack_from('<I', data, pos + 0x24)[0]
                # Valid DEX: header_size=112 (0x70), file_size > header_size
                if header_size == 112 and file_size > 112 and file_size < 10_000_000:
                    regions.append((pos, pos + file_size))
                    log(
                        f"    [dex] Protected DEX region: "
                        f"0x{pos:08x}-0x{pos + file_size:08x} ({file_size} bytes)",
                        "INFO",
                    )
            idx = pos + 8
    return regions


def replace_bytes_outside_regions(data: bytes, old: bytes, new: bytes,
                                   skip_regions: list[tuple[int, int]]) -> tuple[bytes, int]:
    """Replace byte pattern in data, skipping protected regions.
    Returns (modified_data, replacement_count)."""
    assert len(old) == len(new), "Replacement must be same length"
    result = bytearray(data)
    count = 0
    idx = 0
    while True:
        pos = data.find(old, idx)
        if pos == -1:
            break
        # Check if this position falls inside any protected region
        in_protected = any(start <= pos < end for start, end in skip_regions)
        if not in_protected:
            result[pos:pos + len(new)] = new
            count += 1
        idx = pos + 1
    return bytes(result), count


def apply_binary_patches(binary_path: Path, custom_name: str, extended: bool = False):
    """Apply hex-level patches to compiled binaries.
    DEX-aware: protects embedded DEX sections from string sweep corruption."""
    data = binary_path.read_bytes()
    original_size = len(data)
    patched = False

    # Find embedded DEX regions to protect
    dex_regions = find_dex_regions(data) if extended else []

    # Standard thread name patches (safe — these patterns don't appear in DEX)
    for old_hex, new_hex, description in get_binary_patches():
        old_bytes = bytes.fromhex(old_hex)
        new_bytes = bytes.fromhex(new_hex)
        if old_bytes in data:
            data = data.replace(old_bytes, new_bytes)
            log(f"    {description}", "OK")
            patched = True

    # Extended: sweep for residual "frida" strings in binary
    # MUST skip DEX regions to avoid corrupting embedded helper DEX
    if extended:
        for old_hex, new_hex, description in get_binary_string_patches(custom_name):
            old_bytes = bytes.fromhex(old_hex)
            new_bytes = bytes.fromhex(new_hex)
            if old_bytes in data:
                if dex_regions:
                    data, count = replace_bytes_outside_regions(
                        data, old_bytes, new_bytes, dex_regions
                    )
                else:
                    count = data.count(old_bytes)
                    data = data.replace(old_bytes, new_bytes)
                if count:
                    log(f"    [ext] {description} ({count}x, skipped DEX regions)", "OK")
                    patched = True

    if patched:
        assert len(data) == original_size, "Binary size changed — patches are not same-length!"
        binary_path.write_bytes(data)


# ============================================================================
# Build
# ============================================================================

def configure_arch(frida_dir: Path, arch: str, ndk_path: Path):
    log(f"Configuring for {arch}...", "STEP")
    run(
        ["./configure", f"--host={arch}"],
        cwd=frida_dir,
        env={"ANDROID_NDK_ROOT": str(ndk_path)},
    )


def build_frida(frida_dir: Path, ndk_path: Path):
    cpus = os.cpu_count() or 4
    log(f"Building ({cpus} threads)...", "STEP")
    run(
        ["make", f"-j{cpus}"],
        cwd=frida_dir,
        env={"ANDROID_NDK_ROOT": str(ndk_path)},
    )


# ============================================================================
# Collect artifacts
# ============================================================================

def collect_artifacts(
    frida_dir: Path,
    arch: str,
    custom_name: str,
    version: str,
    output_dir: Path,
    extended: bool,
) -> list[Path]:
    """Stage, verify, and promote mandatory build artifacts."""
    log(f"Collecting artifacts for {arch}...", "STEP")

    arch_short = arch.replace("android-", "")

    def find_artifact(subdir: str, patterns: list[str]) -> Path | None:
        base = frida_dir / "build" / "subprojects" / "frida-core" / subdir
        for pattern in patterns:
            candidate = base / pattern
            if candidate.is_file():
                return candidate
        # List directory for debugging
        if base.exists():
            log(f"    Looking in {base}:", "INFO")
            for f in sorted(base.iterdir()):
                if f.is_file() and f.stat().st_size > 1000:
                    log(f"      {f.name} ({f.stat().st_size:,} bytes)", "INFO")
        return None

    def save_artifact(src: Path, out_name: str, stage_dir: Path) -> list[Path]:
        out_bin = stage_dir / out_name
        shutil.copy2(src, out_bin)
        os.chmod(out_bin, 0o755)

        out_gz = stage_dir / f"{out_name}.gz"
        with out_bin.open("rb") as source, out_gz.open("wb") as raw_output:
            with gzip.GzipFile(
                filename=out_bin.name,
                mode="wb",
                fileobj=raw_output,
                mtime=0,
            ) as compressed:
                shutil.copyfileobj(source, compressed)
        log(
            f"    -> {out_gz.name} ({out_gz.stat().st_size / 1024 / 1024:.1f} MB)",
            "OK",
        )
        return [out_bin, out_gz]

    server = find_artifact(
        "server",
        [
            f"{custom_name}-server",
            f"{custom_name}-server-raw",
            "frida-server",
            "frida-server-raw",
        ],
    )
    if server is None:
        raise BuildError(f"Server artifact not found for {arch}")

    gadget = find_artifact(
        "lib/gadget",
        [
            f"lib{custom_name}-gadget.so",
            f"lib{custom_name}-gadget-modulated.so",
            "libfrida-gadget.so",
            "libfrida-gadget-modulated.so",
        ],
    )
    if gadget is None:
        raise BuildError(f"Gadget artifact not found for {arch}")

    agent = find_artifact(
        "lib/agent",
        [
            f"lib{custom_name}-agent.so",
            f"lib{custom_name}-agent-modulated.so",
            f"lib{custom_name}-agent-raw.so",
            "libfrida-agent.so",
            "libfrida-agent-modulated.so",
        ],
    )

    log(f"  Server: {server.name}", "OK")
    log(f"  Gadget: {gadget.name}", "OK")
    apply_binary_patches(server, custom_name, extended)
    apply_binary_patches(gadget, custom_name, extended)
    if agent is not None:
        log(f"  Agent: {agent.name}", "OK")
        apply_binary_patches(agent, custom_name, extended)

    output_dir.mkdir(parents=True, exist_ok=True)
    promoted: list[Path] = []
    with TemporaryDirectory(dir=output_dir, prefix=".staging-") as temporary:
        stage_dir = Path(temporary)
        staged = [
            *save_artifact(
                server,
                f"{custom_name}-server-{version}-android-{arch_short}",
                stage_dir,
            ),
            *save_artifact(
                gadget,
                f"{custom_name}-gadget-{version}-android-{arch_short}.so",
                stage_dir,
            ),
        ]

        for artifact in staged:
            if artifact.suffix != ".gz":
                verify_binary(artifact)

        for artifact in sorted(staged, key=lambda path: path.name):
            destination = output_dir / artifact.name
            os.replace(artifact, destination)
            promoted.append(destination)

    return promoted


# ============================================================================
# Verification
# ============================================================================

def scan_forbidden_markers(binary_path: Path) -> dict[str, int]:
    """Count runtime markers that indicate an invalid output artifact."""
    if not binary_path.is_file():
        raise BuildError(f"Binary artifact is missing: {binary_path}")
    data = binary_path.read_bytes()
    return {
        marker.decode("ascii", errors="backslashreplace"): data.count(marker)
        for marker in FORBIDDEN_BINARY_MARKERS
        if marker in data
    }


def verify_binary(binary_path: Path) -> None:
    """Reject compiled artifacts containing known forbidden runtime markers."""
    findings = scan_forbidden_markers(binary_path)
    if findings:
        details = ", ".join(
            f"{marker} x{count}" for marker, count in findings.items()
        )
        raise BuildError(f"Forbidden runtime markers in {binary_path.name}: {details}")
    log(f"  {binary_path.name}: forbidden-marker scan passed", "OK")


def git_revision(path: Path) -> str:
    """Return the exact Git revision for a repository or submodule."""
    result = run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True)
    revision = (result.stdout or "").strip()
    if not revision:
        raise BuildError(f"Could not resolve git revision for {path}")
    return revision


def create_build_info(
    *,
    builder_dir: Path,
    frida_dir: Path,
    name: str,
    port: int | None,
    version: str,
    architectures: list[str],
) -> dict[str, object]:
    """Create release provenance for the builder and upstream source revisions."""
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    workflow_url = (
        f"https://github.com/{repository}/actions/runs/{run_id}"
        if repository and run_id
        else None
    )
    return {
        "architectures": architectures,
        "builder_commit": git_revision(builder_dir),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "frida_commit": git_revision(frida_dir),
        "frida_core_commit": git_revision(frida_dir / "subprojects/frida-core"),
        "frida_version": version,
        "name": name,
        "ndk_version": NDK_VERSION,
        "port": port or 27042,
        "workflow_url": workflow_url,
    }


def write_release_assets(
    output_dir: Path,
    *,
    builder_dir: Path,
    frida_dir: Path,
    name: str,
    port: int | None,
    version: str,
    architectures: list[str],
) -> tuple[Path, Path]:
    """Write deterministic metadata JSON and checksums for release artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    info_path = output_dir / "build-info.json"
    sums_path = output_dir / "SHA256SUMS"
    info = create_build_info(
        builder_dir=builder_dir,
        frida_dir=frida_dir,
        name=name,
        port=port,
        version=version,
        architectures=architectures,
    )
    info_path.write_text(
        json.dumps(info, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    artifacts = sorted(
        path
        for path in output_dir.iterdir()
        if path.is_file() and path.name not in {info_path.name, sums_path.name}
    )
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in artifacts
    ]
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return info_path, sums_path


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Build custom anti-detection Frida server from source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build.py --version 17.7.2
  python3 build.py --version 17.7.2 --name stealth --port 27142
  python3 build.py --version 17.7.2 --arch android-arm64,android-arm --extended
  python3 build.py --version 17.7.2 --skip-build  # patch only, no compilation
  python3 build.py --version 17.7.2 --temp-fixes   # add stability patches

Detection vectors covered:
""" + DETECTION_VECTORS,
    )

    parser.add_argument("--version", "-v", required=True,
                        help="Frida version to build (e.g. 17.7.2)")
    parser.add_argument("--arch", "-a", default="android-arm64",
                        help=f"Comma-separated architectures. Options: {', '.join(ALL_ARCHS)}")
    parser.add_argument("--name", "-n", default="ajeossida",
                        help="Custom name replacing 'frida' everywhere (default: ajeossida)")
    parser.add_argument("--port", "-p", type=int, default=None,
                        help="Custom listening port (default: 27042 unchanged)")
    parser.add_argument(
        "--extended",
        "-e",
        action="store_true",
        help="Apply extended anti-detection (D-Bus interfaces, symbols, paths, binary sweep)",
    )
    parser.add_argument("--temp-fixes", action="store_true",
                        help="Apply stability fixes (perfetto skip, cloak detach)")
    parser.add_argument("--work-dir", "-w", default=None,
                        help="Working directory (default: ./build)")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Output directory (default: ./output)")
    parser.add_argument("--ndk-path", default=None,
                        help="Path to existing Android NDK r29 (skip download)")
    parser.add_argument("--skip-clone", action="store_true",
                        help="Use existing source in work-dir")
    parser.add_argument("--skip-build", action="store_true",
                        help="Only apply patches, don't compile")
    parser.add_argument("--verify", action="store_true",
                        help="After build, scan binaries for residual 'frida' strings")

    args = parser.parse_args()

    # Validate
    version = validate_version(args.version)
    frida_major = detect_frida_major(version)
    custom_name = validate_custom_name(args.name)
    archs = parse_architectures(args.arch)
    port = validate_port(args.port)

    # Directories
    script_dir = Path(__file__).parent.resolve()
    work_dir = Path(args.work_dir) if args.work_dir else script_dir / "build"
    output_dir = Path(args.output_dir) if args.output_dir else script_dir / "output"
    work_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Banner
    log("=" * 60, "HEADER")
    log("Custom Frida Builder", "HEADER")
    log("=" * 60, "HEADER")
    log(f"  Version:  Frida {version} (major: {frida_major})", "INFO")
    log(f"  Name:     '{custom_name}'", "INFO")
    log(f"  Archs:    {', '.join(archs)}", "INFO")
    log(f"  Port:     {port or '27042 (default)'}", "INFO")
    log(f"  Extended: {args.extended}", "INFO")
    log(f"  Work dir: {work_dir}", "INFO")
    log(f"  Output:   {output_dir}", "INFO")

    # Step 1: NDK
    if args.ndk_path:
        ndk_path = Path(args.ndk_path).resolve()
        if not ndk_path.exists():
            raise BuildError(f"NDK path does not exist: {ndk_path}")
    else:
        ndk_path = ensure_ndk(work_dir)
    log(f"  NDK:      {ndk_path}", "INFO")

    # Step 2: Clone
    frida_dir = work_dir / "frida"
    if not args.skip_clone:
        if frida_dir.exists():
            log("Removing existing frida dir...", "WARN")
            shutil.rmtree(frida_dir)
        frida_dir = clone_frida(version, work_dir)
    else:
        if not frida_dir.exists():
            raise BuildError("--skip-clone requires existing source in work-dir")
        log(f"Using existing source at {frida_dir}", "OK")

    # Step 3: Source patches
    apply_source_patches(frida_dir, custom_name)
    apply_targeted_patches(frida_dir, custom_name, frida_major)

    # Step 3.5: Extended patches
    if args.extended:
        apply_extended_patches(frida_dir, custom_name, port)
    elif port:
        apply_port_patches(frida_dir, port)

    # Step 4: Stability fixes
    if args.temp_fixes:
        apply_stability_fixes(frida_dir, frida_major)

    if args.skip_build:
        log("=" * 60, "HEADER")
        log("Patches applied. Build skipped (--skip-build).", "OK")
        log(f"Source ready at: {frida_dir}", "INFO")
        log("To build manually:", "INFO")
        log(f"  cd {frida_dir}", "INFO")
        log(f"  ANDROID_NDK_ROOT={ndk_path} ./configure --host=android-arm64", "INFO")
        log(f"  ANDROID_NDK_ROOT={ndk_path} make -j$(nproc)", "INFO")
        return

    # Step 5: Build loop
    for arch in archs:
        log("=" * 60, "HEADER")
        log(f"Building for {arch}", "STEP")
        log("=" * 60, "HEADER")

        # Configure
        configure_arch(frida_dir, arch, ndk_path)

        # First build
        log("First build...", "STEP")
        build_frida(frida_dir, ndk_path)

        # Post-build patches (frida_agent_main appears only after first build)
        apply_post_build_patches(frida_dir, custom_name)

        # Second build (incremental — only recompiles files with patched symbol)
        log("Second build (incremental)...", "STEP")
        build_frida(frida_dir, ndk_path)

        # Collect and binary-patch artifacts
        collect_artifacts(frida_dir, arch, custom_name, version, output_dir, args.extended)

    # Step 6: Verification
    if args.verify:
        log("=" * 60, "HEADER")
        log("Verification: scanning for residual 'frida' strings...", "STEP")
        for f in sorted(output_dir.iterdir()):
            if f.is_file() and not f.name.endswith(".gz"):
                verify_binary(f)

    write_release_assets(
        output_dir,
        builder_dir=script_dir,
        frida_dir=frida_dir,
        name=custom_name,
        port=port,
        version=version,
        architectures=archs,
    )

    # Done
    log("=" * 60, "HEADER")
    log("BUILD COMPLETE", "OK")
    log(f"Artifacts in: {output_dir}", "OK")
    for f in sorted(output_dir.iterdir()):
        size_mb = f.stat().st_size / (1024 * 1024)
        log(f"  {f.name} ({size_mb:.1f} MB)", "OK")

    # Usage hint
    log("", "INFO")
    log("To deploy:", "STEP")
    arch_short = archs[0].replace("android-", "")
    server_name = f"{custom_name}-server-{version}-android-{arch_short}"
    log(f"  adb push output/{server_name} /data/local/tmp/{custom_name}-server", "INFO")
    log(f"  adb shell chmod 755 /data/local/tmp/{custom_name}-server", "INFO")
    log(f"  adb shell /data/local/tmp/{custom_name}-server &", "INFO")
    if port:
        log(f"  frida -H 127.0.0.1:{port} -f <package>", "INFO")
    else:
        log("  frida -U -f <package>", "INFO")


if __name__ == "__main__":
    try:
        main()
    except BuildError as error:
        log(str(error), "ERROR")
        raise SystemExit(1) from error
