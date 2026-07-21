"""
Patch definitions for Custom Frida Builder.

Compatibility target: Frida 17.16.3 source code.
Extended beyond ajeossida with additional anti-detection techniques.

Patch categories:
  [A] Ajeossida-compatible  — proven patches from hackcatml's approach
  [E] Extended               — new techniques not in ajeossida
  [V] Version-specific       — differs between Frida 16.x and 17.x

Source verification notes (17.16.3):
  - g_set_prgname("frida") does NOT exist — removed
  - frida-gadget-tcp/unix do NOT exist — removed
  - memfd_create is in lib/base/linux.vala, NOT frida-helper-backend.vala
  - SELinux labels are in linjector.vala, NOT frida-helper-backend.vala
  - cloak.vala uses GOT slot patching, NOT Gum.Interceptor
  - gumprocess-linux.c uses entry->name, NOT details.name
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RequiredFilePatch:
    """A source contract whose absence must stop the build."""

    relative_path: str
    old: str
    new: str
    minimum: int = 1


def get_required_file_patches(name: str) -> list[RequiredFilePatch]:
    """Return exact Frida source patches required for Android runtime correctness."""
    linux_host_session = "subprojects/frida-core/src/linux/linux-host-session.vala"
    return [
        RequiredFilePatch(
            linux_host_session,
            "re/frida/HelperBackend",
            f"re/{name}/HelperBackend",
        ),
        RequiredFilePatch(
            linux_host_session,
            '"/frida-zymbiote-',
            f'"/{name}-zymbiote-',
            minimum=2,
        ),
        RequiredFilePatch(
            "subprojects/frida-core/src/linux/helpers/zymbiote.c",
            '"/frida-zymbiote-',
            f'"/{name}-zymbiote-',
        ),
        RequiredFilePatch(
            "subprojects/frida-core/lib/payload/exit-monitor.vala",
            (
                """\t\tconstruct {
\t\t\tvar interceptor = Gum.Interceptor.obtain ();

\t\t\tunowned Gum.InvocationListener listener = this;

#if WINDOWS
\t\t\tinterceptor.attach ((void *) """
                """Gum.Process.find_module_by_name (\"kernel32.dll\")."""
                """find_export_by_name (\"ExitProcess\"),
\t\t\t\tlistener);
#else
\t\t\tvar libc = Gum.Process.get_libc_module ();
\t\t\tconst string[] apis = {
\t\t\t\t\"exit\",
\t\t\t\t\"_exit\",
\t\t\t\t\"abort\",
\t\t\t};
\t\t\tforeach (var symbol in apis) {
\t\t\t\tinterceptor.attach ((void *) libc.find_export_by_name (symbol), listener);
\t\t\t}
#endif
\t\t}"""
            ),
            """\t\tconstruct {
\t\t\t// Exit interception intentionally disabled.
\t\t}""",
        ),
        RequiredFilePatch(
            "subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c",
            """    gum_interceptor_replace (interceptor, gum_original_signal,
        gum_exceptor_backend_replacement_signal, NULL, &options);
    gum_interceptor_replace (interceptor, gum_original_sigaction,
        gum_exceptor_backend_replacement_sigaction, NULL, &options);""",
            "    (void) options; /* Signal interception intentionally disabled. */",
        ),
    ]


# ============================================================================
# [A] GLOBAL SOURCE PATCHES — recursive string replace across entire tree
# ============================================================================


def get_source_patches(name: str, cap_name: str) -> list[tuple[str, str]]:
    """
    Global string replacements applied recursively across the Frida source tree.
    Order matters — more specific patterns before general ones to avoid double-patching.
    """
    return [
        # --- Agent library name (visible in /proc/pid/maps) ---
        ("libfrida-agent-raw.so", f"lib{name}-agent-raw.so"),
        ("libfrida-agent-modulated", f"lib{name}-agent-modulated"),
        # --- Android helper Java class (DEX embedded in server binary) ---
        # Must rename to prevent binary sweep from corrupting DEX, and to hide
        # the "re.frida.helper" process name which is a detection vector.
        # Order: most specific first
        ("re.frida.Helper", f"re.{name}.Helper"),
        ("re.frida.helper", f"re.{name}.helper"),
        ("re.frida.Gadget", f"re.{name}.Gadget"),
        ("package re.frida;", f"package re.{name};"),
        # --- D-Bus / service identifier ---
        ("re.frida.server", f"re.{name}.server"),
        # --- Helper binaries (spawned during injection) ---
        # More specific first, then bare form for compat system
        ("frida-helper-32", f"{name}-helper-32"),
        ("frida-helper-64", f"{name}-helper-64"),
        ("get_frida_helper_", f"get_{name}_helper_"),
        ("frida-helper", f"{name}-helper"),
        ('"/frida-"', f'"/{name}-"'),
        # --- Agent references (various quoting styles in Vala/C/Meson) ---
        # More specific first to avoid partial matches
        ('"agent" / "frida-agent.', f'"agent" / "{name}-agent.'),
        ("'frida-agent'", f"'{name}-agent'"),
        ('"frida-agent"', f'"{name}-agent"'),
        ("frida-agent-", f"{name}-agent-"),
        ("get_frida_agent_", f"get_{name}_agent_"),
        ("'FridaAgent'", f"'{cap_name}Agent'"),
        ('"FridaAgent"', f'"{cap_name}Agent"'),
        # --- JS engine thread name (visible in /proc/pid/task/tid/status) ---
        ('"gum-js-loop"', f'"{name}-js-loop"'),
        # --- [E] Extended: asset directory name ---
        ("/ 'frida'", f"/ '{name}'"),  # root_asset_dir = libdir / 'frida'
    ]


def get_rollback_patches(name: str) -> list[tuple[str, str]]:
    """
    Undo accidental renames of build system filenames.
    The global replace catches these, but they're filenames, not runtime artifacts.
    """
    return [
        # Build system files that should keep "frida-agent-" prefix
        (f"{name}-agent-x86.symbols", "frida-agent-x86.symbols"),
        (f"{name}-agent-android.version", "frida-agent-android.version"),
        (f"{name}-agent.version", "frida-agent.version"),
        (f"{name}-agent.symbols", "frida-agent.symbols"),
        # Gadget build files
        (f"{name}-gadget.symbols", "frida-gadget.symbols"),
        (f"{name}-gadget.version", "frida-gadget.version"),
        (f"{name}-gadget.def", "frida-gadget.def"),
        (f"{name}-gadget.plist", "frida-gadget.plist"),
        # Helper build files
        (f"{name}-helper.symbols", "frida-helper.symbols"),
        (f"{name}-helper.version", "frida-helper.version"),
        (f"{name}-helper-linux.version", "frida-helper-linux.version"),
        (f"{name}-helper.plist", "frida-helper.plist"),
        (f"{name}-helper.xcent", "frida-helper.xcent"),
        # Server build files
        (f"{name}-server.symbols", "frida-server.symbols"),
        (f"{name}-server.version", "frida-server.version"),
        (f"{name}-server.plist", "frida-server.plist"),
        (f"{name}-server.xcent", "frida-server.xcent"),
    ]


# ============================================================================
# [A] TARGETED FILE PATCHES — specific build system files
# ============================================================================


def get_targeted_patches(name: str, cap_name: str, target: str) -> list[tuple[str, str]]:
    """
    Patches for specific build system files.
    Verified against Frida 17.16.3 meson.build files.
    """
    if target == "server_meson":
        # subprojects/frida-core/server/meson.build
        return [
            ("'frida-server-raw'", f"'{name}-server-raw'"),
            ("'frida-server'", f"'{name}-server'"),
            ('"frida-server"', f'"{name}-server"'),
            ("'frida-server-universal'", f"'{name}-server-universal'"),
            # 17.16.3: server_name variable
            ("server_name = 'frida-server'", f"server_name = '{name}-server'"),
        ]

    elif target == "compat_build":
        # subprojects/frida-core/compat/build.py
        # 17.16.3 uses constants: SERVER_TARGET, GADGET_TARGET, and Path references
        return [
            ('SERVER_TARGET = "frida-server"', f'SERVER_TARGET = "{name}-server"'),
            ('Path("server") / "frida-server"', f'Path("server") / "{name}-server"'),
            ('GADGET_TARGET = "frida-gadget"', f'GADGET_TARGET = "{name}-gadget"'),
            ('"frida-gadget.dll"', f'"{name}-gadget.dll"'),
            ('"frida-gadget.dylib"', f'"{name}-gadget.dylib"'),
            ('"frida-gadget.so"', f'"{name}-gadget.so"'),
            # Cross-arch naming
            ('"frida-server-"', f'"{name}-server-"'),
            ('"frida-gadget-"', f'"{name}-gadget-"'),
        ]

    elif target == "core_meson":
        # subprojects/frida-core/meson.build
        # 17.16.3: defines helper_name, agent_name, gadget_name
        return [
            ("helper_name = 'frida-helper'", f"helper_name = '{name}-helper'"),
            ("agent_name = 'frida-agent'", f"agent_name = '{name}-agent'"),
            ("gadget_name = 'frida-gadget'", f"gadget_name = '{name}-gadget'"),
            ("'FRIDA_HELPER_PATH'", f"'{name.upper()}_HELPER_PATH'"),
            ("'FRIDA_AGENT_PATH'", f"'{name.upper()}_AGENT_PATH'"),
            # Asset directory
            ("get_option('libdir') / 'frida'", f"get_option('libdir') / '{name}'"),
            # Gadget modulated (17.16.3 has this only in gadget meson)
            ('"frida-gadget"', f'"{name}-gadget"'),
            ("frida-gadget-modulated", f"{name}-gadget-modulated"),
            ("libfrida-gadget-modulated", f"lib{name}-gadget-modulated"),
        ]

    elif target == "gadget_meson":
        # subprojects/frida-core/lib/gadget/meson.build
        # Verified exact lines from 17.16.3
        # NOTE: do NOT rename vala_header — it's a build-time artifact,
        # and C glue files #include it by the original name
        return [
            ("'frida-gadget-raw'", f"'{name}-gadget-raw'"),
            ("'frida-gadget'", f"'{name}-gadget'"),
            ("'frida-gadget-modulated'", f"'{name}-gadget-modulated'"),
            ("'frida-gadget-universal'", f"'{name}-gadget-universal'"),
            ("'FridaGadget.dylib'", f"'{cap_name}Gadget.dylib'"),
        ]

    elif target == "agent_meson":
        # subprojects/frida-core/lib/agent/meson.build
        # NOTE: do NOT rename vala_header — C glue files #include it by name
        # NOTE: do NOT rename _frida_agent_main here — it's generated by Vala
        # from the namespace. The post-build phase renames both definition and
        # export together after the first compilation.
        return [
            ("'frida-agent-raw'", f"'{name}-agent-raw'"),
            ("'frida-agent'", f"'{name}-agent'"),
            ("'frida-agent-modulated'", f"'{name}-agent-modulated'"),
            ("'frida-agent-universal'", f"'{name}-agent-universal'"),
        ]

    return []


# ============================================================================
# [V] VERSION-SPECIFIC PATCHES — differ between Frida 16.x and 17.x
# ============================================================================

MEMFD_PATCHES = {
    # Frida 16.x: memfd_create in frida-helper-backend.vala
    16: {
        "file": "src/linux/frida-helper-backend.vala",
        "old": "return Linux.syscall (SysCall.memfd_create, name, flags);",
        "new": 'return Linux.syscall (SysCall.memfd_create, "jit-cache", flags);',
    },
    # Frida 17.x: memfd_create moved to lib/base/linux.vala
    # Verified: exact function signature and enum name
    17: {
        "file": "lib/base/linux.vala",
        "old": "return Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags);",
        "new": 'return Linux.syscall (LinuxSyscall.MEMFD_CREATE, "jit-cache", flags);',
    },
}


# ============================================================================
# [A] SELINUX LABEL PATCHES
# ============================================================================


def SELINUX_PATCHES(name: str) -> list[tuple[str, str]]:
    """
    SELinux security context labels.
    Verified in 17.16.3: located in src/linux/linjector.vala
    Three occurrences: adjust_directory_permissions, adjust_file_permissions, adjust_fd_permissions
    """
    return [
        # Context strings in code
        ('"frida_file"', f'"{name}_file"'),
        ('"frida_memfd"', f'"{name}_memfd"'),
        # Context in SELinux policy references (colon-prefixed)
        (":frida_file", f":{name}_file"),
        (":frida_memfd", f":{name}_memfd"),
    ]


# ============================================================================
# [A] BINARY-LEVEL HEX PATCHES — post-compilation thread name changes
# ============================================================================


def get_binary_patches() -> list[tuple[str, str, str]]:
    """
    Hex-level byte replacements for compiled binaries.
    Changes GLib/GDBus internal thread names visible in /proc/pid/task/tid/status.
    All patches MUST be same-length to avoid corrupting the binary.
    """
    return [
        # gmain -> amain (GLib main loop thread)
        ("676d61696e00", "616d61696e00", "gmain\\0 -> amain\\0"),
        # gdbus -> gdbug (GDBus thread)
        ("676462757300", "676462756700", "gdbus\\0 -> gdbug\\0"),
        # pool-spawner -> pool-spoiler (GLib thread pool spawner)
        (
            "706f6f6c2d737061776e657200",
            "706f6f6c2d73706f696c657200",
            "pool-spawner\\0 -> pool-spoiler\\0",
        ),
    ]


# ============================================================================
# [E] EXTENDED: DEFAULT PORT PATCH — change Frida's default port 27042
# ============================================================================


def get_port_patches(new_port: int = 27142) -> list[dict]:
    """
    Change Frida's default listening port from 27042.

    Detection: many apps scan localhost:27042 to detect Frida.
    Port 27042 = 0x69A2, appears as little-endian 0xA269 in binaries.

    Args:
        new_port: New port number (default 27142, must be same byte-length)
    """
    return [
        # Source-level: constant definition
        {
            "type": "source",
            "pattern": "27042",
            "replacement": str(new_port),
            "files": [
                "subprojects/frida-core/lib/interfaces/session.vala",
                "subprojects/frida-core/src/droidy/droidy-client.vala",
                "subprojects/frida-core/server/server.vala",
            ],
            "description": f"Default port 27042 -> {new_port}",
        },
    ]


# ============================================================================
# [E] EXTENDED: BINARY STRING SWEEP — remove residual "frida" strings
# ============================================================================


def get_binary_string_patches(name: str) -> list[tuple[str, str, str]]:
    """
    Residual "frida" string sweep in compiled binaries.

    After source-level patching and compilation, some "frida" strings may remain
    (from static initializers, third-party code, or compiler-generated data).

    This does a careful sweep: replace null-terminated "frida\0" with same-length
    innocuous strings. Only applied when --extended is set.
    """
    # "frida\0" (5 chars + null = 6 bytes) -> "libgc\0" (looks like GC lib reference)
    # Same length, won't corrupt binary
    return [
        ("667269646100", "6c6962676300", 'residual "frida\\0" -> "libgc\\0"'),
        # NOTE: "Frida\0" (capital F) is NOT patched here.
        # The JS runtime defines `Frida` as a global API object (Frida.version, etc.)
        # embedded in the compiled binary. Replacing "Frida\0" corrupts the JS engine
        # and causes: ReferenceError: Frida is not defined (core.js:134)
        # See: https://github.com/TheQmaks/phantom-frida/issues/1
        #
        # "FRIDA\0" -> "XBNDL\0"
        ("465249444100", "58424e444c00", 'residual "FRIDA\\0" -> "XBNDL\\0"'),
    ]


# ============================================================================
# [E] EXTENDED: TEMP FILE PATH PATCHES — runtime file paths
# ============================================================================


def get_temp_path_patches(name: str) -> list[tuple[str, str]]:
    """
    Patch temp file/directory paths used by Frida at runtime.
    These paths appear in /proc/pid/fd and /tmp listings.
    """
    return [
        # Temp directory prefix
        ('".frida"', f'".{name}"'),
        ('"frida-"', f'"{name}-"'),
        # Socket/pipe paths
        ('"frida_server"', f'"{name}_server"'),
    ]


# ============================================================================
# [E] EXTENDED: INTERNAL IDENTIFIER PATCHES
# ============================================================================


def get_internal_patches(name: str, cap_name: str) -> list[tuple[str, str]]:
    """
    Patch internal identifiers that could be found via memory scanning.
    Apps sometimes scan process memory for these strings.

    NOTE: Do NOT rename frida_init, frida_deinit, frida_version, frida_version_string here.
    These C symbols are generated by the Vala compiler from the 'Frida' namespace
    (e.g. Frida.version_string() -> frida_version_string() in C). Renaming the definition
    without renaming the Vala namespace causes linker errors (undefined symbol).
    The binary string sweep (--extended) handles any residual 'frida' in the final binary.
    """
    return [
        # GType names visible through GObject introspection; these literals are safe to rename.
        ("FridaServer", f"{cap_name}Server"),
        ("FridaGadget", f"{cap_name}Gadget"),
        ("FridaPortal", f"{cap_name}Portal"),
        ("FridaInject", f"{cap_name}Inject"),
    ]


# ============================================================================
# [E] EXTENDED: STABILITY / CRASH FIXES
# ============================================================================


def get_stability_patches_17(frida_dir: Path) -> list[dict]:
    """
    Optional stability fixes for Frida 17.x.
    Apply only if needed (device-specific issues).
    """
    return [
        {
            "description": (
                "Skip perfetto_hprof_ thread during enumeration (prevents SEGV on some devices)"
            ),
            "file": "subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c",
            # Verified 17.16.3: variable is entry->name, NOT details.name
            "old": "    carry_on = func (entry, user_data);",
            "new": (
                '    if (entry->name != NULL && strcmp (entry->name, "perfetto_hprof_") == 0)\n'
                "        goto skip;\n"
                "    carry_on = func (entry, user_data);"
            ),
        },
    ]


# ============================================================================
# SUMMARY - transformations and verification boundaries
# ============================================================================

DETECTION_VECTORS = """
Build transformations:

[required source and artifact contracts]
 - Server, helper, Gadget, agent, JNI package, and zymbiote socket identifiers
 - Selected thread and memfd names, SELinux labels, and D-Bus service identifier
 - frida_agent_main generated symbol, patched in both caller and definition

[optional with --extended]
 - Configured listening port, selected GType names, and temporary path prefixes
 - Same-length residual byte replacements outside protected DEX regions

[hard output gate]
 - Rejects the explicit FORBIDDEN_BINARY_MARKERS set in Server and Gadget

Compatibility identifiers intentionally preserved:
 - D-Bus protocol interfaces under re.frida.* and /re/frida/GadgetSession
 - Public capital Frida API names and generated C ABI symbols required by stock clients
 - Allowlisted protocol strings; verification does not claim every substring is removed

Runtime compatibility and observation claims require scripts/android_smoke.py evidence.
"""
