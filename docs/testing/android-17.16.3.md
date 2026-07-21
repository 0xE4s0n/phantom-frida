# Android acceptance: Frida 17.16.3

Tested on 2026-07-21 with artifacts built from builder commit
`98afaa4f9c9b9322d70d3858a17cabb6dab3668c`.

## Environment

| Component | Value |
|---|---|
| Device | Samsung SM-G955F |
| Android | LineageOS 21 (Android 14, API 34) |
| ABI | `arm64-v8a` |
| Root | MagiskSU 30.7 |
| Host client | Unmodified Frida Python bindings 17.16.3 |
| Android NDK | r29 (`29.0.14206865`) |
| Test package | `com.android.calculator2` |

The device serial, unrelated package list, and other personal device data were
not retained. The generated local JSON report also omits the serial and is
excluded from Git.

## Artifacts

| File | SHA-256 |
|---|---|
| `oemcodec-server-17.16.3-android-arm64` | `6ab48cda97ecf307c60b73dfaf7ca8a44146773664c3b0abe63493d2f5730bd9` |
| `oemcodec-server-17.16.3-android-arm64.gz` | `930121e6716e9fadc5e3da7820b816787885c9594bda6a74fe7ddf98409ff9bf` |
| `oemcodec-gadget-17.16.3-android-arm64.so` | `def6423cdbfa22c6deb01e0f1e4f9ed532f96f498a403623d46670ff3b4fd4fa` |
| `oemcodec-gadget-17.16.3-android-arm64.so.gz` | `66efc35d0e70160989d88c58c55f97c5b74bd71bc61a45b2a897c971712e608e` |

`SHA256SUMS` independently verified all four files before the device run. The
uncompressed server and Gadget were identified as AArch64 ELF artifacts.

## Command

The acceptance harness was run from the repository root with exactly one
authorized device attached:

```powershell
.venv\Scripts\python.exe scripts\android_smoke.py `
  --server output\oemcodec-server-17.16.3-android-arm64 `
  --gadget output\oemcodec-gadget-17.16.3-android-arm64.so `
  --name oemcodec `
  --port 27142 `
  --package com.android.calculator2 `
  --ndk <path-to-android-ndk-r29> `
  --report android-smoke-report.json
```

The harness compiled `tests/android/gadget-loader.c` for
`aarch64-linux-android34`, generated the matching Gadget configuration, and
used port 27143 for the isolated Gadget check.

## Results

| Check | Result | Evidence |
|---|---|---|
| Root precondition | PASS | `su -c id` returned UID 0. |
| Stock client to Server | PASS | Frida 17.16.3 enumerated 124 processes. |
| Spawn, attach, and resume | PASS | The calculator process completed the scripted lifecycle. |
| Java bridge and hook installation | PASS | `Java.available` was true and the structured agent reported no failures. |
| `/proc` maps, file descriptors, and thread names | PASS | No forbidden `frida-server`, `frida-helper`, or `frida-zymbiote` marker was found. |
| Zymbiote socket rename | PASS | A rooted live scan found the custom `oemcodec-zymbiote` socket and no `frida-zymbiote` socket. |
| Stock client to Gadget | PASS | The separately loaded Gadget accepted Frida 17.16.3 and enumerated its process. |
| Cleanup | PASS | No test process, ADB forward, or tested socket marker remained after exit. |

Redacted structured result:

```json
{
  "frida_version": "17.16.3",
  "gadget": {
    "abi": "arm64-v8a",
    "api_level": 34,
    "process_count": 1
  },
  "server": {
    "java_available": true,
    "script_failures": []
  },
  "status": "passed"
}
```

## Scope boundary

This run proves the Server and Gadget paths on physical Android 14 hardware.
It also exercises the corrected JNI lookup path without reproducing the
`backend_class != null` assertion. It is not, by itself, an Android 15 device
test; Android 15 should remain a separately stated compatibility target until
it is exercised on matching hardware or an equivalent rooted test image.
