# phantom-frida

`phantom-frida` builds Android Frida Server and Gadget from source while
changing a targeted set of observable runtime identifiers. It is a builder and
verification harness, not a promise that every application-specific detection
method is defeated.

The current compatibility target is **Frida 17.16.3** on Android. Other Frida
versions are intentionally treated as unverified until their source contracts,
full build, and rooted-device acceptance have been repeated.

Use this project only on applications and devices you own or are authorized to
test.

## What is verified

The repository separates three kinds of evidence:

1. Unit and fixture tests validate input handling, exact Frida 17.16.3 source
   patch contracts, DEX rebuilding, artifact promotion, metadata, workflows,
   and failure behavior.
2. `build.py --verify` requires both Server and Gadget, then rejects known
   forbidden runtime markers before publishing either artifact.
3. `scripts/android_smoke.py` exercises a built artifact on one rooted device:
   stock-client enumeration, spawn, attach, Java bridge assertions, `/proc`
   scans, and a separately loaded Gadget.

A passing source test or byte scan is not equivalent to runtime stealth. Claims
about Android behavior should include the generated, redacted smoke-test report.

## Build with GitHub Actions

Run **Build Custom Frida** from the Actions tab. The reusable build workflow:

- validates every user-controlled build input;
- downloads Android NDK r29 from Google and checks its published checksum;
- clones a fresh upstream source tree instead of caching patched source;
- uploads only after the hard artifact and marker gates pass;
- includes `build-info.json` and `SHA256SUMS` in one build artifact.

The weekly workflow resolves the latest release through the authenticated
GitHub API, calls the same read-only build workflow, verifies the downloaded
artifact, attests it, and grants release write permission only to the final job.

## Local build

Requirements:

- Ubuntu 22.04 or newer (WSL is supported);
- Python 3.10 or newer;
- Git, curl, unzip, a C/C++ toolchain, JDK 17, and Node.js 18 or newer
  (CI uses Node.js 24.13.1);
- Android SDK platform and build-tools containing `android.jar` and D8;
- about 20 GB of free disk space.

If `--ndk-path` is omitted, the builder downloads Android NDK r29 under
`build/`. A reproducible arm64 build is:

```bash
export ANDROID_SDK_ROOT=/path/to/Android/Sdk
python3 build.py \
  --version 17.16.3 \
  --name oemcodec \
  --arch android-arm64 \
  --port 27142 \
  --extended \
  --verify
```

Useful options:

```text
--version, -v    Exact Frida semantic version (required)
--name, -n       Lowercase replacement name, 3-32 characters
--arch, -a       One or more supported Android architectures
--port, -p       Listening port; omitted keeps 27042
--extended, -e   Apply the optional extended identifier transformations
--temp-fixes     Apply opt-in, device-specific stability changes
--verify         Reject known forbidden markers in final artifacts
--skip-build     Patch source without compiling
--skip-clone     Use an existing source tree in the work directory
--ndk-path       Use an existing Android NDK r29 directory
```

## Outputs and provenance

For the example above, `output/` contains:

```text
oemcodec-server-17.16.3-android-arm64
oemcodec-server-17.16.3-android-arm64.gz
oemcodec-gadget-17.16.3-android-arm64.so
oemcodec-gadget-17.16.3-android-arm64.so.gz
build-info.json
SHA256SUMS
```

`build-info.json` records the exact builder, Frida, and frida-core commits, NDK
version, UTC build time, architectures, name, port, and workflow URL when built
in Actions. Verify downloaded binary files before use:

```bash
cd output
sha256sum --check SHA256SUMS
python3 -m json.tool build-info.json >/dev/null
```

Public weekly releases also receive a GitHub build-provenance attestation.

## Stock-client compatibility

The builder preserves the D-Bus protocol interfaces under `re.frida.*`, the
`/re/frida/GadgetSession` path, public capital `Frida` JavaScript API strings,
and generated C ABI symbols required by stock clients. Renaming those values
would break the normal Frida client/server contract.

The D-Bus service identifier, helper JNI package, zymbiote socket prefix,
selected process/library/path identifiers, selected thread names, and an
optional custom port are separate implementation details that the builder can
transform. The output verifier rejects this explicit marker set:

```text
frida\0
frida-zymbiote
re/frida/HelperBackend
frida-server
frida-helper
```

Capital `Frida` and allowlisted protocol strings are not verifier failures.

## Rooted Android acceptance

Install the exact Python binding recorded in `build-info.json`, install the
pinned Java bridge dependency, and connect exactly one rooted Android device:

```bash
python3 -m pip install "frida==17.16.3" frida-tools
npm ci --ignore-scripts

python3 scripts/android_smoke.py \
  --server output/oemcodec-server-17.16.3-android-arm64 \
  --gadget output/oemcodec-gadget-17.16.3-android-arm64.so \
  --name oemcodec \
  --port 27142 \
  --package com.example.app \
  --ndk build/android-ndk-r29 \
  --report android-smoke-report.json
```

The package must be an installed Java application you are authorized to test.
The harness compiles `test_comprehensive.js` with the explicit
`frida-java-bridge` required by Frida 17, starts Server through a forwarded TCP
port, then compiles a minimal native loader and exercises Gadget on a separate
port. It cleans up its processes and forwards on exit.

Frida Gadget configuration must be named next to the library as
`lib<name>-gadget.config.so`; the harness generates and deploys this file.

## Development checks

```bash
python -m pip install --requirement requirements-dev.txt
npm ci --ignore-scripts
python -m pytest
ruff check .
ruff format --check .
mypy build.py patches.py namegen.py scripts
node --check test_comprehensive.js
bash -n build-wsl.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full evidence requirements.

## Repository layout

```text
build.py                 Clone, patch, compile, verify, and collect artifacts
patches.py               Source and same-length binary transformations
namegen.py               Seeded build-name and port generation
scripts/android_smoke.py Rooted Android Server/Gadget acceptance harness
test_comprehensive.js    Structured Frida 17 Java bridge assertions
tests/                   Unit, contract, fixture, and workflow tests
.github/workflows/       CI, CodeQL, reusable build, and release isolation
```

## Known boundaries

- Only Frida 17.16.3 is the current verification target; support is not inferred
  for all 17.x or 16.x releases.
- `--temp-fixes` changes runtime behavior and remains opt-in.
- Marker absence does not prove resistance to behavioral, integrity, timing, or
  application-specific detection.
- Frida 17 raw agents need explicit bridge imports or bundling. The harness uses
  `frida.Compiler`; the Frida REPL and tracer provide their own bundled bridges.

## Credits and licensing

- [Frida](https://frida.re/) by Ole André Ravnas and contributors
- [ajeossida](https://github.com/hackcatml/ajeossida) by hackcatml

The builder code is MIT licensed. Generated binaries retain upstream licensing;
see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
