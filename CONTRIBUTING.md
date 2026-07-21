# Contributing

Keep changes focused, reproducible, and tied to an observable failure. Builder
changes should preserve stock Frida client compatibility unless a proposal
explicitly changes that contract.

## Local setup

Use Python 3.12, Node.js, Go, and Bash. Install the pinned development and
JavaScript dependencies:

```bash
python -m pip install --requirement requirements-dev.txt
npm ci --ignore-scripts
```

## Fast verification

Run the same checks as pull-request CI:

```bash
python -m pytest --cov=build --cov=patches --cov=namegen \
  --cov=scripts.android_smoke --cov-report=term-missing
ruff check .
ruff format --check .
mypy build.py patches.py namegen.py scripts
node --check test_comprehensive.js
bash -n build-wsl.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

For a bug fix, first add a test that reproduces the failure, confirm it fails,
then make the smallest implementation change that makes it pass.

## Frida integration changes

Changes to `build.py` or `patches.py` also require a clean, full build of the
documented target:

```bash
python3 build.py --version 17.16.3 --name oemcodec \
  --arch android-arm64 --port 27142 --extended --verify
```

Record the exact builder and upstream commits from `output/build-info.json`.
Do not commit the downloaded `build/` tree or generated `output/` binaries.

## Android runtime evidence

Claims about spawning, attaching, Java bridge behavior, Gadget loading, process
artifacts, or detection resistance require the rooted-device harness. Run it
against an application and device you are authorized to test:

```bash
python3 scripts/android_smoke.py \
  --server output/oemcodec-server-17.16.3-android-arm64 \
  --gadget output/oemcodec-gadget-17.16.3-android-arm64.so \
  --name oemcodec --port 27142 --package com.example.app \
  --ndk build/android-ndk-r29 \
  --report android-smoke-report.json
```

The harness requires exactly one rooted Android device. Redact the serial,
package-specific data, and other identifiers before attaching a report to a
public issue or pull request.

## Pull requests

Explain the root cause, link the regression test, list exact verification
commands, and identify any unsupported cases. Generated artifacts, credentials,
and unredacted device logs must not be committed.
