## Summary

Describe the problem and the smallest change that solves it.

## Verification

List the exact commands run and their results. Attach a redacted
`android-smoke-report.json` when making Android runtime or stealth claims.

## Checklist

- [ ] I added or updated a regression test before changing behavior.
- [ ] `pytest`, Ruff, mypy, JavaScript, shell, and actionlint checks pass.
- [ ] A full Frida 17.16.3 build passes if source patches or build logic changed.
- [ ] Rooted-device evidence is included if runtime compatibility or detection changed.
- [ ] Documentation and third-party provenance remain accurate.
- [ ] No generated binaries, downloaded SDK/NDK files, secrets, or device identifiers are committed.
