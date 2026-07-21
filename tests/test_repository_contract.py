from pathlib import Path


def test_community_and_security_files_exist() -> None:
    required = [
        "CONTRIBUTING.md",
        "SECURITY.md",
        "THIRD_PARTY_NOTICES.md",
        ".github/CODEOWNERS",
        ".github/pull_request_template.md",
        ".github/ISSUE_TEMPLATE/bug.yml",
        ".github/ISSUE_TEMPLATE/feature.yml",
        ".github/workflows/codeql.yml",
    ]
    assert all(Path(path).is_file() for path in required)


def test_readme_does_not_overclaim_protocol_or_version_support() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "all 16 detection vectors" not in readme.lower()
    assert "17.x | Fully verified" not in readme
    assert "D-Bus interfaces | Protocol inspection | - | Renamed" not in readme
    assert "Frida 17.16.3" in readme
    assert "Gadget" in readme
    assert "SHA256SUMS" in readme
    assert "android_smoke.py" in readme
    assert "3-20 characters" in readme
    assert "a reproducible arm64 build" not in readme.lower()
    assert "a verified pinned-input arm64 build" in readme.lower()


def test_codeql_is_pinned_and_has_minimal_permissions() -> None:
    codeql = Path(".github/workflows/codeql.yml").read_text(encoding="utf-8")
    sha = "e0647621c2984b5ed2f768cb892365bf2a616ad1"
    assert codeql.count(f"github/codeql-action/init@{sha}") == 1
    assert codeql.count(f"github/codeql-action/analyze@{sha}") == 1
    assert "contents: read" in codeql
    assert "security-events: write" in codeql
    assert "python" in codeql
    assert "javascript-typescript" in codeql


def test_codeowners_covers_security_sensitive_files() -> None:
    codeowners = Path(".github/CODEOWNERS").read_text(encoding="utf-8")
    for rule in (
        "* @TheQmaks",
        "/.github/workflows/ @TheQmaks",
        "/build.py @TheQmaks",
        "/patches.py @TheQmaks",
    ):
        assert rule in codeowners


def test_issue_form_collects_reproduction_environment() -> None:
    bug_form = Path(".github/ISSUE_TEMPLATE/bug.yml").read_text(encoding="utf-8")
    for field in (
        "frida-version",
        "artifact-source",
        "architecture",
        "android-version",
        "reproduction",
        "logs",
    ):
        assert f"id: {field}" in bug_form


def test_builder_help_and_defaults_use_the_documented_target() -> None:
    files = ("build.py", "patches.py", "build-wsl.sh")
    combined = "\n".join(Path(path).read_text(encoding="utf-8") for path in files)
    assert "17.7.2" not in combined
    assert "17.16.3" in combined
    assert "D-Bus interfaces, symbols" not in combined
