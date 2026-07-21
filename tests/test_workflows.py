import re
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")
WORKFLOWS = list(WORKFLOW_DIR.glob("*.yml"))
SHA_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def workflow_text(name: str) -> str:
    return (WORKFLOW_DIR / name).read_text(encoding="utf-8")


def run_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if not re.match(r"^\s+run:\s*[|>]\s*$", line):
            continue
        indentation = len(line) - len(line.lstrip())
        block: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indentation:
                break
            block.append(candidate)
        blocks.append("\n".join(block))
    return blocks


def test_every_external_action_is_pinned_to_a_full_sha() -> None:
    for workflow in WORKFLOWS:
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if not line.strip().startswith("uses:"):
                continue
            reference = line.split("uses:", 1)[1].strip().split(" #", 1)[0]
            assert reference.startswith("./") or SHA_REF.fullmatch(reference), (
                workflow,
                reference,
            )


def test_workflows_do_not_execute_expression_generated_commands() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in WORKFLOWS)
    for workflow in WORKFLOWS:
        assert all(
            "${{" not in block for block in run_blocks(workflow.read_text(encoding="utf-8"))
        ), workflow
    assert "run: ${{" not in combined
    assert "curl -s https://api.github.com/repos/frida/frida/releases/latest" not in combined
    assert "if-no-files-found: warn" not in combined
    assert "if-no-files-found: ignore" not in combined


def test_checkout_does_not_persist_repository_credentials() -> None:
    for workflow in WORKFLOWS:
        text = workflow.read_text(encoding="utf-8")
        if "actions/checkout@" in text:
            assert "persist-credentials: false" in text, workflow


def test_fast_ci_has_expected_quality_gate() -> None:
    text = workflow_text("ci.yml")
    assert "name: CI" in text
    assert "name: quality" in text
    assert "permissions:\n  contents: read" in text
    for command in (
        "pytest",
        "ruff check",
        "mypy",
        "node --check",
        "bash -n",
        "actionlint",
    ):
        assert command in text


def test_reusable_build_is_read_only_and_fails_on_missing_artifacts() -> None:
    text = workflow_text("build.yml")
    assert "workflow_call:" in text
    assert "permissions:\n  contents: read" in text
    assert "persist-credentials: false" in text
    assert "if-no-files-found: error" in text
    assert "build/frida" not in text.split("actions/cache@", 1)[-1]


def test_scheduled_build_separates_read_build_from_write_release() -> None:
    text = workflow_text("scheduled-build.yml")
    assert "permissions:\n  contents: read" in text
    assert "resolve:" in text
    assert "build:" in text
    assert "release:" in text
    assert "contents: write" in text
    assert "attestations: write" in text
    assert "id-token: write" in text
    assert "actions/attest-build-provenance@" in text


def test_scheduled_release_is_pinned_to_the_device_verified_version() -> None:
    text = workflow_text("scheduled-build.yml")
    assert "inputs.frida_version || '17.16.3'" in text
    assert 'if [[ "$version" != "17.16.3" ]]' in text
    assert "releases/latest" not in text


def test_release_publishes_every_file_covered_by_sha256sums() -> None:
    text = workflow_text("scheduled-build.yml")
    release_command = text.split('gh release create "$tag"', 1)[1]
    assert "release-assets/*" in release_command
    assert "release-assets/*.gz" not in release_command


def test_release_targets_repository_without_requiring_checkout() -> None:
    text = workflow_text("scheduled-build.yml")
    release_job = text.split("  release:", 1)[1]
    assert "GH_REPO: ${{ github.repository }}" in release_job


def test_dependabot_updates_pinned_actions_weekly() -> None:
    text = Path(".github/dependabot.yml").read_text(encoding="utf-8")
    assert "package-ecosystem: github-actions" in text
    assert "interval: weekly" in text
