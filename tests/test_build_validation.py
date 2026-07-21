import pytest

import build


@pytest.mark.parametrize("value", ["17.16.3;id", "main", "17.16", "v17.16.3"])
def test_validate_version_rejects_non_release_tags(value: str) -> None:
    with pytest.raises(build.BuildError):
        build.validate_version(value)


@pytest.mark.parametrize("value", ["a", "two-words", "9daemon", "name;id", "a" * 21])
def test_validate_custom_name_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(build.BuildError):
        build.validate_custom_name(value)


def test_validate_custom_name_normalizes_case() -> None:
    assert build.validate_custom_name("OemCodec") == "oemcodec"


def test_validate_custom_name_accepts_zymbiote_field_boundary() -> None:
    assert build.validate_custom_name("a" * 20) == "a" * 20


@pytest.mark.parametrize("value", [0, -1, 65536])
def test_validate_port_rejects_values_outside_tcp_range(value: int) -> None:
    with pytest.raises(build.BuildError):
        build.validate_port(value)


def test_validate_port_accepts_default_and_boundaries() -> None:
    assert build.validate_port(None) is None
    assert build.validate_port(1) == 1
    assert build.validate_port(65535) == 65535


def test_parse_architectures_preserves_requested_order() -> None:
    assert build.parse_architectures("android-arm64, android-arm") == [
        "android-arm64",
        "android-arm",
    ]


@pytest.mark.parametrize("value", ["", "android-arm64,", "linux-x86_64"])
def test_parse_architectures_rejects_empty_or_unknown_values(value: str) -> None:
    with pytest.raises(build.BuildError):
        build.parse_architectures(value)
