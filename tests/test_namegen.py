from datetime import datetime, timezone

from namegen import weekly_seed


def test_weekly_seed_uses_iso_year_at_new_year_boundary() -> None:
    now = datetime(2021, 1, 1, tzinfo=timezone.utc)
    assert weekly_seed(now) == "2020-W53"


def test_weekly_seed_zero_pads_week_number() -> None:
    now = datetime(2026, 1, 5, tzinfo=timezone.utc)
    assert weekly_seed(now) == "2026-W02"
