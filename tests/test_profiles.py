from __future__ import annotations

import pytest

from finality_ref.profiles import PROFILES


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_has_positive_latency_target(profile):
    assert profile.latency_target_us > 0


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_defines_deployment_boundary(profile):
    assert profile.deployment_boundary and profile.sink_kind and profile.state_backend


def test_profiles_cover_sub_ms_to_tens_of_ms():
    values = [p.latency_target_us for p in PROFILES]
    assert min(values) <= 100
    assert any(v < 1000 for v in values)
    assert any(v >= 10_000 for v in values)
    assert max(values) >= 50_000
