from __future__ import annotations

import pytest

from finality_ref.surface import DeploymentManifest, EffectSurface


CHANNELS = [
    "network-egress", "storage-write", "renderer", "message-queue", "process-spawn",
    "actuator", "payment-ledger", "model-output", "dma-memory-release", "webhook",
    "email-send", "sms-send", "radio-transmit", "ledger-bridge", "file-export",
    "clipboard", "print-spool", "socket-egress", "shared-memory-release", "device-command",
]

@pytest.mark.parametrize("channel", CHANNELS)
def test_any_unguarded_external_channel_is_critical(channel):
    m = DeploymentManifest([
        EffectSurface(channel, channel, True, False, "host", True)
    ])
    findings = m.audit()
    assert any(f.severity == "CRITICAL" and f.reason == "unguarded_external_effect_path" for f in findings)
    with pytest.raises(RuntimeError):
        m.assert_complete()


@pytest.mark.parametrize("channel", CHANNELS)
def test_guarded_privileged_channel_passes_static_coverage_audit(channel):
    m = DeploymentManifest([
        EffectSurface(channel, channel, True, True, "privileged-finality-boundary", True)
    ])
    assert not m.audit()
    m.assert_complete()


@pytest.mark.parametrize("privileged,boundary,expected", [
    (False, "userspace", "sink_boundary_not_privileged"),
    (True, "", "missing_enforcement_boundary"),
    (False, "", "sink_boundary_not_privileged"),
])
def test_sink_deployment_boundary_must_be_real(privileged, boundary, expected):
    m = DeploymentManifest([EffectSurface("egress", "network-egress", True, True, boundary, privileged)])
    assert any(f.reason == expected for f in m.audit())
