from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EffectSurface:
    name: str
    channel: str
    externally_effective: bool
    sink_mediated: bool
    enforcement_boundary: str
    privileged: bool


@dataclass(frozen=True)
class SurfaceFinding:
    severity: str
    surface: str
    reason: str


class DeploymentManifest:
    """Static deployment self-audit for wide-channel bypass exposure.

    It does not prove topology. It makes the completeness assumption explicit and
    machine-testable in deployment manifests: every externally effective path must
    be sink-mediated at a privileged/protected boundary.
    """

    def __init__(self, surfaces: list[EffectSurface] | tuple[EffectSurface, ...]):
        self.surfaces = tuple(surfaces)

    def audit(self) -> tuple[SurfaceFinding, ...]:
        findings: list[SurfaceFinding] = []
        seen: set[tuple[str, str]] = set()
        for s in self.surfaces:
            key = (s.name, s.channel)
            if key in seen:
                findings.append(SurfaceFinding("MEDIUM", s.name, "duplicate_surface_definition"))
            seen.add(key)
            if not s.externally_effective:
                continue
            if not s.sink_mediated:
                findings.append(SurfaceFinding("CRITICAL", s.name, "unguarded_external_effect_path"))
            if not s.privileged:
                findings.append(SurfaceFinding("HIGH", s.name, "sink_boundary_not_privileged"))
            if not s.enforcement_boundary.strip():
                findings.append(SurfaceFinding("HIGH", s.name, "missing_enforcement_boundary"))
        return tuple(findings)

    def assert_complete(self) -> None:
        critical = [f for f in self.audit() if f.severity in {"CRITICAL", "HIGH"}]
        if critical:
            joined = "; ".join(f"{f.surface}:{f.reason}" for f in critical)
            raise RuntimeError(f"deployment finality coverage incomplete: {joined}")
