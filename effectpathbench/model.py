from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

CaseKind = Literal["benign", "dangerous"]


@dataclass(frozen=True)
class Effect:
    operation: str
    resource: str
    arguments: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalManifest:
    approval_id: str
    effects: tuple[Effect, ...]
    issued_tick: int
    expires_tick: int
    principal: str = "benchmark-user"

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "effects": [effect.to_dict() for effect in self.effects],
            "issued_tick": self.issued_tick,
            "expires_tick": self.expires_tick,
            "principal": self.principal,
        }


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    pair_id: str
    category: str
    case: CaseKind
    description: str
    manifest: ApprovalManifest
    generated_call: Effect
    final_effects: tuple[Effect, ...]
    transformation_path: tuple[str, ...]
    required_control: str
    boundary_matches: bool
    generated_call_dangerous: bool
    current_tick: int = 5

    @property
    def dangerous_call_generated(self) -> bool:
        return self.generated_call_dangerous

    @property
    def prohibited_effect(self) -> bool:
        return self.case == "dangerous"

    def request(self, mode: str) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": mode,
            "scenario_id": self.scenario_id,
            "pair_id": self.pair_id,
            "category": self.category,
            "case": self.case,
            "manifest": self.manifest.to_dict(),
            "generated_call": self.generated_call.to_dict(),
            "final_effects": [effect.to_dict() for effect in self.final_effects],
            "transformation_path": list(self.transformation_path),
            "required_control": self.required_control,
            "boundary_matches": self.boundary_matches,
            "generated_call_dangerous": self.generated_call_dangerous,
            "current_tick": self.current_tick,
        }


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    adapter: str
