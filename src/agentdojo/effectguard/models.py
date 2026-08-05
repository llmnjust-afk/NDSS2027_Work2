from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any


class GuardMode(str, Enum):
    NO_DEFENSE = "no_defense"
    CALL_BOUNDARY = "call_boundary"
    FINAL_RECHECK = "final_recheck"
    EFFECTGUARD = "effectguard"


@dataclass(frozen=True)
class FieldSemantics:
    immutable: frozenset[str] = frozenset(
        {"principal", "session", "tool", "operation", "target", "credential_scope", "policy_version"}
    )
    equivalent: frozenset[str] = frozenset({"canonical_args"})
    narrowing: frozenset[str] = frozenset({"cardinality"})

    def __post_init__(self) -> None:
        groups = (self.immutable, self.equivalent, self.narrowing)
        if any(left & right for index, left in enumerate(groups) for right in groups[index + 1 :]):
            raise ValueError("Effect fields must have exactly one comparison semantics")


@dataclass(frozen=True)
class Effect:
    principal: str
    session: str
    tool: str
    operation: str
    target: str
    canonical_args: Mapping[str, Any]
    credential_scope: tuple[str, ...]
    cardinality: int
    policy_version: str
    provenance: tuple[str, ...]
    attempt: int
    parent: str | None
    expiry: float
    nonce: str
    transformation: str

    def __post_init__(self) -> None:
        if self.cardinality < 1:
            raise ValueError("cardinality must be positive")
        object.__setattr__(self, "canonical_args", MappingProxyType(dict(self.canonical_args)))
        object.__setattr__(self, "credential_scope", tuple(self.credential_scope))
        object.__setattr__(self, "provenance", tuple(self.provenance))

    def transformed(self, **changes: Any) -> Effect:
        return replace(self, **changes)


@dataclass
class AuthorizationManifest:
    policy_version: str = "1"
    semantics: FieldSemantics = field(default_factory=FieldSemantics)
    required_provenance: tuple[str, ...] = ("user",)
    authorizations: dict[str, Effect] = field(default_factory=dict)
    transformations: dict[str, Effect] = field(default_factory=dict)
    consumed: dict[str, int] = field(default_factory=dict)

    def add_authorization(self, effect: Effect) -> Effect:
        if effect.nonce in self.authorizations or effect.nonce in self.transformations:
            raise ValueError(f"Duplicate effect nonce: {effect.nonce}")
        self.authorizations[effect.nonce] = effect
        return effect

    def add_transformation(self, effect: Effect) -> Effect:
        if effect.parent not in self.authorizations and effect.parent not in self.transformations:
            raise ValueError(f"Unknown parent nonce: {effect.parent}")
        if effect.nonce in self.authorizations or effect.nonce in self.transformations:
            raise ValueError(f"Duplicate effect nonce: {effect.nonce}")
        self.transformations[effect.nonce] = effect
        return effect

    def root(self, effect: Effect) -> Effect:
        current = effect
        seen: set[str] = set()
        while current.parent is not None:
            if current.nonce in seen:
                raise ValueError("Effect lineage contains a cycle")
            seen.add(current.nonce)
            current = self.authorizations.get(current.parent) or self.transformations[current.parent]
        return current


@dataclass(frozen=True)
class ToolEffectSpec:
    operation: str | None = None
    target_arg: str | None = None
    credential_scope: tuple[str, ...] = ()
