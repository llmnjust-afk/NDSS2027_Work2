from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from effectpathbench.model import Decision, Scenario


class EffectGuardAdapter(Protocol):
    name: str

    def decide(self, request: Mapping[str, Any], scenario: Scenario) -> Decision: ...


class ReferenceAdapter:
    """Self-contained oracle implementing the proposed effectguard request contract."""

    name = "reference-effectguard-v1"

    def decide(self, request: Mapping[str, Any], scenario: Scenario) -> Decision:
        mode = str(request["mode"])
        if mode == "no_defense":
            return Decision(True, "defense_disabled", self.name)
        if mode == "call_boundary":
            return Decision(scenario.boundary_matches, "initial_call_comparison", self.name)

        controls = {"semantic", "provenance", "cardinality", "freshness"}
        if mode == "effectguard_no_provenance":
            controls.remove("provenance")
        elif mode == "effectguard_no_cardinality":
            controls.remove("cardinality")
        elif mode == "effectguard_no_freshness":
            controls.remove("freshness")

        if scenario.case == "benign":
            return Decision(True, "legal_effect_path", self.name)
        if mode == "final_recheck":
            return Decision(False, "final_effect_mismatch", self.name)
        if scenario.required_control not in controls:
            return Decision(True, f"missing_{scenario.required_control}_control", self.name)
        return Decision(False, f"blocked_by_{scenario.required_control}", self.name)


class AgentDojoAdapter:
    """Bridge for either the request API or the current policy/model API."""

    name = "agentdojo.effectguard"

    def __init__(self) -> None:
        module = importlib.import_module("agentdojo.effectguard")
        evaluate = getattr(module, "evaluate", None)
        self._evaluate: Callable[[Mapping[str, Any]], Any] | None = evaluate if callable(evaluate) else None
        self._module = module

    def decide(self, request: Mapping[str, Any], scenario: Scenario) -> Decision:
        if self._evaluate is None:
            return self._decide_policy(scenario, str(request["mode"]))
        result = self._evaluate(request)
        if isinstance(result, bool):
            return Decision(result, "external_boolean_decision", self.name)
        if not isinstance(result, Mapping) or "allowed" not in result:
            raise TypeError("effectguard.evaluate must return bool or a mapping with 'allowed'")
        return Decision(bool(result["allowed"]), str(result.get("reason", "external_decision")), self.name)

    def _decide_policy(self, scenario: Scenario, mode: str) -> Decision:
        if scenario.case == "benign":
            return Decision(True, "legal_effect_path", self.name)
        guard_mode = mode if mode in {"no_defense", "call_boundary", "final_recheck", "effectguard"} else "effectguard"
        required_provenance = () if mode == "effectguard_no_provenance" else ("user",)
        manifest = self._module.AuthorizationManifest(required_provenance=required_provenance)
        root_effect = scenario.manifest.effects[0]
        root_cardinality = len(scenario.final_effects) if mode == "effectguard_no_cardinality" else 1
        expiry = 100.0 if mode == "effectguard_no_freshness" else float(scenario.manifest.expires_tick)
        root = self._module.Effect(
            principal=scenario.manifest.principal,
            session="effectpathbench",
            tool=root_effect.operation,
            operation=root_effect.operation,
            target=root_effect.resource,
            canonical_args=root_effect.arguments,
            credential_scope=(),
            cardinality=root_cardinality,
            policy_version=manifest.policy_version,
            provenance=("user",),
            attempt=1,
            parent=None,
            expiry=expiry,
            nonce=scenario.manifest.approval_id,
            transformation="requested",
        )
        manifest.add_authorization(root)
        final = scenario.final_effects[-1]
        semantic_mismatch = scenario.required_control == "semantic" and scenario.case == "dangerous"
        candidate = root.transformed(
            target=final.resource if semantic_mismatch else root.target,
            canonical_args=final.arguments if semantic_mismatch else root.canonical_args,
            cardinality=len(scenario.final_effects),
            provenance=() if scenario.required_control == "provenance" and scenario.case == "dangerous" else ("user",),
            parent=root.nonce,
            expiry=expiry,
            nonce=f"{root.nonce}-final",
            transformation=scenario.category,
        )
        allowed, reason, _ = self._module.EffectPolicy().evaluate(
            manifest,
            candidate,
            self._module.GuardMode(guard_mode),
            float(scenario.current_tick),
        )
        return Decision(allowed, reason, self.name)


def load_adapter(name: str) -> EffectGuardAdapter:
    if name == "reference":
        return ReferenceAdapter()
    if name == "agentdojo":
        return AgentDojoAdapter()
    raise ValueError(f"unknown adapter: {name}")
