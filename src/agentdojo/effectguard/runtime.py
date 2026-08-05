from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from agentdojo.functions_runtime import (
    Function,
    FunctionCallArgTypes,
    FunctionReturnType,
    FunctionsRuntime,
    TaskEnvironment,
)

from .canonicalization import CanonicalizerRegistry
from .events import EventSink, GuardEvent, NullEventSink
from .models import AuthorizationManifest, Effect, GuardMode, ToolEffectSpec
from .policy import EffectDeniedError, EffectPolicy, _matches_authorization


class EffectGuardRuntime(FunctionsRuntime):
    """Functions runtime enforcing authorization at the common execution boundary."""

    def __init__(
        self,
        functions: Sequence[Function] = (),
        *,
        mode: GuardMode | str = GuardMode.EFFECTGUARD,
        manifest: AuthorizationManifest | None = None,
        principal: str = "user",
        session: str = "default",
        provenance: tuple[str, ...] = ("user",),
        event_sink: EventSink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(functions)
        self.mode = GuardMode(mode)
        self.manifest = manifest or AuthorizationManifest()
        self.principal = principal
        self.session = session
        self.provenance = provenance
        self.event_sink = event_sink or NullEventSink()
        self.clock = clock
        self.canonicalizers = CanonicalizerRegistry()
        self.tool_specs: dict[str, ToolEffectSpec] = {}
        self._sequence = 0
        self._nonce = 0
        self._pending: dict[str, list[Effect]] = {}
        self.policy = EffectPolicy()

    def register_effect_tool(self, tool: str, spec: ToolEffectSpec) -> None:
        self.tool_specs[tool] = spec

    def register_canonicalizer(self, tool: str, field: str, canonicalizer: Callable[[Any], Any]) -> None:
        self.canonicalizers.register(tool, field, canonicalizer)

    def _next_nonce(self) -> str:
        self._nonce += 1
        return f"effect-{self._nonce}"

    def _effect(
        self,
        tool: str,
        args: Mapping[str, Any],
        *,
        operation: str | None = None,
        target: str | None = None,
        credential_scope: tuple[str, ...] | None = None,
        cardinality: int = 1,
        provenance: tuple[str, ...] | None = None,
        attempt: int = 1,
        parent: str | None = None,
        expiry: float | None = None,
        nonce: str | None = None,
        transformation: str = "requested",
    ) -> Effect:
        spec = self.tool_specs.get(tool, ToolEffectSpec())
        canonical_args = self.canonicalizers.args(tool, args)
        target_value = target
        if target_value is None and spec.target_arg is not None:
            target_value = self.canonicalizers.target(tool, spec.target_arg, args.get(spec.target_arg, ""))
        return Effect(
            principal=self.principal,
            session=self.session,
            tool=tool,
            operation=operation or spec.operation or tool,
            target=target_value or "",
            canonical_args=canonical_args,
            credential_scope=credential_scope if credential_scope is not None else spec.credential_scope,
            cardinality=cardinality,
            policy_version=self.manifest.policy_version,
            provenance=provenance if provenance is not None else self.provenance,
            attempt=attempt,
            parent=parent,
            expiry=expiry if expiry is not None else self.clock() + 300,
            nonce=nonce or self._next_nonce(),
            transformation=transformation,
        )

    def register_initial_effect(self, tool: str, args: Mapping[str, Any], **metadata: Any) -> Effect:
        effect = self._effect(tool, args, **metadata)
        return self.manifest.add_authorization(effect)

    def register_final_effect(
        self, parent: str, tool: str, args: Mapping[str, Any], *, transformation: str = "final", **metadata: Any
    ) -> Effect:
        effect = self._effect(tool, args, parent=parent, transformation=transformation, **metadata)
        self.manifest.add_transformation(effect)
        self._pending.setdefault(tool, []).append(effect)
        return effect

    def _candidate(self, function: str, kwargs: Mapping[str, FunctionCallArgTypes]) -> Effect:
        pending = self._pending.get(function, [])
        if pending:
            registered = pending.pop(0)
            spec = self.tool_specs.get(function, ToolEffectSpec())
            actual = self._effect(
                function,
                kwargs,
                operation=registered.operation,
                target=registered.target if spec.target_arg is None else None,
                credential_scope=registered.credential_scope,
                cardinality=registered.cardinality,
                provenance=registered.provenance,
                attempt=registered.attempt,
                parent=registered.parent,
                expiry=registered.expiry,
                nonce=registered.nonce,
                transformation=registered.transformation,
            )
            return actual

        matches = [effect for effect in self.manifest.authorizations.values() if effect.tool == function]
        available = [
            effect
            for effect in matches
            if self.manifest.consumed.get(effect.nonce, 0) < effect.cardinality
        ]
        equivalent = [effect for effect in available if _matches_authorization(effect.canonical_args, kwargs)]
        selected = equivalent[0] if equivalent else (available[0] if self.mode is GuardMode.CALL_BOUNDARY and available else None)
        return self._effect(
            function,
            kwargs,
            parent=selected.nonce if selected is not None else None,
            transformation="direct",
        )

    def _record(self, decision: str, reason: str, candidate: Effect) -> None:
        self._sequence += 1
        self.event_sink.append(
            GuardEvent(
                sequence=self._sequence,
                decision=decision,
                reason=reason,
                mode=self.mode.value,
                tool=candidate.tool,
                nonce=candidate.nonce,
                parent=candidate.parent,
                attempt=candidate.attempt,
            )
        )

    def run_function(
        self,
        env: TaskEnvironment | None,
        function: str,
        kwargs: Mapping[str, FunctionCallArgTypes],
        raise_on_error: bool = False,
    ) -> tuple[FunctionReturnType, str | None]:
        if function not in self.tool_specs:
            return super().run_function(env, function, kwargs, raise_on_error)
        candidate = self._candidate(function, kwargs)
        allowed, reason, root = self.policy.evaluate(self.manifest, candidate, self.mode, self.clock())
        self._record("allow" if allowed else "deny", reason, candidate)
        if not allowed:
            error = EffectDeniedError(reason)
            if raise_on_error:
                raise error
            return "", f"EffectDeniedError: {reason}"
        result, error = super().run_function(env, function, kwargs, raise_on_error)
        if error is None and self.mode is GuardMode.EFFECTGUARD and root is not None:
            self.manifest.consumed[root.nonce] = self.manifest.consumed.get(root.nonce, 0) + candidate.cardinality
        return result, error
