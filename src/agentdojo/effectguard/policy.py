from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .models import AuthorizationManifest, Effect, GuardMode


class EffectDeniedError(PermissionError):
    pass


def _is_narrowing(requested: Any, actual: Any) -> bool:
    if isinstance(requested, int) and isinstance(actual, int):
        return actual <= requested
    if isinstance(requested, Mapping) and isinstance(actual, Mapping):
        return all(key in requested and _is_narrowing(requested[key], value) for key, value in actual.items())
    if isinstance(requested, Sequence) and isinstance(actual, Sequence) and not isinstance(requested, str):
        return all(item in requested for item in actual)
    return requested == actual


def _matches_authorization(requested: Any, actual: Any) -> bool:
    if isinstance(requested, str) and requested.startswith("<") and requested.endswith(">"):
        return True
    if isinstance(requested, Mapping) and isinstance(actual, Mapping):
        if not all(key in actual and _matches_authorization(value, actual[key]) for key, value in requested.items()):
            return False
        return all(key in requested or value in (None, "", [], {}) for key, value in actual.items())
    if isinstance(requested, Sequence) and isinstance(actual, Sequence) and not isinstance(requested, str):
        return len(requested) == len(actual) and all(
            _matches_authorization(expected, observed) for expected, observed in zip(requested, actual)
        )
    return requested == actual


class EffectPolicy:
    def evaluate(
        self, manifest: AuthorizationManifest, candidate: Effect, mode: GuardMode, now: float
    ) -> tuple[bool, str, Effect | None]:
        if mode is GuardMode.NO_DEFENSE:
            return True, "defense disabled", None

        try:
            root = manifest.root(candidate)
        except (KeyError, ValueError):
            return False, "invalid lineage", None
        if root.nonce not in manifest.authorizations:
            return False, "missing authorization", None

        if mode is GuardMode.CALL_BOUNDARY:
            if root.tool == candidate.tool and root.operation == candidate.operation:
                return True, "call boundary authorized", root
            return False, "tool or operation not authorized", root

        for name in ("principal", "session", "tool", "operation", "target", "credential_scope", "policy_version"):
            if getattr(root, name) != getattr(candidate, name):
                return False, f"immutable field changed: {name}", root
        if not _matches_authorization(root.canonical_args, candidate.canonical_args):
            return False, "arguments are not authorized by the canonical template", root

        if mode is GuardMode.FINAL_RECHECK:
            return True, "final effect equivalent", root

        if candidate.expiry < now or root.expiry < now:
            return False, "authorization expired", root
        if candidate.attempt < root.attempt:
            return False, "attempt regressed", root
        if not set(manifest.required_provenance).issubset(candidate.provenance):
            return False, "required provenance missing", root
        if not _is_narrowing(root.cardinality, candidate.cardinality):
            return False, "cardinality widened", root
        if manifest.consumed.get(root.nonce, 0) + candidate.cardinality > root.cardinality:
            return False, "authorization cardinality exhausted", root
        return True, "effect authorized", root
