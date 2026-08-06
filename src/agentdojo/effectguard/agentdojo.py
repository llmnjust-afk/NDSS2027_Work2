from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from agentdojo.functions_runtime import Function, FunctionCall

from .models import GuardMode, ToolEffectSpec
from .runtime import EffectGuardRuntime

_READ_PREFIXES = ("get_", "read_", "search_", "list_", "check_")
_READ_TOOLS: set[str] = set()
_TARGET_ARGS = (
    "recipients",
    "recipient",
    "channel",
    "file_id",
    "email_id",
    "event_id",
    "id",
    "user",
    "url",
    "hotel",
    "restaurant",
    "car_rental_company",
)


def is_effectful_tool(name: str) -> bool:
    return not name.startswith(_READ_PREFIXES) and name not in _READ_TOOLS


def _target_arg(args: dict) -> str | None:
    return next((name for name in _TARGET_ARGS if name in args), None)


def build_authorized_runtime(
    functions: Sequence[Function],
    authorizations: Sequence[FunctionCall],
    *,
    mode: GuardMode | str,
) -> EffectGuardRuntime:
    runtime = EffectGuardRuntime(functions, mode=mode, session="agentdojo-task")
    effectful = [call for call in authorizations if is_effectful_tool(call.function)]
    target_args: dict[str, str | None] = {}
    for call in effectful:
        target_args.setdefault(call.function, _target_arg(dict(call.args)))
    for function in functions:
        if is_effectful_tool(function.name):
            runtime.register_effect_tool(
                function.name,
                ToolEffectSpec(operation=function.name, target_arg=target_args.get(function.name)),
            )

    cardinalities = Counter((call.function, repr(dict(call.args))) for call in effectful)
    registered: set[tuple[str, str]] = set()
    for call in effectful:
        key = (call.function, repr(dict(call.args)))
        if key not in registered:
            runtime.register_initial_effect(
                call.function,
                call.args,
                cardinality=cardinalities[key],
            )
            registered.add(key)
    return runtime
