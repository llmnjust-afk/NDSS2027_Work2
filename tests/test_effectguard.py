import json
from typing import Annotated

import pytest
from pydantic import BaseModel, Field

from agentdojo.effectguard import (
    EffectDeniedError,
    EffectGuardRuntime,
    GuardMode,
    JsonlEventSink,
    ToolEffectSpec,
    canonicalize_email,
)
from agentdojo.functions_runtime import Depends, FunctionCall, TaskEnvironment


class MailState(BaseModel):
    sent: list[str] = Field(default_factory=list)


class MailEnv(TaskEnvironment):
    mail: MailState = Field(default_factory=MailState)


def mail_runtime(mode: GuardMode = GuardMode.EFFECTGUARD, **kwargs) -> EffectGuardRuntime:
    runtime = EffectGuardRuntime(mode=mode, principal="alice", session="session-1", clock=lambda: 100.0, **kwargs)
    runtime.register_effect_tool(
        "send_mail", ToolEffectSpec(operation="send", target_arg="recipient", credential_scope=("mail.send",))
    )
    runtime.register_canonicalizer("send_mail", "recipient", canonicalize_email)

    @runtime.register_function
    def send_mail(mail: Annotated[MailState, Depends("mail")], recipient: str, body: str) -> str:
        """Send one email.

        :param recipient: Destination address
        :param body: Message body
        """
        mail.sent.append(recipient)
        return recipient

    return runtime


def authorize_mail(runtime: EffectGuardRuntime, recipient: str = "a@example.com", **metadata):
    return runtime.register_initial_effect(
        "send_mail", {"recipient": recipient, "body": "hello"}, expiry=200.0, **metadata
    )


def test_benign_normalization_is_allowed():
    runtime = mail_runtime()
    requested = authorize_mail(runtime, "  A@Example.COM ")
    runtime.register_final_effect(
        requested.nonce,
        "send_mail",
        {"recipient": "a@example.com", "body": "hello"},
        expiry=200.0,
        transformation="normalize_email",
    )
    env = MailEnv()

    result, error = runtime.run_function(env, "send_mail", {"recipient": "a@example.com", "body": "hello"})

    assert error is None
    assert result == "a@example.com"
    assert env.mail.sent == ["a@example.com"]


def test_redirect_denied_by_effectguard_but_missed_by_call_boundary():
    guarded = mail_runtime()
    requested = authorize_mail(guarded)
    guarded.register_final_effect(
        requested.nonce,
        "send_mail",
        {"recipient": "attacker@example.com", "body": "hello"},
        expiry=200.0,
        transformation="redirect",
    )
    guarded_env = MailEnv()

    _, error = guarded.run_function(guarded_env, "send_mail", {"recipient": "attacker@example.com", "body": "hello"})

    assert error == "EffectDeniedError: immutable field changed: target"
    assert guarded_env.mail.sent == []

    boundary = mail_runtime(GuardMode.CALL_BOUNDARY)
    requested = authorize_mail(boundary)
    boundary.register_final_effect(
        requested.nonce,
        "send_mail",
        {"recipient": "attacker@example.com", "body": "hello"},
        expiry=200.0,
        transformation="redirect",
    )
    boundary_env = MailEnv()

    _, error = boundary.run_function(boundary_env, "send_mail", {"recipient": "attacker@example.com", "body": "hello"})

    assert error is None
    assert boundary_env.mail.sent == ["attacker@example.com"]


def test_one_to_many_transformation_is_denied_by_cardinality():
    runtime = mail_runtime()
    requested = authorize_mail(runtime, cardinality=1)
    runtime.register_final_effect(
        requested.nonce,
        "send_mail",
        {"recipient": "a@example.com", "body": "hello"},
        cardinality=2,
        expiry=200.0,
        transformation="fan_out",
    )
    env = MailEnv()

    _, error = runtime.run_function(env, "send_mail", {"recipient": "a@example.com", "body": "hello"})

    assert error == "EffectDeniedError: cardinality widened"
    assert env.mail.sent == []


@pytest.mark.parametrize(
    ("metadata", "reason"),
    [
        ({"expiry": 99.0}, "authorization expired"),
        ({"expiry": 200.0, "provenance": ("untrusted_tool",)}, "required provenance missing"),
    ],
)
def test_stale_and_untrusted_provenance_are_denied(metadata, reason):
    runtime = mail_runtime()
    requested = authorize_mail(runtime)
    runtime.register_final_effect(
        requested.nonce,
        "send_mail",
        {"recipient": "a@example.com", "body": "hello"},
        transformation="final",
        **metadata,
    )

    _, error = runtime.run_function(MailEnv(), "send_mail", {"recipient": "a@example.com", "body": "hello"})

    assert error == f"EffectDeniedError: {reason}"


def test_nested_calls_are_intercepted_at_run_function_boundary():
    runtime = mail_runtime()

    @runtime.register_function
    def identity(value: str) -> str:
        """Return a value.

        :param value: Value to return
        """
        return value

    nested = FunctionCall(function="send_mail", args={"recipient": "attacker@example.com", "body": "hello"})
    outer = runtime.register_initial_effect("identity", {"value": nested}, expiry=200.0)
    runtime.register_final_effect(outer.nonce, "identity", {"value": nested}, expiry=200.0)
    env = MailEnv()

    _, error = runtime.run_function(env, "identity", {"value": nested})

    assert error == "EffectDeniedError: missing authorization"
    assert env.mail.sent == []


def test_direct_runtime_call_is_intercepted_and_can_raise():
    runtime = mail_runtime()
    env = MailEnv()

    with pytest.raises(EffectDeniedError, match="missing authorization"):
        runtime.run_function(
            env, "send_mail", {"recipient": "attacker@example.com", "body": "hello"}, raise_on_error=True
        )

    assert env.mail.sent == []


def test_jsonl_events_are_appended(tmp_path):
    path = tmp_path / "guard.jsonl"
    runtime = mail_runtime(event_sink=JsonlEventSink(path))
    requested = authorize_mail(runtime)
    runtime.register_final_effect(
        requested.nonce,
        "send_mail",
        {"recipient": "a@example.com", "body": "hello"},
        expiry=200.0,
    )
    runtime.run_function(MailEnv(), "send_mail", {"recipient": "a@example.com", "body": "hello"})
    runtime.run_function(MailEnv(), "send_mail", {"recipient": "other@example.com", "body": "hello"})

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [record["sequence"] for record in records] == [1, 2]
    assert [record["decision"] for record in records] == ["allow", "deny"]
