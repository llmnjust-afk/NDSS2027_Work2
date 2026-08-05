from agentdojo.effectguard.agentdojo import build_authorized_runtime
from agentdojo.functions_runtime import FunctionCall, make_function


@make_function
def read_value() -> str:
    """Reads a value."""
    return "value"


@make_function
def send_message(recipient: str, body: str) -> str:
    """Sends a message.

    :param recipient: Recipient.
    :param body: Message body.
    """
    return f"{recipient}:{body}"


def test_reads_pass_without_authorization() -> None:
    runtime = build_authorized_runtime([read_value, send_message], [], mode="effectguard")
    result, error = runtime.run_function(None, "read_value", {})
    assert result == "value"
    assert error is None


def test_dynamic_template_preserves_target() -> None:
    authorization = FunctionCall(function="send_message", args={"recipient": "alice", "body": "<summary>"})
    runtime = build_authorized_runtime([send_message], [authorization], mode="effectguard")
    result, error = runtime.run_function(None, "send_message", {"recipient": "alice", "body": "summary text"})
    assert result == "alice:summary text"
    assert error is None
    _, error = runtime.run_function(None, "send_message", {"recipient": "mallory", "body": "summary text"})
    assert error is not None


def test_final_recheck_rejects_unauthorized_arguments() -> None:
    authorization = FunctionCall(function="send_message", args={"recipient": "alice", "body": "hello"})
    runtime = build_authorized_runtime([send_message], [authorization], mode="final_recheck")
    _, error = runtime.run_function(None, "send_message", {"recipient": "mallory", "body": "hello"})
    assert error is not None


def test_call_boundary_allows_changed_arguments_once() -> None:
    authorization = FunctionCall(function="send_message", args={"recipient": "alice", "body": "hello"})
    runtime = build_authorized_runtime([send_message], [authorization], mode="call_boundary")
    result, error = runtime.run_function(None, "send_message", {"recipient": "mallory", "body": "hello"})
    assert result == "mallory:hello"
    assert error is None
