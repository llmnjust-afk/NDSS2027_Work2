import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.functions_runtime import FunctionsRuntime


def _completion(arguments: str):
    tool_call = SimpleNamespace(
        id="call-1",
        function=SimpleNamespace(name="example", arguments=arguments),
    )
    message = SimpleNamespace(content=None, tool_calls=[tool_call])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def test_retries_malformed_tool_call_json() -> None:
    client = Mock()
    llm = OpenAILLM(client, "model")
    responses = [_completion('{"value": "unterminated'), _completion('{"value": "ok"}')]
    with patch(
        "agentdojo.agent_pipeline.llms.openai_llm.chat_completion_request",
        side_effect=responses,
    ) as request:
        _, _, _, messages, _ = llm.query("query", FunctionsRuntime())
    assert request.call_count == 2
    assert messages[-1]["tool_calls"][0].args == {"value": "ok"}


def test_raises_after_three_malformed_tool_calls() -> None:
    client = Mock()
    llm = OpenAILLM(client, "model")
    with patch(
        "agentdojo.agent_pipeline.llms.openai_llm.chat_completion_request",
        return_value=_completion('{"value": "unterminated'),
    ) as request:
        try:
            llm.query("query", FunctionsRuntime())
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError("Expected JSONDecodeError")
    assert request.call_count == 3
