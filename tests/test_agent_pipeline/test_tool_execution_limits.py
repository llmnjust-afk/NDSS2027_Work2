import pytest

from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.functions_runtime import EmptyEnv, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage


def test_executor_aborts_oversized_tool_call_batch_before_execution():
    executed = []
    runtime = FunctionsRuntime()

    @runtime.register_function
    def mutate(value: int) -> int:
        """Record a value.

        Args:
            value: Value to record.
        """
        executed.append(value)
        return value

    calls = [FunctionCall(function="mutate", args={"value": index}) for index in range(3)]
    messages = [ChatAssistantMessage(role="assistant", content=None, tool_calls=calls)]

    with pytest.raises(AbortAgentError, match="more than 2 tool calls"):
        ToolsExecutor(max_tool_calls_per_message=2).query("", runtime, EmptyEnv(), messages)

    assert executed == []
