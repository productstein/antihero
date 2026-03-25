"""Anthropic Claude SDK adapter.

Wraps Anthropic client.messages.create so that tool_use blocks
in assistant responses are evaluated against Antihero policy
before the caller can execute them.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from antihero.adapters.base import ToolAdapter
from antihero.envelopes.tce import Caller, Subject
from antihero.guard import Guard


class AnthropicAdapter(ToolAdapter):
    """Adapter for Anthropic Claude tool-use agents.

    Intercepts tool_use content blocks in responses and evaluates
    each one against the policy engine.

    Usage:
        from anthropic import Anthropic
        from antihero.adapters.anthropic import wrap_anthropic_client

        client = Anthropic()
        guard = Guard(engine=..., chain=..., store=...)
        wrap_anthropic_client(client, guard)
    """

    def detect(self, agent: Any) -> bool:
        module = getattr(agent, "__module__", "") or ""
        qualname = getattr(agent, "__qualname__", "") or ""
        return "anthropic" in module or "anthropic" in qualname

    def wrap(self, agent: Any, guard: Guard) -> Any:
        original_fn = agent

        def guarded_create(**kwargs: Any) -> Any:
            # Pre-check: evaluate the request
            messages = kwargs.get("messages", [])
            last_user = ""
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        last_user = content[:200]
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                last_user = block.get("text", "")[:200]
                                break
                    break

            guard.evaluate(
                action="anthropic.messages.create",
                resource=last_user,
                subject=Subject(agent_id="anthropic-client"),
            )

            # Call the original
            response = original_fn(**kwargs)

            # Post-check: evaluate tool_use blocks
            content = getattr(response, "content", [])
            for block in content:
                block_type = getattr(block, "type", None)
                if block_type == "tool_use":
                    tool_name = getattr(block, "name", "unknown")
                    tool_input = getattr(block, "input", {})
                    input_str = str(tool_input)[:200]

                    # Detect PTC caller context from response block
                    block_caller = getattr(block, "caller", None)
                    caller = None
                    if block_caller:
                        caller = Caller(
                            type="programmatic",
                            container_id=getattr(block_caller, "container_id", None),
                            tool_id=getattr(block_caller, "tool_id", None),
                        )
                    else:
                        caller = Caller(type="direct")

                    # This will raise ActionDeniedError if denied
                    guard.evaluate(
                        action=f"anthropic.tool_use.{tool_name}",
                        resource=input_str,
                        subject=Subject(agent_id="anthropic-client"),
                        caller=caller,
                    )

            return response

        guarded_create.__name__ = getattr(original_fn, "__name__", "create")
        guarded_create.__doc__ = getattr(original_fn, "__doc__", "")
        return guarded_create


def wrap_anthropic_client(client: Any, guard: Guard) -> Any:
    """Wrap an Anthropic client's messages.create method.

    Args:
        client: An anthropic.Anthropic() client instance.
        guard: An Antihero Guard instance.

    Returns:
        The client with messages.create wrapped.
    """
    adapter = AnthropicAdapter()
    original = client.messages.create
    wrapped: Callable[..., Any] = adapter.wrap(original, guard)
    client.messages.create = wrapped
    return client
