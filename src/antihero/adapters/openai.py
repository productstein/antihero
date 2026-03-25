"""OpenAI function-calling adapter.

Wraps OpenAI chat completion clients so that function/tool calls
are routed through Antihero's Guard for policy evaluation.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from antihero.adapters.base import ToolAdapter
from antihero.envelopes.tce import Subject
from antihero.guard import Guard


class OpenAIAdapter(ToolAdapter):
    """Adapter for OpenAI function-calling agents.

    Wraps the `client.chat.completions.create` method to intercept
    tool_calls in responses and evaluate them against policy before
    the caller can execute them.

    Usage:
        from openai import OpenAI
        from antihero import wrap

        client = OpenAI()
        guarded_create = wrap(client.chat.completions.create)
    """

    def detect(self, agent: Any) -> bool:
        # Detect openai.ChatCompletion.create or similar
        module = getattr(agent, "__module__", "") or ""
        qualname = getattr(agent, "__qualname__", "") or ""
        return "openai" in module or "openai" in qualname

    def wrap(self, agent: Any, guard: Guard) -> Any:
        original_fn = agent

        def guarded_create(**kwargs: Any) -> Any:
            # Pre-check: evaluate the prompt itself
            messages = kwargs.get("messages", [])
            last_user = ""
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    last_user = str(msg.get("content", ""))[:200]
                    break

            # Evaluate prompt as a chat action
            guard.evaluate(
                action="openai.chat.create",
                resource=last_user,
                subject=Subject(agent_id="openai-client"),
            )

            # Call the original
            response = original_fn(**kwargs)

            # Post-check: evaluate any tool calls in the response
            choices = getattr(response, "choices", [])
            for choice in choices:
                message = getattr(choice, "message", None)
                if not message:
                    continue
                tool_calls = getattr(message, "tool_calls", None) or []
                for tc in tool_calls:
                    fn = getattr(tc, "function", None)
                    if fn:
                        fn_name = getattr(fn, "name", "unknown")
                        fn_args = getattr(fn, "arguments", "{}")
                        # This will raise ActionDeniedError if denied
                        guard.evaluate(
                            action=f"openai.tool_call.{fn_name}",
                            resource=(
                                fn_args[:200] if isinstance(fn_args, str) else str(fn_args)[:200]
                            ),
                            subject=Subject(agent_id="openai-client"),
                        )

            return response

        # Preserve metadata
        guarded_create.__name__ = getattr(original_fn, "__name__", "create")
        guarded_create.__doc__ = getattr(original_fn, "__doc__", "")
        return guarded_create


def wrap_openai_client(client: Any, guard: Guard) -> Any:
    """Convenience: wrap an OpenAI client's chat.completions.create method.

    Args:
        client: An openai.OpenAI() client instance.
        guard: An Antihero Guard instance.

    Returns:
        A callable that replaces client.chat.completions.create.
    """
    adapter = OpenAIAdapter()
    original = client.chat.completions.create
    wrapped: Callable[..., Any] = adapter.wrap(original, guard)
    client.chat.completions.create = wrapped
    return client
