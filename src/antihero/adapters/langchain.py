"""LangChain tool adapter.

Wraps LangChain BaseTool subclasses so that every invocation
goes through Antihero's Guard for policy evaluation.
"""

from __future__ import annotations

from typing import Any

from antihero.adapters.base import ToolAdapter
from antihero.envelopes.tce import Subject
from antihero.guard import Guard


class LangChainAdapter(ToolAdapter):
    """Adapter for LangChain BaseTool subclasses.

    Wraps a LangChain tool so that _run() calls are intercepted
    and evaluated against Antihero policy.

    Usage:
        from langchain.tools import BaseTool
        from antihero import Guard

        guard = Guard(engine=..., chain=..., store=...)
        adapter = LangChainAdapter()
        wrapped_tool = adapter.wrap(my_tool, guard)
    """

    def detect(self, agent: Any) -> bool:
        cls_name = type(agent).__name__
        mro_names = [c.__name__ for c in type(agent).__mro__]
        return "BaseTool" in mro_names or cls_name == "BaseTool"

    def wrap(self, agent: Any, guard: Guard) -> Any:
        tool = agent
        original_run = tool._run

        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            # Build action from tool name
            action = f"langchain.tool.{tool.name}"
            resource = str(args[0])[:200] if args else str(kwargs)[:200]

            return guard.execute(
                original_run,
                action=action,
                resource=resource,
                parameters=kwargs if kwargs else {"input": args[0]} if args else {},
                subject=Subject(agent_id="langchain-agent"),
            )

        tool._run = guarded_run
        return tool


def wrap_langchain_tools(tools: list[Any], guard: Guard) -> list[Any]:
    """Convenience: wrap a list of LangChain tools with Antihero policy enforcement.

    Args:
        tools: List of LangChain BaseTool instances.
        guard: An Antihero Guard instance.

    Returns:
        The same tools list, with _run methods wrapped.
    """
    adapter = LangChainAdapter()
    for tool in tools:
        if adapter.detect(tool):
            adapter.wrap(tool, guard)
    return tools
