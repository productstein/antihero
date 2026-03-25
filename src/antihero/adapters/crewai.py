"""CrewAI agent/tool adapter.

Wraps CrewAI agents and tools so that every tool invocation
goes through Antihero's Guard for policy evaluation.

CrewAI tools expose a ``_run()`` method (similar to LangChain), and
CrewAI agents can delegate tasks to other agents.  This adapter
intercepts both patterns.

Optional dependency — ``crewai`` does **not** need to be installed.
"""

from __future__ import annotations

from typing import Any

from antihero.adapters.base import ToolAdapter
from antihero.envelopes.tce import Subject
from antihero.guard import Guard


class CrewAIAdapter(ToolAdapter):
    """Adapter for CrewAI agents and tools.

    Wraps CrewAI tool ``_run()`` calls and agent delegation so that
    each invocation is evaluated against Antihero policy.

    Usage::

        from antihero import Guard
        from antihero.adapters.crewai import CrewAIAdapter

        guard = Guard(engine=..., chain=..., store=...)
        adapter = CrewAIAdapter()

        # Wrap individual tools
        wrapped_tool = adapter.wrap(my_tool, guard)

        # Or wrap an entire agent's tool set
        wrap_crewai_agent(agent, guard)
    """

    def detect(self, agent: Any) -> bool:
        """Return True if *agent* is a CrewAI Agent, Crew, or tool."""
        cls_name = type(agent).__name__
        mro_names = [c.__name__ for c in type(agent).__mro__]

        # CrewAI tools inherit from crewai.tools.BaseTool (or
        # langchain_core.tools.BaseTool) and expose _run().
        if "BaseTool" in mro_names and hasattr(agent, "_run"):
            module = getattr(type(agent), "__module__", "") or ""
            if "crewai" in module:
                return True

        # CrewAI Agent or Crew class
        if cls_name in {"Agent", "Crew"} and _is_crewai_class(agent):
            return True

        return False

    def wrap(self, agent: Any, guard: Guard) -> Any:
        """Wrap a CrewAI tool or agent with Guard enforcement.

        * If *agent* looks like a **tool** (has ``_run``), its ``_run``
          method is wrapped.
        * If *agent* looks like a **CrewAI Agent** (has ``tools``), every
          tool in its ``tools`` list is wrapped, and its
          ``execute_task`` / ``delegate`` path is guarded.
        * If *agent* looks like a **Crew**, every agent inside the crew
          is wrapped recursively.

        Returns the same object with methods monkey-patched.
        """
        cls_name = type(agent).__name__

        if cls_name == "Crew" and _is_crewai_class(agent):
            return self._wrap_crew(agent, guard)

        if cls_name == "Agent" and _is_crewai_class(agent):
            return self._wrap_agent(agent, guard)

        # Treat as a standalone tool
        if hasattr(agent, "_run"):
            return self._wrap_tool(agent, guard)

        return agent

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _wrap_tool(self, tool: Any, guard: Guard) -> Any:
        """Wrap a single CrewAI tool's ``_run`` method."""
        original_run = tool._run

        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            tool_name = getattr(tool, "name", type(tool).__name__)
            action = f"crewai.tool.{tool_name}"
            resource = str(args[0])[:200] if args else str(kwargs)[:200]

            # Capture positional args in a closure so guard.execute can
            # call the wrapper with **parameters.
            def _invoke(**_kw: Any) -> Any:
                return original_run(*args, **kwargs)

            return guard.execute(
                _invoke,
                action=action,
                resource=resource,
                parameters=kwargs if kwargs else {"input": str(args[0])} if args else {},
                subject=Subject(agent_id="crewai-agent"),
            )

        tool._run = guarded_run
        return tool

    def _wrap_agent(self, agent: Any, guard: Guard) -> Any:
        """Wrap every tool on a CrewAI Agent and guard delegation."""
        # Wrap each tool in the agent's tool list
        tools = getattr(agent, "tools", None) or []
        for tool in tools:
            if hasattr(tool, "_run"):
                self._wrap_tool(tool, guard)

        # Guard agent delegation (execute_task dispatches to tools or
        # delegates to other agents).
        if hasattr(agent, "execute_task"):
            original_execute = agent.execute_task

            def guarded_execute_task(*args: Any, **kwargs: Any) -> Any:
                agent_role = getattr(agent, "role", "unknown")
                task_desc = ""
                if args:
                    task_desc = str(getattr(args[0], "description", ""))[:200]
                elif "task" in kwargs:
                    task_desc = str(getattr(kwargs["task"], "description", ""))[:200]

                # Capture positional args in closure for guard.execute
                def _invoke(**_kw: Any) -> Any:
                    return original_execute(*args, **kwargs)

                return guard.execute(
                    _invoke,
                    action="crewai.agent.execute_task",
                    resource=task_desc,
                    parameters=kwargs,
                    subject=Subject(
                        agent_id=f"crewai-agent-{agent_role}",
                    ),
                )

            agent.execute_task = guarded_execute_task

        return agent

    def _wrap_crew(self, crew: Any, guard: Guard) -> Any:
        """Wrap every agent inside a CrewAI Crew."""
        agents = getattr(crew, "agents", None) or []
        for ag in agents:
            self._wrap_agent(ag, guard)

        # Guard the top-level kickoff
        if hasattr(crew, "kickoff"):
            original_kickoff = crew.kickoff

            def guarded_kickoff(*args: Any, **kwargs: Any) -> Any:
                return guard.execute(
                    original_kickoff,
                    action="crewai.crew.kickoff",
                    resource="crew",
                    parameters=kwargs,
                    subject=Subject(agent_id="crewai-crew"),
                )

            crew.kickoff = guarded_kickoff

        return crew


def _is_crewai_class(obj: Any) -> bool:
    """Heuristic check that *obj* originates from the ``crewai`` package."""
    module = getattr(type(obj), "__module__", "") or ""
    return "crewai" in module


# ------------------------------------------------------------------
# Convenience helpers
# ------------------------------------------------------------------

def wrap_crewai_agent(agent: Any, guard: Guard) -> Any:
    """Convenience: wrap a single CrewAI Agent with Antihero policy enforcement.

    Args:
        agent: A ``crewai.Agent`` instance.
        guard: An Antihero Guard instance.

    Returns:
        The same agent, with tools and delegation wrapped.
    """
    adapter = CrewAIAdapter()
    return adapter.wrap(agent, guard)


def wrap_crewai_crew(crew: Any, guard: Guard) -> Any:
    """Convenience: wrap an entire CrewAI Crew with Antihero policy enforcement.

    Args:
        crew: A ``crewai.Crew`` instance.
        guard: An Antihero Guard instance.

    Returns:
        The same crew, with all agents' tools and delegation wrapped.
    """
    adapter = CrewAIAdapter()
    return adapter.wrap(crew, guard)


def wrap_crewai_tools(tools: list[Any], guard: Guard) -> list[Any]:
    """Convenience: wrap a list of CrewAI tools with Antihero policy enforcement.

    Args:
        tools: List of CrewAI tool instances.
        guard: An Antihero Guard instance.

    Returns:
        The same tools list, with _run methods wrapped.
    """
    adapter = CrewAIAdapter()
    for tool in tools:
        if adapter.detect(tool) or hasattr(tool, "_run"):
            adapter._wrap_tool(tool, guard)
    return tools
