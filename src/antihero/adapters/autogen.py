"""AutoGen agent adapter.

Wraps Microsoft AutoGen conversable agents so that registered
tool/function calls go through Antihero's Guard for policy evaluation.

AutoGen agents register tools via ``register_function()`` or
``register_for_execution()``.  This adapter monkey-patches those
registration paths to inject Guard enforcement around every registered
callable, and optionally guards the multi-agent conversation flow.

Optional dependency — ``autogen`` / ``pyautogen`` does **not** need to
be installed.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from antihero.adapters.base import ToolAdapter
from antihero.envelopes.tce import Subject
from antihero.guard import Guard


class AutoGenAdapter(ToolAdapter):
    """Adapter for Microsoft AutoGen agents.

    Wraps AutoGen function registrations and conversation initiation
    so that every tool execution is evaluated against Antihero policy.

    Usage::

        from antihero import Guard
        from antihero.adapters.autogen import AutoGenAdapter

        guard = Guard(engine=..., chain=..., store=...)
        adapter = AutoGenAdapter()

        # Wrap a single agent
        wrapped_agent = adapter.wrap(assistant, guard)

        # Or use the convenience helper
        from antihero.adapters.autogen import wrap_autogen_agent
        wrap_autogen_agent(assistant, guard)
    """

    def detect(self, agent: Any) -> bool:
        """Return True if *agent* is an AutoGen conversable agent."""
        cls_name = type(agent).__name__
        mro_names = [c.__name__ for c in type(agent).__mro__]
        module = getattr(type(agent), "__module__", "") or ""

        # pyautogen / autogen-agentchat classes
        if "autogen" in module:
            return True

        # Well-known AutoGen class names in the MRO
        autogen_classes = {
            "ConversableAgent",
            "AssistantAgent",
            "UserProxyAgent",
            "GroupChatManager",
        }
        if autogen_classes & set(mro_names):
            return True

        if cls_name in autogen_classes:
            return True

        return False

    def wrap(self, agent: Any, guard: Guard) -> Any:
        """Wrap an AutoGen agent with Guard enforcement.

        Three things are wrapped:

        1. **Existing registered functions** — any callables already
           present in ``_function_map`` are replaced with guarded
           versions.
        2. **register_function / register_for_execution** — future
           registrations are intercepted so that newly added functions
           are automatically guarded.
        3. **initiate_chat** — the top-level conversation entry-point
           is guarded to audit the start of multi-agent flows.

        Returns the same agent object with methods monkey-patched.
        """
        agent_name = getattr(agent, "name", type(agent).__name__)
        subject = Subject(agent_id=f"autogen-{agent_name}")

        # 1. Wrap already-registered functions
        fn_map = getattr(agent, "_function_map", None)
        if isinstance(fn_map, dict):
            for fn_name, fn_callable in list(fn_map.items()):
                fn_map[fn_name] = _guard_callable(
                    fn_callable, fn_name, guard, subject,
                )

        # 2. Wrap register_function so future registrations are guarded
        if hasattr(agent, "register_function"):
            original_register = agent.register_function

            def guarded_register(function_map: dict[str, Callable[..., Any]]) -> None:
                wrapped_map = {
                    name: _guard_callable(fn, name, guard, subject)
                    for name, fn in function_map.items()
                }
                return original_register(wrapped_map)

            agent.register_function = guarded_register

        # 3. Wrap register_for_execution so decorated tools are guarded
        if hasattr(agent, "register_for_execution"):
            original_reg_exec = agent.register_for_execution

            def guarded_register_for_execution(
                name: str | None = None,
            ) -> Callable[..., Any]:
                """Return a decorator that registers a guarded function."""
                decorator = original_reg_exec(name=name)

                def guarded_decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                    fn_name = name or getattr(fn, "__name__", "unknown")
                    guarded_fn = _guard_callable(fn, fn_name, guard, subject)
                    return decorator(guarded_fn)

                return guarded_decorator

            agent.register_for_execution = guarded_register_for_execution

        # 4. Guard initiate_chat for multi-agent conversation auditing
        if hasattr(agent, "initiate_chat"):
            original_initiate = agent.initiate_chat

            def guarded_initiate_chat(
                recipient: Any, *args: Any, **kwargs: Any,
            ) -> Any:
                recipient_name = getattr(recipient, "name", "unknown")
                message = kwargs.get("message", "")
                if isinstance(message, str):
                    resource = message[:200]
                else:
                    resource = str(message)[:200]

                def _invoke(**_kw: Any) -> Any:
                    return original_initiate(recipient, *args, **kwargs)

                return guard.execute(
                    _invoke,
                    action="autogen.initiate_chat",
                    resource=resource,
                    parameters={
                        "recipient": recipient_name,
                        **{k: str(v)[:200] for k, v in kwargs.items()},
                    },
                    subject=subject,
                )

            agent.initiate_chat = guarded_initiate_chat

        return agent


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _guard_callable(
    fn: Callable[..., Any],
    fn_name: str,
    guard: Guard,
    subject: Subject,
) -> Callable[..., Any]:
    """Return a wrapper around *fn* that routes through the Guard."""

    def guarded(*args: Any, **kwargs: Any) -> Any:
        action = f"autogen.function.{fn_name}"
        resource = str(args[0])[:200] if args else str(kwargs)[:200]

        # Build a parameter dict for auditing, but use a closure to
        # forward the original positional + keyword args faithfully.
        params = dict(kwargs)
        if args:
            params["_positional_repr"] = [str(a)[:200] for a in args]

        def _invoke(**_kw: Any) -> Any:
            return fn(*args, **kwargs)

        return guard.execute(
            _invoke,
            action=action,
            resource=resource,
            parameters=params,
            subject=subject,
        )

    guarded.__name__ = f"antihero_guarded_{fn_name}"
    guarded.__doc__ = f"Antihero-guarded wrapper for {fn_name}"
    return guarded


# ------------------------------------------------------------------
# Convenience helpers
# ------------------------------------------------------------------

def wrap_autogen_agent(agent: Any, guard: Guard) -> Any:
    """Convenience: wrap an AutoGen agent with Antihero policy enforcement.

    Args:
        agent: An AutoGen ConversableAgent (or subclass) instance.
        guard: An Antihero Guard instance.

    Returns:
        The same agent, with function registrations and chat initiation wrapped.
    """
    adapter = AutoGenAdapter()
    return adapter.wrap(agent, guard)


def wrap_autogen_agents(agents: list[Any], guard: Guard) -> list[Any]:
    """Convenience: wrap multiple AutoGen agents with Antihero policy enforcement.

    Args:
        agents: List of AutoGen agent instances.
        guard: An Antihero Guard instance.

    Returns:
        The same agents list, each with functions and chat wrapped.
    """
    adapter = AutoGenAdapter()
    for agent in agents:
        if adapter.detect(agent):
            adapter.wrap(agent, guard)
    return agents
