"""Generic callable adapter — wraps any Python callable with Guard enforcement."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from antihero.adapters.base import ToolAdapter
from antihero.guard import Guard


class GenericAdapter(ToolAdapter):
    """Wraps plain Python callables with policy enforcement.

    Usage:
        adapter = GenericAdapter()
        wrapped = adapter.wrap(my_function, guard)
        result = wrapped(arg1=val1, arg2=val2)
    """

    def detect(self, agent: Any) -> bool:
        """Accepts any callable."""
        return callable(agent)

    def wrap(self, agent: Any, guard: Guard) -> Callable[..., Any]:
        """Wrap a callable so every invocation goes through Guard.

        The wrapped callable uses the original function's name as the action
        and "callable" as the resource.
        """
        fn = agent
        action = getattr(fn, "__name__", "unknown_callable")

        def guarded(**kwargs: Any) -> Any:
            return guard.execute(
                fn,
                action=f"callable.{action}",
                resource="callable",
                parameters=kwargs,
            )

        guarded.__name__ = f"antihero_guarded_{action}"
        guarded.__doc__ = f"Antihero-guarded wrapper for {action}"
        return guarded
