"""Abstract base adapter for wrapping different agent frameworks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from antihero.guard import Guard


class ToolAdapter(ABC):
    """Base class for agent framework adapters.

    Each adapter knows how to intercept tool calls from a specific
    framework (LangChain, OpenAI, generic callables) and route them
    through the Guard.
    """

    @abstractmethod
    def wrap(self, agent: Any, guard: Any) -> Any:
        """Wrap an agent's tool-calling interface with Guard enforcement.

        Args:
            agent: The agent or tool to wrap.
            guard: The Guard instance to use for policy enforcement.

        Returns:
            The wrapped agent (same type, with tools gated).
        """
        ...

    @abstractmethod
    def detect(self, agent: Any) -> bool:
        """Check if this adapter can handle the given agent.

        Args:
            agent: The agent or tool to check.

        Returns:
            True if this adapter can wrap this agent.
        """
        ...
