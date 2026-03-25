"""Antihero framework adapters.

Each adapter wraps a specific framework's tool-calling interface
with policy enforcement.

Available adapters:
    - ROS2Adapter — ROS 2 action servers and services
    - LeRobotAdapter — LeRobot policy inference
    - GenericAdapter — any Python callable (fallback)
    - OpenAIAdapter — OpenAI function-calling
    - AnthropicAdapter — Anthropic Claude SDK
    - LangChainAdapter — LangChain BaseTool
    - CrewAIAdapter — CrewAI agents, crews, and tools
    - AutoGenAdapter — Microsoft AutoGen conversable agents

Adapters are imported lazily to avoid pulling in framework dependencies.
"""
