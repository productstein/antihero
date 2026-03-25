"""Real-time precompiled policy engine for robotics control loops.

Compiles PolicyDocuments into an optimized artifact (trie + BDD + bytecode)
that evaluates in sub-100μs — fast enough for 1kHz robotics control loops.

Usage:
    from antihero.realtime import PolicyCompiler, CompiledEvaluator

    compiler = PolicyCompiler(policies)
    artifact = compiler.compile()
    evaluator = CompiledEvaluator(artifact)
    decision = evaluator.evaluate(action, resource, subject_id, roles, context)
"""

from antihero.realtime.compiler import PolicyCompiler
from antihero.realtime.evaluator import CompiledEvaluator, PolicyDecision
from antihero.realtime.guard import RealtimeGuard
from antihero.realtime.subject import CompiledSubject

__all__ = [
    "PolicyCompiler",
    "CompiledEvaluator",
    "PolicyDecision",
    "RealtimeGuard",
    "CompiledSubject",
]
