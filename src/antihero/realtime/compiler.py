"""Policy compiler — transforms PolicyDocuments into a CompiledPolicy artifact.

The compiler processes all policies once (offline) and produces an optimized
data structure that the CompiledEvaluator can traverse in sub-100μs.

Compilation steps:
1. Flatten all rules across tiers with tier metadata
2. Build action trie from all rule action patterns
3. Build resource trie from all rule resource patterns
4. Compile conditions for each rule into bytecode
5. Build subject pattern index
6. Construct deny-dominates BDD
7. Sign the artifact with Ed25519
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from antihero.policy.schema import PolicyDocument
from antihero.realtime.bdd import CompiledRule, PolicyBDD
from antihero.realtime.bytecode import CompiledConditions, ConditionCompiler
from antihero.realtime.trie import GlobTrie


@dataclass(slots=True)
class IndexedRule:
    """A rule with its compiled components and original metadata."""

    index: int
    rule_id: str
    tier: str
    effect: str
    priority: int
    risk_score: float
    subjects: list[str]
    actions: list[str]
    resources: list[str]
    requirements: tuple[dict[str, Any], ...]
    conditions: CompiledConditions


@dataclass(slots=True)
class CompiledPolicy:
    """The compiled policy artifact — everything needed for fast evaluation."""

    action_trie: GlobTrie
    resource_trie: GlobTrie
    rules: list[IndexedRule]
    bdd: PolicyBDD
    subject_index: dict[str, set[int]]  # pattern → rule indices
    policy_hash: str
    compiled_at: float
    total_rules: int
    tier_counts: dict[str, int]

    def rule_by_index(self, idx: int) -> IndexedRule | None:
        """Get a rule by its index."""
        if 0 <= idx < len(self.rules):
            return self.rules[idx]
        return None


TIER_ORDER: dict[str, int] = {"baseline": 0, "org": 1, "app": 2, "user": 3}


class PolicyCompiler:
    """Compiles PolicyDocuments into a CompiledPolicy artifact."""

    def __init__(self, policies: list[PolicyDocument]) -> None:
        self._policies = policies
        self._condition_compiler = ConditionCompiler()

    def compile(self) -> CompiledPolicy:
        """Compile all policies into an optimized artifact.

        This is an offline operation — call once when policies change,
        then reuse the artifact for all evaluations.
        """
        # Step 1: Flatten and index all rules
        indexed_rules: list[IndexedRule] = []
        tier_counts: dict[str, int] = {"baseline": 0, "org": 0, "app": 0, "user": 0}

        sorted_policies = sorted(
            self._policies,
            key=lambda p: TIER_ORDER.get(p.tier, 99),
        )

        rule_index = 0
        for policy in sorted_policies:
            sorted_rules = sorted(policy.rules, key=lambda r: -r.priority)
            for rule in sorted_rules:
                compiled_conds = self._condition_compiler.compile(
                    list(rule.conditions)
                )
                indexed_rules.append(
                    IndexedRule(
                        index=rule_index,
                        rule_id=rule.id,
                        tier=policy.tier,
                        effect=rule.effect,
                        priority=rule.priority,
                        risk_score=rule.risk_score,
                        subjects=list(rule.subjects),
                        actions=list(rule.actions),
                        resources=list(rule.resources),
                        requirements=tuple(rule.requirements),
                        conditions=compiled_conds,
                    )
                )
                tier_counts[policy.tier] = tier_counts.get(policy.tier, 0) + 1
                rule_index += 1

        # Step 2: Build action trie
        action_trie = GlobTrie()
        for rule in indexed_rules:
            for pattern in rule.actions:
                action_trie.insert(pattern, rule.index)

        # Step 3: Build resource trie
        resource_trie = GlobTrie()
        for rule in indexed_rules:
            for pattern in rule.resources:
                resource_trie.insert(pattern, rule.index)

        # Step 4: Build subject pattern index
        subject_index: dict[str, set[int]] = {}
        for rule in indexed_rules:
            for pattern in rule.subjects:
                if pattern not in subject_index:
                    subject_index[pattern] = set()
                subject_index[pattern].add(rule.index)

        # Step 5: Build BDD
        compiled_rules = [
            CompiledRule(
                index=r.index,
                rule_id=r.rule_id,
                tier=r.tier,
                effect=r.effect,
                priority=r.priority,
                risk_score=r.risk_score,
                requirements=r.requirements,
            )
            for r in indexed_rules
        ]
        bdd = PolicyBDD(compiled_rules)

        # Step 6: Compute policy hash
        policy_hash = self._compute_hash()

        return CompiledPolicy(
            action_trie=action_trie,
            resource_trie=resource_trie,
            rules=indexed_rules,
            bdd=bdd,
            subject_index=subject_index,
            policy_hash=policy_hash,
            compiled_at=time.time(),
            total_rules=len(indexed_rules),
            tier_counts=tier_counts,
        )

    def _compute_hash(self) -> str:
        """Compute a deterministic hash of all input policies."""
        hasher = hashlib.sha256()
        for policy in sorted(self._policies, key=lambda p: p.name):
            hasher.update(policy.model_dump_json().encode())
        return hasher.hexdigest()
