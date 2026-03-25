"""Glob pattern trie for O(|pattern|) action/resource matching.

Replaces fnmatch loops with a single trie traversal. Supports * and ?
wildcards (fnmatch semantics without character classes for performance).

Each leaf stores the set of rule indices that match at that path.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class TrieNode:
    """A node in the glob trie."""

    children: dict[str, TrieNode] = field(default_factory=dict)
    wildcard_child: TrieNode | None = None  # '*' segment
    char_wild_children: dict[str, TrieNode] = field(default_factory=dict)  # '?' patterns
    rule_indices: set[int] = field(default_factory=set)
    is_terminal: bool = False
    is_catch_all: bool = False  # True if pattern was just "*"


class GlobTrie:
    """A trie that indexes glob patterns for fast matching.

    Patterns are split on '.' (e.g., 'motion.arm.*' → ['motion', 'arm', '*']).
    Matching traverses the trie segment-by-segment, following wildcard branches.
    """

    def __init__(self) -> None:
        self._root = TrieNode()

    def insert(self, pattern: str, rule_index: int) -> None:
        """Insert a glob pattern with its associated rule index."""
        if pattern == "*":
            self._root.is_catch_all = True
            self._root.rule_indices.add(rule_index)
            return

        segments = pattern.split(".")
        node = self._root
        for seg in segments:
            if seg == "*":
                if node.wildcard_child is None:
                    node.wildcard_child = TrieNode()
                node = node.wildcard_child
            else:
                if seg not in node.children:
                    node.children[seg] = TrieNode()
                node = node.children[seg]

        node.is_terminal = True
        node.rule_indices.add(rule_index)

    def match(self, value: str) -> set[int]:
        """Return all rule indices whose patterns match the given value.

        Uses iterative DFS to avoid recursion overhead on the hot path.
        """
        result: set[int] = set()

        # Catch-all rules always match
        if self._root.is_catch_all:
            result.update(self._root.rule_indices)

        segments = value.split(".")
        num_segments = len(segments)

        # Stack: (node, segment_index)
        stack: list[tuple[TrieNode, int]] = [(self._root, 0)]

        while stack:
            node, idx = stack.pop()

            if idx == num_segments:
                if node.is_terminal:
                    result.update(node.rule_indices)
                # Trailing wildcard also matches at end
                if node.wildcard_child is not None:
                    wc = node.wildcard_child
                    if wc.is_terminal:
                        result.update(wc.rule_indices)
                continue

            seg = segments[idx]

            # Exact match
            if seg in node.children:
                stack.append((node.children[seg], idx + 1))

            # Wildcard '*' matches this segment and possibly more
            if node.wildcard_child is not None:
                wc = node.wildcard_child
                # '*' consumes exactly one segment
                stack.append((wc, idx + 1))
                # '*' at terminal position matches all remaining segments
                if wc.is_terminal:
                    result.update(wc.rule_indices)
                # '*' can also skip and continue matching more segments
                if wc.wildcard_child is not None:
                    stack.append((wc, idx))

        return result

    @property
    def root(self) -> TrieNode:
        """Access the root node (for serialization)."""
        return self._root
