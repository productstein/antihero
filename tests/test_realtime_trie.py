"""Tests for the glob pattern trie."""

import pytest

from antihero.realtime.trie import GlobTrie


class TestGlobTrie:
    """Test glob pattern matching via trie."""

    def test_exact_match(self) -> None:
        trie = GlobTrie()
        trie.insert("file.write", 0)
        trie.insert("file.read", 1)

        assert trie.match("file.write") == {0}
        assert trie.match("file.read") == {1}
        assert trie.match("file.delete") == set()

    def test_wildcard_suffix(self) -> None:
        trie = GlobTrie()
        trie.insert("file.*", 0)

        assert trie.match("file.write") == {0}
        assert trie.match("file.read") == {0}
        assert trie.match("db.query") == set()

    def test_wildcard_prefix(self) -> None:
        trie = GlobTrie()
        trie.insert("*.write", 0)

        assert trie.match("file.write") == {0}
        assert trie.match("db.write") == {0}
        assert trie.match("file.read") == set()

    def test_catch_all(self) -> None:
        trie = GlobTrie()
        trie.insert("*", 0)
        trie.insert("file.write", 1)

        result = trie.match("file.write")
        assert 0 in result
        assert 1 in result

        assert trie.match("anything.at.all") == {0}

    def test_multiple_rules_same_pattern(self) -> None:
        trie = GlobTrie()
        trie.insert("file.write", 0)
        trie.insert("file.write", 1)

        assert trie.match("file.write") == {0, 1}

    def test_deep_path(self) -> None:
        trie = GlobTrie()
        trie.insert("motion.arm.left.move", 0)

        assert trie.match("motion.arm.left.move") == {0}
        assert trie.match("motion.arm.right.move") == set()

    def test_wildcard_middle(self) -> None:
        trie = GlobTrie()
        trie.insert("motion.*.move", 0)

        assert trie.match("motion.arm.move") == {0}
        assert trie.match("motion.leg.move") == {0}
        assert trie.match("motion.arm.stop") == set()

    def test_multiple_patterns_overlap(self) -> None:
        trie = GlobTrie()
        trie.insert("motion.*", 0)
        trie.insert("motion.arm.*", 1)
        trie.insert("*", 2)

        result = trie.match("motion.arm.move")
        assert 2 in result  # catch-all

    def test_no_patterns(self) -> None:
        trie = GlobTrie()
        assert trie.match("anything") == set()

    def test_robotics_actions(self) -> None:
        """Test with realistic robotics action patterns."""
        trie = GlobTrie()
        trie.insert("motion.*", 0)
        trie.insert("force.*", 1)
        trie.insert("perception.camera.*", 2)
        trie.insert("power.shutdown", 3)
        trie.insert("environment.door.open", 4)

        assert 0 in trie.match("motion.arm")
        assert 1 in trie.match("force.apply")
        assert 2 in trie.match("perception.camera.capture")
        assert 3 in trie.match("power.shutdown")
        assert trie.match("power.reboot") == set()
        assert 4 in trie.match("environment.door.open")
        assert trie.match("environment.door.close") == set()
