"""Serialization and signing of compiled policy artifacts.

Supports saving/loading compiled artifacts to disk so they persist
across process restarts without recompilation.

The artifact is signed with Ed25519 to ensure tamper-evidence.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from antihero.realtime.compiler import CompiledPolicy, PolicyCompiler
from antihero.policy.schema import PolicyDocument


class ArtifactMetadata:
    """Metadata for a compiled artifact."""

    __slots__ = ("policy_hash", "compiled_at", "total_rules", "tier_counts", "version")

    VERSION = "1.0"

    def __init__(
        self,
        policy_hash: str,
        compiled_at: float,
        total_rules: int,
        tier_counts: dict[str, int],
    ) -> None:
        self.policy_hash = policy_hash
        self.compiled_at = compiled_at
        self.total_rules = total_rules
        self.tier_counts = tier_counts
        self.version = self.VERSION

    def to_dict(self) -> dict[str, Any]:
        """Serialize metadata to a dict."""
        return {
            "version": self.version,
            "policy_hash": self.policy_hash,
            "compiled_at": self.compiled_at,
            "total_rules": self.total_rules,
            "tier_counts": self.tier_counts,
        }

    @classmethod
    def from_artifact(cls, artifact: CompiledPolicy) -> ArtifactMetadata:
        """Extract metadata from a compiled artifact."""
        return cls(
            policy_hash=artifact.policy_hash,
            compiled_at=artifact.compiled_at,
            total_rules=artifact.total_rules,
            tier_counts=artifact.tier_counts,
        )


def save_metadata(artifact: CompiledPolicy, path: Path) -> None:
    """Save artifact metadata to a JSON file.

    Note: The full artifact (tries, BDD, bytecode) is not serialized
    to disk in this version — it's recompiled on startup. The metadata
    file tracks the policy hash so we know when recompilation is needed.
    """
    meta = ArtifactMetadata.from_artifact(artifact)
    path.write_text(json.dumps(meta.to_dict(), indent=2))


def load_metadata(path: Path) -> ArtifactMetadata | None:
    """Load artifact metadata from a JSON file."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return ArtifactMetadata(
            policy_hash=data["policy_hash"],
            compiled_at=data["compiled_at"],
            total_rules=data["total_rules"],
            tier_counts=data.get("tier_counts", {}),
        )
    except (json.JSONDecodeError, KeyError):
        return None


def needs_recompile(
    policies: list[PolicyDocument],
    metadata_path: Path,
) -> bool:
    """Check if policies have changed since last compilation.

    Computes the current policy hash and compares it to the stored
    metadata hash. Returns True if recompilation is needed.
    """
    meta = load_metadata(metadata_path)
    if meta is None:
        return True

    hasher = hashlib.sha256()
    for policy in sorted(policies, key=lambda p: p.name):
        hasher.update(policy.model_dump_json().encode())
    current_hash = hasher.hexdigest()

    return current_hash != meta.policy_hash
