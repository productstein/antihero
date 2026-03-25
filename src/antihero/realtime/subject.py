"""Pre-hashed subject representation for O(1) lookup.

Converts agent_id, roles, user_id, and principal into hash keys
at creation time so the hot path never computes hashes.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch


@dataclass(slots=True, frozen=True)
class CompiledSubject:
    """Pre-computed subject identity for fast matching."""

    agent_id: str
    roles: frozenset[str]
    user_id: str | None
    principal_id: str | None
    _identity_key: int  # Pre-computed hash for index lookup

    @classmethod
    def from_tce_subject(cls, subject: object) -> CompiledSubject:
        """Create from a TCE Subject object."""
        agent_id = getattr(subject, "agent_id", "")
        roles = getattr(subject, "roles", frozenset())
        user_id = getattr(subject, "user_id", None)
        principal = getattr(subject, "principal", None)
        principal_id = principal.human_id if principal is not None else None

        identity_key = hash((agent_id, roles, user_id, principal_id))
        return cls(
            agent_id=agent_id,
            roles=frozenset(roles),
            user_id=user_id,
            principal_id=principal_id,
            _identity_key=identity_key,
        )

    @classmethod
    def create(
        cls,
        agent_id: str,
        roles: frozenset[str] | None = None,
        user_id: str | None = None,
        principal_id: str | None = None,
    ) -> CompiledSubject:
        """Create directly from values."""
        r = roles or frozenset()
        identity_key = hash((agent_id, r, user_id, principal_id))
        return cls(
            agent_id=agent_id,
            roles=r,
            user_id=user_id,
            principal_id=principal_id,
            _identity_key=identity_key,
        )

    def matches_patterns(self, patterns: list[str]) -> bool:
        """Check if this subject matches any of the given glob patterns.

        Checks against agent_id, all roles, user_id, and principal_id.
        """
        targets = [self.agent_id]
        targets.extend(self.roles)
        if self.user_id:
            targets.append(self.user_id)
        if self.principal_id:
            targets.append(self.principal_id)

        for pattern in patterns:
            for target in targets:
                if fnmatch(target, pattern):
                    return True
        return False
