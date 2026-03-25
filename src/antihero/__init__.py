"""Antihero — Behavioral safety engine for humanoid robots.

Open source policy enforcement, digital twin validation, and
cryptographic audit trails for robotics.

    from antihero.policy.engine import PolicyEngine
    from antihero.policy.schema import PolicyDocument, PolicyRule
    from antihero.envelopes.tce import ToolCallEnvelope, Subject
"""

__version__ = "0.3.0"

from antihero.envelopes.pde import PolicyDecisionEnvelope, Requirement
from antihero.envelopes.tce import Caller, Subject, ToolCallEnvelope
from antihero.exceptions import ActionDeniedError, AntiheroError

__all__ = [
    "ActionDeniedError",
    "AntiheroError",
    "Caller",
    "PolicyDecisionEnvelope",
    "Requirement",
    "Subject",
    "ToolCallEnvelope",
    "__version__",
]
