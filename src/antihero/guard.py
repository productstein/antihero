"""Guard — the core enforcement wrapper.

A Guard wraps a callable with policy enforcement. It builds a TCE,
evaluates it against the policy engine, handles requirements, and
produces an audit trail.

Integrated features:
- Threat scanning (pre-policy)
- Canary tokens (pre-policy, immediate deny)
- Decision caching (before/after policy eval)
- Policy evaluation (core)
- Explainable denials (on deny)
- Requirement handling (post-allow)
- Content inspection + semantic analysis (pre/post execution)
- Trajectory analysis (post-execution)
- Latency tracking (full pipeline)
"""

from __future__ import annotations

import contextlib
import signal
import time
from collections.abc import Callable
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from antihero._internal.hashing import sha256_hex
from antihero.envelopes.pde import PolicyDecisionEnvelope
from antihero.envelopes.tce import Caller, PrincipalIdentity, Subject, ToolCallEnvelope
from antihero.evidence.chain import HashChain
from antihero.evidence.store import AbstractAuditStore
from antihero.exceptions import ActionDeniedError, RequirementNotSatisfiedError
from antihero.notifications import NotificationManager
from antihero.policy.engine import PolicyEngine
from antihero.policy.requirements import handle_requirement
from antihero.threats import ThreatScanner

if TYPE_CHECKING:
    from antihero.analytics.trajectory import TrajectoryAnalyzer
    from antihero.canary import CanaryRegistry
    from antihero.content_inspector import ContentInspector
    from antihero.content_semantic import SemanticAnalyzer
    from antihero.crypto_fips import AirGapMode, FIPSCryptoProvider
    from antihero.explanations import ExplanationEngine
    from antihero.incident import IncidentManager
    from antihero.observability import ObservabilityEngine
    from antihero.performance import DecisionCache, LatencyRecord, LatencyTracker
    from antihero.policy.rate_limiter import RateLimiter
    from antihero.telemetry.collector import TelemetryCollector


class Guard:
    """Wraps callables with policy enforcement, gating, and audit logging.

    Usage:
        guard = Guard(engine=engine, chain=chain, store=store)
        result = guard.execute(
            callable=my_tool_fn,
            action="file.write",
            resource="/etc/config",
            parameters={"content": "..."},
            subject=subject,
        )
    """

    def __init__(
        self,
        engine: PolicyEngine,
        chain: HashChain,
        store: AbstractAuditStore,
        *,
        confirm_callback: Callable[[str], bool] | None = None,
        mfa_callback: Callable[[ToolCallEnvelope], bool] | None = None,
        human_proof_callback: Callable[..., Any] | None = None,
        identity_provider: Callable[[Subject], PrincipalIdentity | None] | None = None,
        threat_scanner: ThreatScanner | None = None,
        content_inspector: ContentInspector | None = None,
        rate_limiter: RateLimiter | None = None,
        notifications: NotificationManager | None = None,
        trajectory_analyzer: TrajectoryAnalyzer | None = None,
        canary_registry: CanaryRegistry | None = None,
        decision_cache: DecisionCache | None = None,
        latency_tracker: LatencyTracker | None = None,
        semantic_analyzer: SemanticAnalyzer | None = None,
        explanation_engine: ExplanationEngine | None = None,
        incident_manager: IncidentManager | None = None,
        observability_engine: ObservabilityEngine | None = None,
        crypto_provider: FIPSCryptoProvider | None = None,
        air_gap: AirGapMode | None = None,
        telemetry: TelemetryCollector | None = None,
    ) -> None:
        self._engine = engine
        self._chain = chain
        self._store = store
        self._confirm_callback = confirm_callback
        self._mfa_callback = mfa_callback
        self._human_proof_callback = human_proof_callback
        self._identity_provider = identity_provider
        self._threat_scanner = threat_scanner or ThreatScanner()
        self._content_inspector = content_inspector
        self._rate_limiter = rate_limiter
        self._notifications = notifications or NotificationManager()
        self._trajectory_analyzer = trajectory_analyzer
        self._canary_registry = canary_registry
        self._decision_cache = decision_cache
        self._latency_tracker = latency_tracker
        self._semantic_analyzer = semantic_analyzer
        self._explanation_engine = explanation_engine
        self._incident_manager = incident_manager
        self._observability_engine = observability_engine
        self._crypto_provider = crypto_provider
        self._air_gap = air_gap
        self._telemetry = telemetry

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    @property
    def chain(self) -> HashChain:
        return self._chain

    @property
    def store(self) -> AbstractAuditStore:
        return self._store

    def evaluate(
        self,
        *,
        action: str,
        resource: str,
        parameters: dict[str, Any] | None = None,
        subject: Subject | None = None,
        context: dict[str, Any] | None = None,
        caller: Caller | None = None,
    ) -> PolicyDecisionEnvelope:
        """Evaluate an action without executing it. Returns the PDE."""
        tce = self._build_tce(action, resource, parameters, subject, context, caller)
        return self._engine.evaluate(tce)

    def evaluate_batch(
        self,
        calls: list[dict[str, Any]],
    ) -> list[PolicyDecisionEnvelope]:
        """Evaluate multiple actions in sequence, sharing the same risk budget.

        Each item in calls should be a dict with keys matching evaluate() params:
        action, resource, parameters, subject, context, caller.
        """
        return [self.evaluate(**call) for call in calls]

    def evaluate_plan(
        self,
        plan: Any,
    ) -> Any:
        """Evaluate an Agent Plan Graph for policy violations and trajectory threats.

        Requires a trajectory_analyzer to be configured.
        """
        if self._trajectory_analyzer is None:
            msg = "TrajectoryAnalyzer not configured"
            raise RuntimeError(msg)
        return self._trajectory_analyzer.check_plan(plan, self._engine)

    def delegate(
        self,
        parent_subject: Subject,
        child_agent_id: str,
        allowed_roles: frozenset[str] | None = None,
    ) -> Subject:
        """Create a delegated Subject with attenuated capabilities.

        The child inherits the intersection of parent roles and allowed_roles.
        Delegation depth is incremented by 1.
        """
        parent_roles = parent_subject.roles
        child_roles = parent_roles & allowed_roles if allowed_roles else parent_roles
        return Subject(
            agent_id=child_agent_id,
            user_id=parent_subject.user_id,
            session_id=parent_subject.session_id,
            roles=child_roles,
            parent_agent_id=parent_subject.agent_id,
            delegation_depth=parent_subject.delegation_depth + 1,
            delegated_roles=child_roles,
            metadata=parent_subject.metadata,
        )

    def execute(
        self,
        fn: Callable[..., Any],
        *,
        action: str,
        resource: str,
        parameters: dict[str, Any] | None = None,
        subject: Subject | None = None,
        context: dict[str, Any] | None = None,
        caller: Caller | None = None,
    ) -> Any:
        """Evaluate policy, handle requirements, execute if allowed, log receipt.

        Full pipeline:
        1. Latency timer start
        2. ThreatScanner.scan()
        3. CanaryRegistry.check() — BEFORE policy eval
        4. DecisionCache.get() — cache hit skips step 5
        5. PolicyEngine.evaluate()
        6. DecisionCache.put() — cache allow decisions
        7. ExplanationEngine.explain() — on deny
        8. handle_requirement()
        9. ContentInspector.scan_fields()
        10. SemanticAnalyzer.analyze_input()
        11. fn(**params) — execution
        12. SemanticAnalyzer.analyze_output()
        13. HashChain.append()
        14. TrajectoryAnalyzer.record_and_check()
        15. LatencyTracker.record()
        """
        params = parameters or {}
        t_start = time.monotonic()
        timing: dict[str, float] = {}

        # ── Step 0: Air-gap network block ────────────────────────────────
        if self._air_gap is not None and self._air_gap.is_active:
            network_actions = ("web.", "http.", "network.", "email.")
            if any(action.startswith(prefix) for prefix in network_actions):
                tce = self._build_tce(action, resource, params, subject, context, caller)
                pde = PolicyDecisionEnvelope(
                    tce_id=tce.id,
                    effect="deny",
                    reason="Air-gap mode active: network actions blocked",
                    risk_score=1.0,
                )
                aee = self._chain.append(tce, pde, outcome="blocked")
                self._store.write(aee)
                self._record_latency(timing, t_start, cache_hit=False)
                raise ActionDeniedError(pde.reason, pde=pde)

        # ── Step 0b: Quarantine check ────────────────────────────────────
        if self._incident_manager is not None:
            _subject = subject or Subject(agent_id="anonymous")
            with contextlib.suppress(Exception):
                if self._incident_manager.is_quarantined(
                    agent_id=_subject.agent_id,
                    resource=resource,
                    session_id=_subject.session_id or "",
                ):
                    tce = self._build_tce(action, resource, params, subject, context, caller)
                    pde = PolicyDecisionEnvelope(
                        tce_id=tce.id,
                        effect="deny",
                        reason=f"Agent '{_subject.agent_id}' is quarantined",
                        risk_score=1.0,
                    )
                    aee = self._chain.append(tce, pde, outcome="blocked")
                    self._store.write(aee)
                    self._record_latency(timing, t_start, cache_hit=False)
                    raise ActionDeniedError(pde.reason, pde=pde)

        # ── Step 1: Threat scan ──────────────────────────────────────────
        t0 = time.monotonic()
        scan_text = f"{action} {resource} {params}"
        scan_result = self._threat_scanner.scan(scan_text)
        threat_context = {}
        if not scan_result.is_clean:
            all_categories = {t.category for t in scan_result.threats_found}
            threat_context = {
                "threats": [t.id for t in scan_result.threats_found],
                "threat_severity": scan_result.max_severity,
                "threat_categories": list(all_categories),
            }
            if scan_result.semantic_threats:
                threat_context["semantic_threats"] = [
                    {
                        "id": st.id,
                        "category": st.category,
                        "similarity": st.similarity,
                        "severity": st.severity,
                    }
                    for st in scan_result.semantic_threats
                ]
                all_categories.update(
                    st.category for st in scan_result.semantic_threats
                )
                threat_context["threat_categories"] = list(all_categories)
        timing["threat_scan_ms"] = (time.monotonic() - t0) * 1000

        merged_context = {**(context or {}), **threat_context}
        tce = self._build_tce(action, resource, params, subject, merged_context, caller)

        # If scanner says block and severity >= 0.9, deny before policy eval
        if scan_result.should_block and scan_result.max_severity >= 0.9:
            threat_ids = [t.id for t in scan_result.threats_found if t.action == "deny"]
            pde = PolicyDecisionEnvelope(
                tce_id=tce.id,
                effect="deny",
                reason=(
                    f"Threat detected: {', '.join(threat_ids)} "
                    f"(severity {scan_result.max_severity:.1f})"
                ),
                risk_score=scan_result.max_severity,
            )
            aee = self._chain.append(tce, pde, outcome="blocked")
            self._store.write(aee)
            self._notifications.notify_threat(
                action=action,
                resource=resource,
                threat_ids=threat_ids,
                severity=scan_result.max_severity,
                agent_id=tce.subject.agent_id,
            )
            # Auto-create incident for high-severity threats
            if self._incident_manager is not None:
                with contextlib.suppress(Exception):
                    from antihero.incident import IncidentSeverity, QuarantineAction

                    incident = self._incident_manager.create_incident(
                        severity=IncidentSeverity.CRITICAL,
                        trigger_detail=f"Threat: {', '.join(threat_ids)}",
                        agent_id=tce.subject.agent_id,
                    )
                    self._incident_manager.quarantine(
                        incident.id,
                        QuarantineAction(
                            action_type="disable_agent",
                            target=tce.subject.agent_id,
                        ),
                    )
            self._record_latency(timing, t_start, cache_hit=False)
            raise ActionDeniedError(pde.reason, pde=pde)

        # ── Step 2: Canary check ─────────────────────────────────────────
        t0 = time.monotonic()
        if self._canary_registry is not None:
            tripwire = self._canary_registry.check(
                resource=resource,
                agent_id=tce.subject.agent_id,
                session_id=tce.subject.session_id,
            )
            if tripwire is not None:
                pde = PolicyDecisionEnvelope(
                    tce_id=tce.id,
                    effect="deny",
                    reason=f"Canary triggered: {tripwire.canary_id} ({tripwire.detail})",
                    risk_score=1.0,
                )
                aee = self._chain.append(tce, pde, outcome="blocked")
                self._store.write(aee)
                self._notifications.notify_canary(
                    resource=resource,
                    canary_id=tripwire.canary_id,
                    agent_id=tce.subject.agent_id,
                    session_id=tce.subject.session_id or "",
                )
                self._record_latency(timing, t_start, cache_hit=False)
                explanation = self._explain_denial(pde, tce)
                raise ActionDeniedError(pde.reason, pde=pde, explanation=explanation)
        timing["canary_check_ms"] = (time.monotonic() - t0) * 1000

        # ── Step 3: Decision cache check ─────────────────────────────────
        t0 = time.monotonic()
        cache_hit = False
        cached_pde = None
        if self._decision_cache is not None:
            cached_pde = self._decision_cache.get(
                action=action,
                resource=resource,
                agent_id=tce.subject.agent_id,
                roles=tce.subject.roles,
            )
            if cached_pde is not None:
                cache_hit = True
        timing["policy_eval_ms"] = 0.0  # will be overwritten if no cache hit

        # ── Step 4: Policy evaluation ────────────────────────────────────
        if cached_pde is not None:
            pde = cached_pde
        else:
            t1 = time.monotonic()
            pde = self._engine.evaluate(tce)
            timing["policy_eval_ms"] = (time.monotonic() - t1) * 1000

            # Cache allow decisions
            if self._decision_cache is not None and pde.effect != "deny":
                self._decision_cache.put(
                    action=action,
                    resource=resource,
                    agent_id=tce.subject.agent_id,
                    roles=tce.subject.roles,
                    pde=pde,
                )

        # ── Step 5: Denied — explain, log, raise ────────────────────────
        if pde.effect == "deny":
            aee = self._chain.append(tce, pde, outcome="blocked")
            self._store.write(aee)
            self._notifications.notify_blocked(
                action=action,
                resource=resource,
                reason=pde.reason,
                agent_id=tce.subject.agent_id,
            )
            self._record_latency(timing, t_start, cache_hit=cache_hit)
            self._record_telemetry(action, pde, tce)
            explanation = self._explain_denial(pde, tce)
            raise ActionDeniedError(pde.reason, pde=pde, explanation=explanation)

        # ── Step 6: Handle requirements ──────────────────────────────────
        t0 = time.monotonic()
        if pde.effect == "allow_with_requirements":
            for req in pde.requirements:
                try:
                    handle_requirement(
                        req,
                        tce,
                        confirm_callback=self._confirm_callback,
                        mfa_callback=self._mfa_callback,
                        human_proof_callback=self._human_proof_callback,
                        rate_limiter=self._rate_limiter,
                    )
                except RequirementNotSatisfiedError:
                    aee = self._chain.append(tce, pde, outcome="requirements_pending")
                    self._store.write(aee)
                    raise
        timing["requirements_ms"] = (time.monotonic() - t0) * 1000

        # ── Step 7: Content inspection (pre-execution DLP) ───────────────
        t0 = time.monotonic()
        content_flags: list[dict[str, object]] = []
        has_redact_req = pde.effect == "allow_with_requirements" and any(
            r.kind == "redact" for r in pde.requirements
        )
        if self._content_inspector:
            scan = self._content_inspector.scan_fields(params)
            content_flags = [asdict(f) for f in scan.findings]
            if has_redact_req and scan.redaction_map:
                params = self._content_inspector.apply_redactions(params, scan)

        # ── Step 8: Semantic analysis (pre-execution) ────────────────────
        if self._semantic_analyzer is not None:
            with contextlib.suppress(Exception):
                semantic_findings = self._semantic_analyzer.analyze_input(params)
                for sf in semantic_findings:
                    content_flags.append({
                        "detector": sf.detector,
                        "severity": sf.severity,
                        "field_path": sf.field_path,
                        "detail": sf.detail,
                    })
        timing["content_scan_ms"] = (time.monotonic() - t0) * 1000

        # Determine sandbox timeout from requirements
        sandbox_timeout = None
        if pde.effect == "allow_with_requirements":
            for req in pde.requirements:
                if req.kind == "sandbox":
                    sandbox_timeout = req.params.get("timeout_seconds", 30)

        # ── Step 9: Execute ──────────────────────────────────────────────
        start = time.monotonic()
        try:
            if sandbox_timeout:
                result = self._execute_with_timeout(fn, params, sandbox_timeout)
            else:
                result = fn(**params)
            duration_ms = (time.monotonic() - start) * 1000
            timing["execution_ms"] = duration_ms

            # ── Step 10: Post-execution content inspection ───────────────
            t0 = time.monotonic()
            if self._content_inspector and result is not None:
                with contextlib.suppress(Exception):
                    output_scan = self._content_inspector.scan_fields(
                        {"output": str(result)}
                    )
                    content_flags.extend(asdict(f) for f in output_scan.findings)

            # Post-execution semantic analysis
            if self._semantic_analyzer is not None and result is not None:
                with contextlib.suppress(Exception):
                    output_findings = self._semantic_analyzer.analyze_output(
                        str(result)
                    )
                    for sf in output_findings:
                        content_flags.append({
                            "detector": sf.detector,
                            "severity": sf.severity,
                            "field_path": sf.field_path,
                            "detail": sf.detail,
                        })
            timing["post_scan_ms"] = (time.monotonic() - t0) * 1000

            # Hash the result for non-sensitive audit
            result_hash = None
            with contextlib.suppress(Exception):
                result_hash = sha256_hex(str(result).encode())

            # ── Step 11: Audit event ─────────────────────────────────────
            aee = self._chain.append(
                tce,
                pde,
                outcome="executed",
                execution_duration_ms=duration_ms,
                result_hash=result_hash,
                content_flags=content_flags or None,
            )
            self._store.write(aee)

            # ── Step 11b: FIPS crypto sign ────────────────────────────────
            if self._crypto_provider is not None:
                with contextlib.suppress(Exception):
                    self._crypto_provider.sign_event(aee.this_hash)

            # ── Step 12: Trajectory analysis (post-execution) ────────────
            if self._trajectory_analyzer is not None:
                with contextlib.suppress(Exception):
                    session_id = tce.subject.session_id or tce.subject.agent_id
                    matches = self._trajectory_analyzer.record_and_check(
                        session_id=session_id,
                        action=action,
                        resource=resource,
                        tce_id=str(tce.id),
                    )
                    for match in matches:
                        self._notifications.notify_trajectory(
                            pattern_id=match.pattern_id,
                            severity=match.severity,
                            detail=match.detail,
                            agent_id=tce.subject.agent_id,
                            session_id=session_id,
                        )
                        # Auto-create incident for high-severity trajectories
                        if match.severity >= 0.8 and self._incident_manager is not None:
                            with contextlib.suppress(Exception):
                                from antihero.incident import IncidentSeverity

                                self._incident_manager.create_incident(
                                    severity=IncidentSeverity.HIGH,
                                    trigger_detail=f"Trajectory: {match.pattern_id}",
                                    agent_id=tce.subject.agent_id,
                                )

            # ── Step 13: Record latency ──────────────────────────────────
            self._record_latency(timing, t_start, cache_hit=cache_hit)

            # ── Step 14: Observability ───────────────────────────────────
            if self._observability_engine is not None:
                with contextlib.suppress(Exception):
                    total_ms = (time.monotonic() - t_start) * 1000
                    self._observability_engine.record_event(
                        agent_id=tce.subject.agent_id,
                        action=action,
                        resource=resource,
                        effect=pde.effect,
                        risk_score=pde.risk_score,
                        latency_ms=total_ms,
                    )

            # ── Step 15: Telemetry ───────────────────────────────────────
            self._record_telemetry(action, pde, tce)

            return result

        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            timing["execution_ms"] = duration_ms
            aee = self._chain.append(
                tce,
                pde,
                outcome="error",
                error=str(exc),
                execution_duration_ms=duration_ms,
                content_flags=content_flags or None,
            )
            self._store.write(aee)
            self._record_latency(timing, t_start, cache_hit=cache_hit)
            self._record_telemetry(action, pde, tce)
            raise

    @staticmethod
    def _execute_with_timeout(
        fn: Callable[..., Any], params: dict[str, Any], timeout_seconds: int,
    ) -> Any:
        """Execute a callable with a SIGALRM-based timeout (Unix only)."""
        def _timeout_handler(signum: int, frame: object) -> None:
            raise TimeoutError(
                f"Sandbox timeout: execution exceeded {timeout_seconds}s"
            )

        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout_seconds)
        try:
            return fn(**params)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def _build_tce(
        self,
        action: str,
        resource: str,
        parameters: dict[str, Any] | None = None,
        subject: Subject | None = None,
        context: dict[str, Any] | None = None,
        caller: Caller | None = None,
    ) -> ToolCallEnvelope:
        """Build a TCE from the provided arguments.

        If an identity_provider is configured and the subject has no principal,
        attempts to resolve one from the subject's credentials.
        """
        if subject is None:
            subject = Subject(agent_id="anonymous")

        # Resolve principal identity if provider is configured and principal is missing
        if self._identity_provider is not None and subject.principal is None:
            with contextlib.suppress(Exception):
                principal = self._identity_provider(subject)
                if principal is not None:
                    subject = subject.model_copy(update={"principal": principal})

        return ToolCallEnvelope(
            subject=subject,
            action=action,
            resource=resource,
            parameters=parameters or {},
            context=context or {},
            caller=caller,
        )

    def _explain_denial(
        self,
        pde: PolicyDecisionEnvelope,
        tce: ToolCallEnvelope,
    ) -> object | None:
        """Generate an explanation for a denial, if explanation engine is configured."""
        if self._explanation_engine is None:
            return None
        with contextlib.suppress(Exception):
            return self._explanation_engine.explain(pde, tce)
        return None

    def _record_telemetry(
        self,
        action: str,
        pde: PolicyDecisionEnvelope,
        tce: ToolCallEnvelope,
    ) -> None:
        """Record an anonymized telemetry event. Fails silently."""
        if self._telemetry is None:
            return
        with contextlib.suppress(Exception):
            from antihero.telemetry.anonymizer import (
                bucket_risk_score,
                generalize_action,
                truncate_timestamp,
            )

            # Determine event type
            if pde.effect == "deny":
                event_type = "action_blocked"
            elif any(
                t for t in tce.context.get("threat_categories", [])
            ):
                event_type = "threat_detected"
            else:
                event_type = "evaluation"

            # Extract threat categories from context (already generalized)
            threat_categories = list(tce.context.get("threat_categories", []))

            # Determine policy tier from matched rules
            policy_tier = "baseline"
            if pde.matched_rules:
                policy_tier = pde.matched_rules[0].policy_tier

            # Check if semantic classifier was involved
            semantic_match = bool(tce.context.get("semantic_threats"))

            from antihero.telemetry.collector import TelemetryEvent

            event = TelemetryEvent(
                timestamp=truncate_timestamp(tce.timestamp.isoformat()),
                event_type=event_type,
                action_category=generalize_action(action),
                effect=pde.effect,
                risk_score_bucket=bucket_risk_score(pde.risk_score),
                threat_categories=threat_categories,
                policy_tier=policy_tier,
                semantic_match=semantic_match,
            )
            self._telemetry.record(event)

    def _record_latency(
        self,
        timing: dict[str, float],
        t_start: float,
        *,
        cache_hit: bool,
    ) -> None:
        """Record latency metrics if tracker is configured."""
        if self._latency_tracker is None:
            return
        with contextlib.suppress(Exception):
            from antihero.performance import LatencyRecord

            total_ms = (time.monotonic() - t_start) * 1000
            execution_ms = timing.get("execution_ms", 0.0)
            self._latency_tracker.record(LatencyRecord(
                threat_scan_ms=timing.get("threat_scan_ms", 0.0),
                canary_check_ms=timing.get("canary_check_ms", 0.0),
                policy_eval_ms=timing.get("policy_eval_ms", 0.0),
                requirements_ms=timing.get("requirements_ms", 0.0),
                content_scan_ms=timing.get("content_scan_ms", 0.0),
                execution_ms=execution_ms,
                total_overhead_ms=total_ms - execution_ms,
                cache_hit=cache_hit,
            ))
