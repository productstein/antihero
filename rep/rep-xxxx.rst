REP: XXXX
Title: Declarative Behavioral Safety Policies for ROS 2 Nodes
Author: Antihero Contributors
Status: Draft
Type: Standards Track
Created: 2026-03-24

Abstract
========

This REP defines a YAML-based format for declaring behavioral safety constraints
on ROS 2 nodes. Policies specify what actions a node may perform, under what
conditions, and with what requirements — evaluated at runtime before execution.
The format enables machine-readable safety documentation that satisfies
ISO 10218, ISO/TS 15066, and EU AI Act requirements.

Motivation
==========

ROS 2 currently has no standard mechanism for expressing behavioral safety
constraints on robot nodes. Safety-critical logic is embedded in application
code, scattered across launch files, parameter configurations, and imperative
callbacks. When a warehouse robot must not exceed 0.5 m/s near a human, that
constraint lives in a velocity controller callback. When a surgical robot must
not apply more than 5N of force without confirmation, that limit is hardcoded
in a joint torque filter. There is no standard way to inspect, compose, audit,
or verify these constraints across a fleet.

This creates three concrete problems. First, safety engineers cannot review the
behavioral envelope of a robot system without reading every line of source code.
A single overlooked callback or misconfigured parameter can create a gap between
the documented safety case and the deployed behavior. Second, regulatory
frameworks — ISO 10218 for industrial robots, ISO/TS 15066 for collaborative
robots, and the EU AI Act for AI-enabled autonomous systems — increasingly
require machine-readable evidence of safety constraints. Auditors need to
answer questions like "under what conditions can this robot apply force to a
human?" without reverse-engineering C++ source. Third, insurance underwriters
pricing coverage for autonomous robotic systems have no standardized way to
evaluate behavioral risk. They cannot compare the safety posture of two
warehouse deployments or verify that a claimed constraint is actually enforced
at runtime.

Existing solutions in the ROS ecosystem address physical safety but not
behavioral safety. The ``ros2_control`` framework handles joint limits and
hardware interfaces. ``MoveIt`` provides collision checking and planning scene
constraints. ``Safety Controller`` nodes implement velocity and proximity
limits. These are necessary but insufficient: they constrain the physical
actuator layer without expressing higher-level behavioral policies like "require
pharmacist approval before dispensing medication" or "deny autonomous operation
when no human operator is within line of sight." The gap between actuator-level
safety and behavioral-level safety is where incidents occur.

The EU AI Act, which entered force in 2025, classifies autonomous robotic
systems used in safety-critical environments (medical, industrial,
transportation) as high-risk AI systems under Annex III. Article 9 requires
risk management systems with "appropriate mitigation and control measures."
Article 14 requires "human oversight measures" that allow a human to
"understand the capacities and limitations of the high-risk AI system."
Article 17 requires a quality management system that includes documentation
of "the methods and measures adopted for the development of the high-risk AI
system, including testing, validation and, where relevant, the use of test
data." A declarative, machine-readable policy format satisfies these
requirements directly: the policy document is both the specification and the
runtime enforcement mechanism.

This REP proposes a standard policy document format that is human-readable,
machine-enforceable, composable across organizational tiers, and compatible
with existing ROS 2 node lifecycle and action server patterns. The format is
based on the Antihero policy engine schema, which has been validated in
production AI agent deployments and is adapted here for robotic systems.

Specification
=============

Policy Document Format
----------------------

A policy document is a YAML file with the following top-level structure:

.. code-block:: yaml

    version: "1.0"
    name: "Human-readable policy name"
    tier: baseline | org | app | user
    description: "Multi-line description of the policy scope and intent."
    rules:
      - id: unique-rule-identifier
        description: "What this rule does"
        effect: allow | deny | allow_with_requirements
        priority: 100
        subjects: ["role:operator", "role:maintenance"]
        actions: ["motion.move", "force.apply"]
        resources: ["zone:warehouse-a", "joint:*"]
        conditions:
          - field: "parameters.velocity"
            operator: lte
            value: 1.5
        requirements:
          - kind: confirm
            params:
              message: "Confirm before proceeding"
        risk_score: 0.5

**version** (string, required): Schema version. This REP defines version
``"1.0"``.

**name** (string, required): A human-readable name for the policy. Must be
unique within a deployment.

**tier** (enum, required): The composition tier. One of ``baseline``, ``org``,
``app``, or ``user``. Policies are evaluated in tier order (baseline first,
user last). A deny at any tier cannot be overridden by a lower-priority tier.

**description** (string, optional): A human-readable description of the
policy's scope, intent, and applicable standards.

**rules** (list, required): An ordered list of policy rules.

Rule Format
-----------

Each rule in the ``rules`` list has the following fields:

**id** (string, required): A unique identifier for the rule. Must be unique
across all policies loaded into the engine. Recommended format:
``<policy-prefix>-<verb>-<noun>``, e.g., ``warehouse-deny-restricted-zone``.

**description** (string, optional): Human-readable description of the rule's
purpose.

**effect** (enum, required): The effect of the rule when matched. One of:

- ``allow``: Permit the action.
- ``deny``: Block the action unconditionally.
- ``allow_with_requirements``: Permit the action only if all requirements
  are satisfied.

**priority** (integer, required): Determines evaluation order within a tier.
Higher values are evaluated first. Recommended ranges:

- 200: Hard safety blocks (emergency stop, collision avoidance)
- 100-199: Regulatory compliance (ISO limits, force caps)
- 50-99: Operational constraints (speed limits, zone restrictions)
- 10-49: Monitoring and logging
- 0: Default rules
- Negative: Catch-all / fallback rules

**subjects** (list of strings, optional): Glob patterns matching the subject
(operator, agent, or role) requesting the action. Defaults to ``["*"]``.
Patterns use the format ``role:<name>`` or ``agent:<id>``.

**actions** (list of strings, required): Glob patterns matching the action
being requested. Uses the standard action taxonomy defined below.

**resources** (list of strings, optional): Glob patterns matching the resource
being acted upon. Resources identify zones, joints, tools, patients, or other
domain-specific entities. Defaults to ``["*"]``.

**conditions** (list of condition objects, optional): Additional predicates
that must all be true for the rule to match. Each condition has:

- ``field`` (string): A dot-path into the action request envelope.
  Standard fields include ``parameters.<name>``, ``context.<name>``,
  ``subject.roles``, ``resource``, and ``caller.type``.
- ``operator`` (enum): One of ``eq``, ``neq``, ``in``, ``not_in``, ``gt``,
  ``gte``, ``lt``, ``lte``, ``contains``, ``matches``.
- ``value``: The comparison value. Type depends on the operator.

**requirements** (list of requirement objects, optional): Conditions that must
be fulfilled before execution proceeds. Only relevant when ``effect`` is
``allow_with_requirements``. Each requirement has:

- ``kind`` (string): The requirement type (see Standard Requirement Kinds).
- ``params`` (object, optional): Parameters for the requirement.

**risk_score** (float, required): A value between 0.0 and 1.0 indicating the
inherent risk of the action if performed. Used for cumulative risk budgeting.
The policy engine maintains a running risk total per session; if cumulative
risk exceeds a configurable threshold, subsequent actions are denied regardless
of individual rule matches.

Evaluation Semantics
--------------------

The policy engine evaluates rules using the following algorithm:

1. **Tier ordering.** Policies are grouped by tier and evaluated in order:
   ``baseline``, ``org``, ``app``, ``user``.

2. **Priority ordering.** Within a tier, rules are evaluated in descending
   priority order (highest priority first).

3. **Pattern matching.** A rule matches if all of the following are true:

   a. At least one ``actions`` pattern matches the requested action.
   b. At least one ``resources`` pattern matches the requested resource
      (or ``resources`` is absent/``["*"]``).
   c. At least one ``subjects`` pattern matches the requesting subject
      (or ``subjects`` is absent/``["*"]``).
   d. All ``conditions`` evaluate to true.

4. **Deny dominates.** If any matching rule across any tier has effect
   ``deny``, the action is denied. This is unconditional and cannot be
   overridden by allow rules at any priority or tier.

5. **Requirements accumulate.** If multiple matching rules have effect
   ``allow_with_requirements``, all requirements from all matching rules
   are combined. The action is permitted only when every requirement is
   satisfied.

6. **Fail-closed default.** If no rule matches a given action, the action
   is denied. Deployments that wish to allow unmatched actions must include
   an explicit catch-all allow rule at negative priority.

7. **Risk budget.** The engine maintains a cumulative risk score per session.
   Each allowed action adds its ``risk_score`` to the session total. If the
   cumulative risk exceeds the configured threshold, subsequent actions are
   denied with reason ``risk_budget_exceeded``.

Standard Action Taxonomy
------------------------

This REP defines the following action namespaces for robotic systems. Actions
use dot-separated hierarchical names. Glob patterns (``*``) match any segment.

**motion.*** — Movement actions:

- ``motion.move`` — Move to a target pose or position.
- ``motion.move_joint`` — Command individual joint positions.
- ``motion.move_cartesian`` — Cartesian space motion.
- ``motion.jog`` — Manual jog mode.
- ``motion.follow_path`` — Follow a pre-planned trajectory.
- ``motion.home`` — Return to home position.
- ``motion.stop`` — Commanded stop (not emergency stop).

**force.*** — Force and torque actions:

- ``force.apply`` — Apply force at end effector or contact point.
- ``force.grip`` — Close gripper with specified force.
- ``force.release`` — Release gripper.
- ``force.push`` — Push against a surface.
- ``force.torque`` — Apply torque to a joint.
- ``force.contact`` — Intentional contact with environment.

**perception.*** — Sensing actions:

- ``perception.scan`` — LIDAR or depth sensor scan.
- ``perception.capture_image`` — Camera image capture.
- ``perception.capture_video`` — Video recording.
- ``perception.detect_human`` — Human detection/tracking.
- ``perception.record_audio`` — Audio recording.
- ``perception.identify`` — Object or person identification.

**power.*** — Power and system control:

- ``power.enable_drives`` — Enable motor drives.
- ``power.disable_drives`` — Disable motor drives.
- ``power.emergency_stop`` — Hardware emergency stop.
- ``power.reset_estop`` — Reset emergency stop.
- ``power.shutdown`` — System shutdown.
- ``power.reboot`` — System reboot.

**tool.*** — End effector and tool actions:

- ``tool.change`` — Change end effector or tool.
- ``tool.activate`` — Activate tool (e.g., start welding, open valve).
- ``tool.deactivate`` — Deactivate tool.
- ``tool.calibrate`` — Calibrate tool.

**environment.*** — Environmental interaction:

- ``environment.open_door`` — Open a door or barrier.
- ``environment.dispense`` — Dispense material or product.
- ``environment.pick`` — Pick an object.
- ``environment.place`` — Place an object.
- ``environment.decontaminate`` — Run decontamination cycle.

**communication.*** — External communication:

- ``communication.send`` — Send message to external system.
- ``communication.broadcast`` — Broadcast to all listeners.
- ``communication.alert`` — Send alert or alarm.
- ``communication.report`` — Send status or data report.
- ``communication.call_human`` — Request human assistance.

Standard Requirement Kinds
--------------------------

Requirements are conditions that must be satisfied before an action with
effect ``allow_with_requirements`` can proceed. The following requirement
kinds are defined:

**confirm**: Requires explicit confirmation from an authorized human
operator before the action proceeds.

.. code-block:: yaml

    kind: confirm
    params:
      message: "Confirm: robot will enter restricted zone B"
      timeout_seconds: 30
      required_role: "role:supervisor"

**mfa**: Requires multi-factor authentication from the operator.

.. code-block:: yaml

    kind: mfa
    params:
      method: "totp"
      required_role: "role:maintenance"

**human_proof**: Requires proof of human presence or supervision. This
may include physical presence detection (e.g., safety scanner, deadman
switch), visual confirmation via camera, or RFID badge proximity.

.. code-block:: yaml

    kind: human_proof
    params:
      method: "safety_scanner"
      zone: "collaborative_workspace"
      min_confidence: 0.95

**simulate**: Requires the action to be simulated before physical
execution. The simulation must complete without collision, joint limit
violation, or force exceedance.

.. code-block:: yaml

    kind: simulate
    params:
      simulator: "moveit_planning_scene"
      timeout_seconds: 10
      check_collisions: true
      check_force_limits: true

**rate_limit**: Restricts the frequency of the action.

.. code-block:: yaml

    kind: rate_limit
    params:
      max_count: 10
      window_seconds: 60

**sandbox**: Requires the action to execute in a sandboxed environment
with restricted permissions before being allowed in production.

.. code-block:: yaml

    kind: sandbox
    params:
      environment: "simulation"
      duration_seconds: 300

**log**: Requires that the action be logged to the audit trail. This
is the weakest requirement — it does not gate execution, but ensures
a record exists.

.. code-block:: yaml

    kind: log
    params:
      level: info
      message: "Motion action executed in zone A"

Audit Trail
-----------

Every policy evaluation produces a **PolicyDecisionEnvelope** (PDE), an
immutable record of the decision. The PDE contains:

.. code-block:: yaml

    id: "pde-uuid-v4"
    tce_id: "tce-uuid-v4"       # The action request being evaluated
    timestamp: "2026-03-24T12:00:00Z"
    effect: "allow"              # Final decision
    reason: "Matched warehouse-allow-open-motion"
    risk_score: 0.3              # This action's risk score
    cumulative_risk: 1.7         # Session total after this action
    matched_rules:
      - rule_id: "warehouse-allow-open-motion"
        policy_tier: "org"
        effect: "allow"
        priority: 50
    requirements: []             # Requirements imposed (if any)
    denied_by: null              # Rule ID that caused denial (if denied)

**Hash chain.** PDEs are chained using SHA-256. Each PDE includes the hash
of the previous PDE, forming a tamper-evident log. The genesis PDE in a
session uses a null previous hash. The hash is computed over the canonical
JSON serialization of the PDE (sorted keys, no whitespace).

.. code-block:: text

    PDE_hash[n] = SHA-256(canonical_json(PDE[n]) || PDE_hash[n-1])

**Signatures.** In deployments requiring non-repudiation, each PDE may be
signed using Ed25519. The signing key belongs to the policy engine instance.
The public key is distributed to auditors and insurance underwriters. The
signature covers the PDE content and the hash chain entry.

**Retention.** PDEs must be retained for the duration required by applicable
regulations. ISO 10218 requires maintenance of safety-related records for
the life of the robot system. The EU AI Act Article 12 requires logs to be
kept for a period "appropriate to the intended purpose of the high-risk AI
system" and at least six months.

ROS 2 Integration
-----------------

The policy engine integrates with ROS 2 through three mechanisms:

**Lifecycle node.** The policy engine runs as a managed lifecycle node
(``rclcpp_lifecycle::LifecycleNode`` or ``rclpy.lifecycle.Node``). It
transitions through ``unconfigured → inactive → active`` states. During
the ``on_configure`` transition, it loads policy documents from the
parameter server or local files. During ``on_activate``, it begins
intercepting action requests. This ensures policies are loaded and
validated before any robot motion occurs.

**Action server interception.** The policy engine intercepts action goals
before they reach the target action server. For each incoming
``GoalRequest``, the engine constructs a ToolCallEnvelope (TCE) from the
goal fields, evaluates it against loaded policies, and either forwards the
goal to the underlying action server or rejects it with an appropriate
result code and the PDE as feedback.

The interception is implemented as a transparent proxy: the policy node
advertises the same action interface as the target node, receives goals,
evaluates policy, and either forwards to the real action server or returns
a rejection. This requires no modification to existing action server
implementations.

**Topic filtering.** For publish/subscribe communication, the policy engine
can filter messages on specified topics. It subscribes to the source topic,
evaluates each message against the policy, and republishes allowed messages
on a filtered topic. This is used for perception and communication actions
where the data flow is continuous rather than request-response.

**Parameter mapping.** The policy engine exposes the following ROS 2
parameters:

- ``policy_files`` (string array): Paths to policy YAML files.
- ``risk_threshold`` (double): Maximum cumulative risk score per session.
  Default: 10.0.
- ``fail_closed`` (bool): Whether to deny unmatched actions. Default: true.
- ``audit_log_path`` (string): Path for PDE audit log output.
- ``signature_key_path`` (string): Path to Ed25519 private key for signing.

Reference Implementation
========================

The Antihero open-source policy engine (https://github.com/antihero-ai/antihero)
provides one possible implementation of this specification. The engine is
implemented in Python and TypeScript with a YAML policy loader, condition
evaluator, deny-dominates compositor, risk budget tracker, and SHA-256 audit
chain. A ROS 2 adapter package (``antihero_ros2``) wraps the engine in a
lifecycle node with action server interception.

Conforming implementations must pass the test suite included with this REP,
which verifies:

- Correct tier ordering and deny-dominates semantics.
- Condition operator evaluation for all defined operators.
- Requirements accumulation across multiple matching rules.
- Fail-closed behavior for unmatched actions.
- Risk budget enforcement.
- Hash chain integrity.

Rationale
=========

**Why YAML over imperative code.** Safety constraints expressed in code are
difficult to review, audit, and compose. A declarative format separates the
policy specification from its enforcement. Safety engineers can review and
modify policies without understanding the implementation language. Auditors
can parse policies with standard YAML tooling. Insurance underwriters can
evaluate risk postures by reading documents rather than source code. YAML
was chosen over JSON for human readability and over XML for simplicity. YAML
is already the standard configuration format in the ROS 2 ecosystem (launch
files, parameter files).

**Why fail-closed.** A system that allows actions by default is unsafe in the
presence of novel or unexpected action requests. Fail-closed ensures that any
action not explicitly permitted by policy is denied. This matches the principle
of least privilege and is required by ISO 10218 Section 5.4 (safety-related
control system requirements). Deployments that prefer a permissive default can
add an explicit catch-all allow rule.

**Why deny-dominates.** In a multi-tier policy composition, conflicts between
rules are resolved by giving deny absolute precedence. This prevents a
lower-tier policy (e.g., a user preference) from overriding a higher-tier
safety constraint (e.g., a baseline force limit). This is the only composition
strategy that guarantees safety invariants are maintained when policies are
layered. It mirrors the behavior of firewall rule sets and mandatory access
control systems.

**Why hash chains.** A sequential, hash-chained audit log provides tamper
evidence without requiring a trusted third party or blockchain infrastructure.
If any PDE in the chain is modified after the fact, the hash chain breaks at
that point. This is sufficient for regulatory compliance (ISO 10218 record-
keeping, EU AI Act Article 12 logging) and provides insurance underwriters
with verifiable evidence of runtime behavior. Ed25519 signatures add non-
repudiation where required.

**Why a standard action taxonomy.** Without a shared vocabulary for robot
actions, policies from different vendors and integrators cannot be compared
or composed. The taxonomy defined here covers the common action categories
across industrial, collaborative, healthcare, and service robotics. It is
extensible: vendors may add domain-specific namespaces (e.g.,
``surgery.incise``, ``logistics.palletize``) without conflicting with the
standard namespaces.

Backwards Compatibility
=======================

This REP introduces a new capability and does not modify any existing ROS 2
APIs, message types, or conventions. Existing ROS 2 nodes require no
modification to operate in a deployment with an Antihero policy engine.

The policy engine operates as a transparent proxy for action servers. Nodes
that are not intercepted by the policy engine continue to function without
change. Nodes that are intercepted see standard action goal accepts or
rejects — the policy engine does not introduce new message types into the
action protocol.

The policy YAML format uses standard YAML 1.2 syntax and does not require
custom tags or extensions.

Security Considerations
=======================

**Policy file integrity.** Policy files should be stored in a read-only
filesystem or protected by file system permissions. In containerized
deployments, policy files should be mounted as read-only volumes. Integrity
can be verified by including a SHA-256 hash of each policy file in the
deployment manifest.

**Tamper-evident audit trail.** The hash-chained PDE log provides tamper
evidence. Any modification to a historical PDE invalidates the chain from
that point forward. Deployments requiring non-repudiation should enable
Ed25519 signatures. The signing key must be stored in a hardware security
module (HSM) or trusted platform module (TPM) in safety-critical
deployments.

**Fail-closed default.** The default deny behavior ensures that a
misconfigured or missing policy file does not result in an open system.
If the policy engine fails to load any policy, all actions are denied until
a valid policy is loaded.

**Denial of service.** An attacker who can modify policy files could add
a rule that denies all actions, rendering the robot inoperative. This is
a safer failure mode than an attacker removing safety constraints. However,
deployments should monitor for unexpected policy changes and alert operators.

**Secret management.** Policy files should not contain secrets (API keys,
passwords, private keys). Requirements that reference external authentication
systems (MFA, human proof) should use service discovery or parameter server
references rather than embedding credentials.

**Network security.** If policies are loaded from a remote server, the
connection must use TLS 1.3 with certificate pinning. Policy updates should
be signed and verified before loading.

References
==========

.. [1] ISO 10218-1:2011, "Robots and robotic devices — Safety requirements
   for industrial robots — Part 1: Robots."

.. [2] ISO 10218-2:2011, "Robots and robotic devices — Safety requirements
   for industrial robots — Part 2: Robot systems and integration."

.. [3] ISO/TS 15066:2016, "Robots and robotic devices — Collaborative robots."

.. [4] Regulation (EU) 2024/1689, "Artificial Intelligence Act."

.. [5] NIST AI 100-1, "Artificial Intelligence Risk Management Framework
   (AI RMF 1.0)," January 2023.

.. [6] REP 1, "REP Purpose and Guidelines."

.. [7] ROS 2 Managed Nodes (Lifecycle),
   https://design.ros2.org/articles/node_lifecycle.html

.. [8] ROS 2 Actions,
   https://design.ros2.org/articles/actions.html

Copyright
=========

This document is placed in the public domain or under the CC0-1.0-Universal
license, whichever is more permissive.
