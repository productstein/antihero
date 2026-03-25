# REP-XXXX: Declarative Behavioral Safety Policies for ROS 2 Nodes

This directory contains a draft ROS Enhancement Proposal (REP) and example policy files for the Antihero behavioral safety standard applied to ROS 2 robotic systems.

## Contents

- `rep-xxxx.rst` — The full REP document in reStructuredText format
- `examples/warehouse-policy.yaml` — Policy for warehouse AMRs and robotic arms
- `examples/cobot-policy.yaml` — ISO/TS 15066 compliant collaborative robot policy
- `examples/healthcare-policy.yaml` — Hospital robot policy (privacy, medication, infection control)

## Submitting to ros-infrastructure/rep

### 1. Fork the REP repository

```bash
gh repo fork ros-infrastructure/rep --clone
cd rep
```

### 2. Choose a REP number

Check the existing REPs to find the next available number. As of early 2026, numbers above 2100 are likely available for Standards Track REPs.

```bash
ls rep-*.rst | sort -t- -k2 -n | tail -5
```

Rename `rep-xxxx.rst` to the chosen number (e.g., `rep-2200.rst`) and update the `REP: XXXX` field in the document header.

### 3. Add the REP to the index

Edit `rep-0000.rst` (the REP index) and add your entry under the appropriate section ("Standards Track REPs — Accepted" or "Standards Track REPs — Draft" depending on where the process stands):

```rst
   .. list-table::
      :widths: 10 50 10

      * - 2200
        - Declarative Behavioral Safety Policies for ROS 2 Nodes
        - Draft
```

### 4. Create the pull request

```bash
git checkout -b rep-behavioral-safety-policies
cp /path/to/rep-xxxx.rst rep-2200.rst
mkdir -p rep-2200
cp /path/to/examples/*.yaml rep-2200/
git add rep-2200.rst rep-2200/
git commit -m "REP 2200: Declarative Behavioral Safety Policies for ROS 2 Nodes"
git push -u origin rep-behavioral-safety-policies
gh pr create \
  --title "REP 2200: Declarative Behavioral Safety Policies for ROS 2 Nodes" \
  --body "$(cat <<'EOF'
## Summary

This REP defines a YAML-based format for declaring behavioral safety constraints on ROS 2 nodes. Policies specify what actions a node may perform, under what conditions, and with what requirements — evaluated at runtime before execution.

The format enables machine-readable safety documentation that satisfies ISO 10218, ISO/TS 15066, and EU AI Act requirements.

## Key features

- Declarative YAML policy documents with tiered composition (baseline/org/app/user)
- Deny-dominates evaluation semantics with fail-closed defaults
- Standard action taxonomy for robotic systems (motion, force, perception, power, tool, environment, communication)
- SHA-256 hash-chained audit trail with optional Ed25519 signatures
- ROS 2 integration via lifecycle node and action server interception
- Three complete example policies (warehouse, cobot, hospital)

## References

- ISO 10218-1/2:2011
- ISO/TS 15066:2016
- EU AI Act (Regulation 2024/1689)
- NIST AI RMF 1.0
EOF
)"
```

### 5. Announce on ROS Discourse

After the PR is opened, create a post on [ROS Discourse](https://discourse.ros.org/) in the **General** category:

**Title:** `REP 2200: Declarative Behavioral Safety Policies for ROS 2 Nodes`

**Body:**

> We have submitted REP 2200 for community review. This REP defines a YAML-based format for declaring behavioral safety constraints on ROS 2 nodes, covering action policies, force/speed limits, human presence requirements, and tamper-evident audit trails.
>
> The proposal addresses the gap between physical safety mechanisms (ros2_control, MoveIt collision checking) and behavioral safety requirements from ISO 10218, ISO/TS 15066, and the EU AI Act.
>
> PR: [link to PR]
> Full text: [link to RST file]
> Example policies: [link to examples directory]
>
> We welcome feedback on the specification, action taxonomy, and integration approach.

### 6. Timeline expectations

The REP process typically follows this timeline:

| Stage | Duration | What happens |
|-------|----------|-------------|
| Draft submitted | Week 0 | PR opened, Discourse announcement posted |
| Community review | Weeks 1-8 | Comments on PR, Discourse discussion, revisions |
| Shepherding | Weeks 4-12 | A REP editor assigns themselves, provides structural feedback |
| Revision rounds | Weeks 8-16 | Address editor and community feedback, update the REP |
| Acceptance vote | Weeks 12-24 | REP editors vote on acceptance |
| Final | Week 24+ | REP merged, status changed to Accepted |

Expect at least 3-6 months from initial submission to acceptance. Complex Standards Track REPs may take longer. Keep the PR updated with revisions and respond promptly to reviewer comments.

### 7. Tips for a smooth review

- Respond to every comment on the PR, even if just to acknowledge
- Update the REP document based on feedback and push new commits (do not force-push)
- If significant changes are needed, summarize them in a PR comment so reviewers can see what changed
- Cross-reference any related REPs or ROS 2 design documents
- If a reference implementation exists (as it does here), link to it and ensure it passes CI
- Be prepared to present at a ROS 2 TSC meeting if asked
