<h1 align="center">antihero</h1>

<p align="center">
  <strong>Make your robots insurable.</strong><br />
  Behavioral safety infrastructure for humanoid robots.<br />
  <em>Declarative policies, sub-100μs enforcement, MuJoCo digital twin, cryptographic audit trails.</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@antihero/sdk"><img src="https://img.shields.io/npm/v/@antihero/sdk?color=cb3837&label=npm" alt="npm" /></a>
  <a href="https://pypi.org/project/antihero"><img src="https://img.shields.io/badge/python-3.11+-blue" alt="python" /></a>
  <a href="https://github.com/productstein/antihero/actions/workflows/ci.yml"><img src="https://github.com/productstein/antihero/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/productstein/antihero/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="license" /></a>
  <a href="https://antihero.systems"><img src="https://img.shields.io/badge/docs-antihero.systems-blue" alt="docs" /></a>
  <a href="https://antihero.systems/static/antihero_whitepaper.pdf"><img src="https://img.shields.io/badge/whitepaper-PDF-purple" alt="whitepaper" /></a>
  <a href="https://antihero.systems/static/antihero-arxiv.pdf"><img src="https://img.shields.io/badge/research-paper-orange" alt="research" /></a>
</p>

---

## What is Antihero?

Antihero is behavioral safety infrastructure that makes humanoid robots insurable. It interposes a deterministic policy engine at the **action boundary** — the point where a robot's decision becomes a physical action — and transforms enforcement data into the actuarial evidence that insurance carriers need to underwrite robot fleets.

```
Robot Action ──→ Policy Engine ──→ Digital Twin ──→ Execute/Deny ──→ Audit Trail
 motion.arm.move   YAML rules       MuJoCo sim      allow/deny       Ed25519 signed
 force.gripper     <100μs eval      contact check    risk budget      hash-chained
 perception.*      deny-dominates   effort/velocity  PDE              tamper-evident
```

## Quick Start

```bash
pip install antihero

# Initialize with framework detection
antihero init

# Define a safety policy
cat > .antihero/warehouse-safety.yaml << 'EOF'
version: "1.0"
tier: app
name: warehouse-safety
rules:
  - id: allow-motion
    actions: ["motion.*"]
    effect: allow
    risk_score: 0.2

  - id: deny-excessive-force
    actions: ["force.*"]
    conditions:
      - field: context.force_newtons
        operator: gt
        value: 50.0
    effect: deny

  - id: require-sim-heavy-lift
    actions: ["force.gripper.*"]
    conditions:
      - field: context.payload_kg
        operator: gt
        value: 10.0
    effect: allow_with_requirements
    requirements:
      - kind: simulate
        params:
          engine: mujoco
          max_contact_force: 50.0
EOF

# Certify against ISO 13482 scenarios
antihero certify --suites iso_13482
```

## Adapters

Antihero wraps any robotics framework. Drop-in adapters intercept actions before they reach hardware.

| Framework | Adapter | Usage |
|-----------|---------|-------|
| **ROS 2** | `antihero.adapters.ros` | `adapter.wrap_callback(callback, guard)` |
| **LeRobot** | `antihero.adapters.lerobot` | `adapter.wrap_policy(policy, guard)` |
| **MuJoCo** | Digital twin backend | `SimulationConfig(engine="mujoco")` |
| **Isaac Sim** | Digital twin backend | `SimulationConfig(engine="isaac")` |
| **OpenAI** | `antihero.adapters.openai` | `guard.wrap(openai_client)` |
| **Anthropic** | `antihero.adapters.anthropic` | `guard.wrap(anthropic_client)` |
| **LangChain** | `antihero.adapters.langchain` | `guard.wrap(langchain_agent)` |
| **Any callable** | `antihero.adapters.generic` | `guard.wrap(custom_fn)` |

## Open Source vs Proprietary

| Open Source (Apache 2.0) | Proprietary (SaaS) |
|--------------------------|-------------------|
| Policy engine + YAML schema | Fleet management dashboard |
| Real-time compiled evaluator (<100μs) | Certification engine (130+ scenarios) |
| ROS 2, LeRobot, MuJoCo adapters | Insurance carrier API + webhooks |
| TCE/PDE envelope format | Premium recommendations |
| Ed25519 hash chain format | Compliance exports (ISO, EU AI Act, SOC 2) |
| CLI tool | LLM-enhanced scenario generator |
| ISO 13482 baseline scenarios | Autonomous certification scheduling |
| Digital twin backends | Claims processing + fraud detection |
| Risk budget tracking | Reinsurance treaty simulation |

## Standards Compliance

| Standard | Coverage |
|----------|----------|
| **ISO 13482** | 35 certification scenarios for personal care / service robots |
| **ISO 10218** | Industrial robot safety requirements |
| **ISO/TS 15066** | Collaborative robot force limits (Table A.2 body regions) |
| **EU AI Act** | High-risk AI system requirements (Aug 2026 deadline) |
| **NIST AI RMF** | Risk management framework mapping |

## Technical Highlights

- **<100μs policy evaluation** — precompiled trie + BDD + bytecode VM for 1kHz control loops
- **MuJoCo digital twin** — sim-before-execute validates contact forces, joint efforts, velocity before hardware
- **NVIDIA Isaac Sim** — GPU-accelerated validation for complex multi-robot scenarios
- **Ed25519 cryptographic audit trails** — tamper-evident, legally admissible decision logs
- **Deny-dominates, fail-closed** — any deny rule overrides all allows; no match = deny
- **403+ automated tests** — comprehensive coverage across policy engine, adapters, certification

## Certification

Crash testing for robots — the actuarial data that makes robot insurance possible.

```
OEM builds robot → Antihero certifies against 165+ scenarios →
  Signed Safety Certificate (Ed25519) →
    Carrier prices the premium → Robot deploys with runtime enforcement
```

- **165+ scenarios** across 8 suites (ISO 13482, customer support, finance, devops, data access, admin, orchestration, human proof)
- **Risk grades** A+ through F — coverage score × severity-weighted safety score
- **Safety certificates** — Ed25519-signed, hash-chain-anchored
- **Premium recommendations** — actuarial pricing from certification data + fleet health

## Insurance Infrastructure

Antihero is designed as **underwriting infrastructure** for robot liability insurance.

- Hash-chained audit trails → claims evidence
- Fleet-level risk assessment → carrier underwriting API
- HMAC-signed webhooks → real-time carrier notifications
- Claims processing with 7-layer fraud detection
- Reinsurance treaty simulation (quota share, excess of loss, hybrid)
- Composite risk score incorporating cert data, fleet health, claims history

## Research

| Paper | Description |
|-------|-------------|
| [Whitepaper](https://antihero.systems/static/antihero_whitepaper.pdf) | Architecture, insurance model, and safety thesis |
| [arXiv Preprint](https://antihero.systems/static/antihero-arxiv.pdf) | Runtime enforcement architecture for autonomous robot safety |
| [Actuarial Spec](https://antihero.systems/actuarial-spec) | Insurance data specification for robot underwriting |
| [ROS REP Draft](rep/rep-xxxx.rst) | Declarative Behavioral Safety Policies for ROS 2 Nodes |

## Plans

| Plan | Price | Events/mo | Robots | Key Features |
|------|-------|-----------|--------|--------------|
| **Watchdog** | Free | 1K | 1 | Basic enforcement + audit trail |
| **Enforcer** | $29/mo | 25K | 5 | CLI + MCP + SDK, SOC 2 export |
| **Sentinel** | $99/mo | 250K | 25 | $100K robot liability coverage, fleet dashboard, ISO compliance |
| **Sovereign** | Custom | Unlimited | Unlimited | $1M+ coverage, dedicated instance, 99.99% SLA |

## Resources

- [Documentation](https://antihero.systems/docs) — API reference, integration guides
- [Landing Page](https://antihero.systems) — Product overview
- [News](https://antihero.systems/news) — Release notes
- [Contact](https://antihero.systems/contact) — Get in touch

## Contributing

Contributions welcome. Open an issue first to discuss.

1. Fork the repo
2. Create a feature branch
3. Run tests (`pytest`)
4. Open a pull request

## License

[MIT](LICENSE)
