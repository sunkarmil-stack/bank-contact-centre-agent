# 05 — Delivery Plan (Solution Designer–led, no dedicated PM)

The Solution Designer owns intake → requirements → design → delivery coordination → production support,
working directly with business stakeholders, application SMEs, QA, Change Management, Development and Support.

## 5.1 Phases

| Phase | Duration (indicative) | Key outputs | Exit criteria |
|---|---|---|---|
| 0. Intake & discovery | 2–3 wks | Problem statement, KPI baseline from CCaaS data, top-20 intent analysis, risk screen | Sponsor sign-off on scope |
| 1. Requirements | 2 wks | BRD (doc 01), NFRs, control requirements with Compliance/Privacy | Stakeholder sign-off |
| 2. Solution design | 3 wks | Architecture + ADRs (02), integration design (03), security & governance (04), model inventory entry | Architecture Review Board + Security review approved |
| 3. Build (iterative) | 3 × 2-wk sprints | Walking skeleton → intents in priority order; evaluation dataset grows each sprint | Eval gate green; SIT passed |
| 4. Test | 3 wks | SIT, UAT with Ops, red-team, performance, DR/failover, accessibility, model validation pack | Model Risk validation; UAT sign-off |
| 5. Pilot | 4–6 wks | Agent-assist only for one team → limited IVR self-service | Pilot KPIs met, no Sev1/2 |
| 6. Scale & hypercare | ongoing | More intents/queues, French KB, BAU handover to Support | Handover checklist complete |

## 5.2 Cadence and communication
* Weekly working session with Contact Centre Ops (requirements, backlog priorities).
* Weekly design/dev sync with App SMEs and developers; daily stand-up during build.
* Fortnightly steering update: RAG status, KPIs, risks, decisions needed.
* Decision log and RAID log maintained by the Solution Designer.

## 5.3 RAID log (initial)

| Type | Item | Owner | Mitigation / action |
|---|---|---|---|
| Risk | Model answers outside approved knowledge | SD / Model Risk | Grounding + citation check, fallback, eval gate |
| Risk | Prompt injection leads to unauthorised action | SD / InfoSec | Token-bound identity, HITL, red-team each release |
| Risk | Reviewer queue becomes a bottleneck | Ops | Staffing via Erlang C, SLA alerts, threshold tuning |
| Risk | Latency of model calls in IVR | SD / AI Platform | Provisioned throughput, smaller classifier model, timeouts |
| Assumption | CCaaS passes customer auth level | Telephony | Confirm in design workshop |
| Issue | KB content outdated in some areas | Knowledge Mgmt | Content owner review before pilot |
| Dependency | Customer API purpose-of-use header support | Core banking SMEs | Interim: enforce in MCP layer |

## 5.4 Test strategy

| Level | What | Tooling | Owner |
|---|---|---|---|
| Unit | Guardrails, PII, tokens, routing, QA, Erlang C | pytest | Dev |
| Integration | Graph flows, MCP tools, persistence, restart/resume | pytest (offline model) | Dev |
| API / security | AuthN/Z matrix, four-eyes, idempotency, rate limits | pytest + DAST | Dev / QA |
| Contract | MCP ↔ backend APIs | Pact (planned) | Dev / App SMEs |
| AI evaluation | Intent, routing, HITL precision/recall, grounding, PII leakage, injection block | `evals/run_eval.py`, LangSmith, Foundry evals | SD / QA / Model Risk |
| Red team | Jailbreaks, indirect injection, social engineering | Manual + automated suites | InfoSec |
| UAT | Real Ops scenarios in a test tenant with synthetic data | Console / agent desktop | Ops |
| Performance | p95 latency, throughput, queue depth | Load test | QA |
| Resilience | Kill a worker mid-review; DB failover; model outage | Chaos drills | SRE |

## 5.5 Release & change management
* Every change (code, prompt, model deployment, threshold, KB index) → PR → CI (lint, SAST, tests, eval gate,
  container scan) → change ticket → CAB → staged rollout (dev → test → pre-prod → prod).
* Feature flags per intent; instant rollback = route intent back to human queue.
* Change Management prepares agent training, job aids, and comms; Ops champions per team.

## 5.6 Cutover & hypercare
1. Freeze KB index version; confirm prompt/model versions in model inventory.
2. Deploy to prod (blue/green), smoke test with synthetic customer, enable for pilot team only.
3. Hypercare 2 weeks: daily triage with Support, Ops and Dev; KPI and fallback-rate review.
4. Handover: runbook (doc 06), dashboards, alert routing, known-issues list, support RACI.
