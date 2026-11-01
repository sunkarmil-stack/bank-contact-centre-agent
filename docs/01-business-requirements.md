# 01 — Business Requirements (BRD)

*Owner: Solution Designer · Status: Draft for stakeholder review · Synthetic example*

## 1. Problem statement
Contact-centre agents spend a large share of handle time on repeatable, policy-driven
requests (card loss, balance checks, fee questions, dispute intake, complaint logging),
while high-risk contacts (fraud, vulnerable clients) must reach the right specialist fast.
Knowledge is scattered, after-call work is manual, and QA samples only a small fraction of calls.

## 2. Objectives and success measures

| Objective | KPI | Baseline (to confirm) | Target (pilot) |
|---|---|---|---|
| Contain simple, low-risk intents | Containment rate (resolved, no transfer) | TBD from CCaaS reports | 25–35% of in-scope intents |
| Faster resolution | AHT on assisted contacts | TBD | −15% |
| Lower after-call work | ACW seconds per contact | TBD | −50% (auto wrap-up) |
| Safer handling of risk | Fraud contacts reaching fraud queue within SLA | TBD | ≥ 95% within 30 s |
| Regulatory compliance | Complaints logged when expressed | TBD (QA sample) | 100% |
| Quality | Interactions QA-scored | ~2–5% sampled | 100% auto-scored, low scores human-reviewed |
| Trust | PII leakage / unauthorised actions | — | 0 (hard gate) |

## 3. Scope
**In scope (MVP):** IVR/chat self-service and agent-assist for: product/policy Q&A, balance & recent
transactions, lost/stolen card lock, transaction dispute intake, complaint intake, fraud and
vulnerable-client routing, wrap-up summary, QA scoring, supervisor KPIs, staffing what-if.

**Out of scope (MVP):** credit decisions, payments/transfers initiation, investment advice,
address/KYC changes (future phase, requires additional controls), outbound campaigns, voice biometrics.

## 4. Stakeholders and RACI

| Activity | Contact Centre Ops | Card Services / Disputes | Fraud | Client Care (Complaints) | Compliance / Privacy | Model Risk (2nd line) | InfoSec | App SMEs | Dev | QA | Change Mgmt | Support | Solution Designer |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Requirements & priorities | **A** | C | C | C | C | I | I | C | I | I | I | I | **R** |
| Solution design | C | C | C | C | C | C | C | C | C | I | I | C | **A/R** |
| Control design (HITL, guardrails) | C | C | C | C | **A** | C | C | I | C | I | I | I | **R** |
| Model validation (E-23) | I | I | I | I | C | **A** | C | I | C | C | I | I | **R** (evidence) |
| Build | I | I | I | I | I | I | C | C | **R** | C | I | I | **A** |
| Test (SIT/UAT/eval) | C (UAT) | C (UAT) | C | C | C | C | C | C | C | **R** | I | I | **A** |
| Release / CAB | I | I | I | I | C | C | C | C | C | C | **R** | C | **A** |
| Production support | I | I | I | I | I | I | C | C | C | I | I | **R** | **A** (SME) |

## 5. Personas
* **Caller (retail / small business client)** — wants fast resolution, no repeating themselves.
* **Contact-centre agent** — uses agent-assist; needs context packet on transfer and auto wrap-up.
* **Servicing / fraud reviewer** — approves high-risk actions from a queue.
* **Team lead / supervisor** — monitors KPIs, queues, QA, staffing.
* **Auditor / 2nd line** — verifies decisions, access and model behaviour.

## 6. Functional requirements (with acceptance criteria)

**FR-01 Grounded answers.** *Given* an authenticated or anonymous caller asks a policy question,
*when* approved knowledge covers it, *then* the answer uses only retrieved content and cites document IDs;
*and when* knowledge does not cover it, the caller is transferred (no fabricated answer).

**FR-02 Step-up before disclosure.** *Given* a caller with auth level 0 asks for account data,
*then* no account data is disclosed and the caller is sent to identity verification.

**FR-03 Card lock with human approval.** *Given* an authenticated caller reports a lost/stolen card,
*then* a lock is proposed, the run pauses, a reviewer who is **not** the requester approves or rejects,
and only an approved, matching action is executed exactly once.

**FR-04 Disputes.** Disputes below the configurable threshold (default $500) are opened directly;
at/above threshold require reviewer approval. A CRM case with SLA is created; no outcome is promised.

**FR-05 Complaints.** Any expression of dissatisfaction is logged as a complaint case with a reference
number and acknowledgement SLA; the caller is told the timeline and escalation path.

**FR-06 Fraud.** Suspected fraud/scam → P1 warm transfer to the fraud queue + fraud referral case;
the assistant does not investigate.

**FR-07 Vulnerable clients.** Indicators of vulnerability → specialist queue, empathetic language.

**FR-08 Warm transfer.** Every escalation carries a context packet (intent, sentiment, summary, case id,
priority, target answer SLA).

**FR-09 Wrap-up.** Every interaction produces a redacted summary and disposition code.

**FR-10 QA.** Every interaction is auto-scored; scores < 80 are flagged for human QA.

**FR-11 Supervisor KPIs & staffing.** Supervisors view KPIs and run Erlang C staffing what-ifs.

**FR-12 Audit.** Every data access, tool call, guardrail decision and approval is audit-logged, tamper-evident.

## 7. Non-functional requirements

| Category | Requirement |
|---|---|
| Availability | 99.9% for the API tier; graceful degradation to human hand-off on any dependency failure |
| Latency | p95 ≤ 5 s per turn (IVR), excluding human review wait |
| Durability | Paused runs survive restarts/redeploys; any worker can resume |
| Security | Entra ID auth, least-privilege app roles, managed identities, no secrets in code, private networking |
| Privacy | PII redacted before model, logs, traces and memory; purpose limitation; retention per schedule |
| Auditability | Hash-chained audit trail; prompt/model version recorded per run |
| Scalability | Stateless API replicas; state in PostgreSQL; horizontal scale on queue depth / CPU |
| Accessibility / language | EN/FR support (Canada); plain-language responses |

## 8. Assumptions, constraints, open questions
* CCaaS platform passes authenticated session context (customer reference + auth level) to the service.
* Approved Azure regions in Canada for model hosting and data residency — **confirm with Cloud & Privacy**.
* Open: dispute threshold value; complaint acknowledgement SLA; which intents are eligible for full
  self-service vs agent-assist only; French-language KB availability; record-retention periods.
