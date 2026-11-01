# 07 — Interview Preparation (Solution Designer, Agentic AI)

Use this project as your worked example. Replace the bracketed prompts with **your own** real
experience — interviewers probe details, so only claim what you did.

## 7.1 Sixty-second pitch
"I designed an agentic AI solution for a bank contact centre end to end. I started from the business
problem — handle time and risk on repeatable contacts — and turned it into measurable KPIs with Ops.
The design is a LangGraph supervisor with specialist agents. Agents never touch core systems directly;
they go through an MCP tool server where identity, customer binding and purpose of use come from signed
tokens, not from the model. Anything that changes customer state, like locking a card, pauses for a human
reviewer with four-eyes control, and state is durable and encrypted so any worker can resume after a restart.
Answers are grounded in approved knowledge with citations that are checked, and every failure degrades to a
warm transfer. It ships with an evaluation release gate, OpenTelemetry tracing and an audit trail designed
for model-risk and compliance review."

## 7.2 Round (a) — communication, stakeholder management, fit
Prepare two or three STAR stories:

| Theme | Situation / Task prompt | Actions to highlight (map to this project) | Result |
|---|---|---|---|
| Ambiguous requirements | [A time the business asked for "an AI bot"] | Reframed into intents + KPIs; intent analysis from contact data; agreed MVP scope and out-of-scope list (doc 01) | [Measured outcome] |
| Conflicting stakeholders | [Ops wants containment, Compliance wants control] | Proposed risk-tiered design: self-service for low risk, HITL for state changes, transfer for fraud; made trade-offs explicit in ADRs | [Agreement reached, time saved] |
| No PM — owning delivery | [You coordinated QA/Change/Dev/Support] | RAID log, weekly steering, decision log, CAB readiness, hypercare plan (doc 05) | [On-time go-live, defects] |
| Production issue | [An incident you led] | Correlation IDs, RCA template, eval case added to prevent regression (doc 06) | [MTTR, recurrence prevented] |

Questions to ask them: How are AI use cases risk-tiered today? Who owns the KB content? What CCaaS platform and
how is caller authentication passed? How is model validation engaged during design vs at the end? What does
success look like at 6 months for this role?

## 7.3 Round (b) — architecture deep dive: likely questions and crisp answers

**Why LangGraph instead of a single agent loop?** Explicit, testable control flow; conditional edges per intent;
`interrupt()` for HITL with durable checkpoints; least-privilege tools per node. Free-form agents are harder to validate
under model-risk expectations.

**How does HITL survive restarts and multiple workers?** State is checkpointed (encrypted) in PostgreSQL after every node;
the run registry stores the pending interrupt id and action hash. Any replica receives the review, verifies it, claims the
run with optimistic concurrency, and resumes with `Command(resume=…)`. Tested by tearing down and rebuilding the whole service (new connections, new graph) between pause and approval.

**How do you stop a reviewer approving the wrong thing?** The review must quote the pending `interrupt_id` and the SHA-256
hash of the exact action; reviewer ≠ requester; the approval token is bound to run + action hash and verified again by the
tool server. Stale, duplicate or mismatched reviews get 409.

**How do you defend against prompt injection?** Layers: input screening (and optionally Prompt Shields), spotlighting and
filtering retrieved content, structural controls (identity/customer/purpose never from LLM; tool allow-lists; approval tokens),
output validation, HITL for side effects, red-team cases in the eval gate. Assume the model *will* be fooled sometimes and make
that harmless.

**How do you integrate with enterprise systems?** Through MCP tools behind APIM: OAuth2/mTLS, purpose-of-use headers, idempotency
keys, bounded retries, circuit breakers, contract tests. Adding a system means adding a governed tool once.

**RAG specifics?** Hybrid + semantic ranking in Azure AI Search, security trimming by audience/classification, chunk metadata for
citations and freshness, citation-subset check in the output guard, fallback when grounding is absent.

**Memory?** Short-term = per-contact checkpoint thread, trimmed window. Long-term = store namespaced by customer with TTL, holding only
redacted summaries/dispositions, read only after authentication.

**Evaluation?** Golden dataset with thresholds as a CI release gate (intent, routing, HITL precision/recall, injection block rate,
false-block rate, PII leakage, citation accuracy, escalation, step-up, latency); LangSmith experiments for regressions;
Foundry model-graded groundedness/relevance; production monitoring of fallback and override rates.

**Troubleshooting a slow turn?** Follow the correlation id through OTel spans: `llm.*` vs `tool.*` vs `retriever`; check
throttling/quota, breaker state; compare to baseline; roll back prompt/model version if needed.

**Walk me through the services.** Five: an API gateway at the edge (token check, rate limits, header
hygiene, signed proof of entry), the agent API (orchestration and human review), the MCP tool service
(the agents' only route to business systems), and two systems of record, customer and case services.
Every internal hop carries a workload token plus the user's delegation token; the systems of record
re-verify both and the approval token themselves. I showed what happens when the customer service is
down: the agent hands off safely and other paths keep working.

**What would you change for production at scale?** Foundry Agent Service or AKS hosting decision, PTU capacity planning,
Redis-backed rate limiting, Event Hubs for interaction analytics, French-language KB, voice-specific latency budget.

## 7.4 Round (c–g) talking points

* **(c) API & integrations:** integration inventory (doc 03), idempotency + retry policy, APIM policies, contract tests, CCaaS warm-transfer packet.
* **(d) RAG & AI architecture:** RAG pipeline, guardrail layers, HITL, memory design, eval, fallback matrix (doc 02).
* **(e) Solution design + hands-on delivery:** walk the repo: design docs → code → tests → eval gate → runbook. Demo `scripts/demo.py` and the console.
* **(f) Security, governance & compliance:** Entra app roles + PIM, managed identities, purpose limitation, encryption, audit chain, OSFI E-23 (effective May 1, 2027) / B-10 / B-13 mapping, PIPEDA, FCAC complaint handling (doc 04).
* **(g) Regulated-industry examples:** [Your own CIBC/financial-services examples: AML/KYC/sanctions data work, data governance, audit findings you closed]. Tie each to a control in this design.

## 7.5 Whiteboard plan (10 minutes)
1. Draw context: caller → CCaaS → agent service → model / search / core / CRM (1 min).
2. Draw the graph: guard → orchestrator → specialists → HITL → responder → finalize (3 min).
3. Walk the card-lock sequence including the review binding and restart (3 min).
4. Overlay controls: identity, data, AI governance, observability (2 min).
5. Close with KPIs and how you'd prove value in the pilot (1 min).
