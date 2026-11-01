# 03 — API & Enterprise Integration Design

## 3.1 Integration inventory

| # | System | Direction | Pattern / protocol | AuthN/Z | Data | Idempotency / errors | Owner (SME) |
|---|---|---|---|---|---|---|---|
| I1 | CCaaS (IVR, chat, routing) | In | REST `POST /v1/interactions`; transfer via CCaaS routing API with context packet | Entra client-credentials token for the channel app; customer auth level asserted in token | Utterance (redacted at boundary), session id, customer ref | `Idempotency-Key` per turn | Telephony / CCaaS team |
| I2 | Agent desktop | In | REST (agent-assist) | Entra user token, `contact_centre_agent` role | Same | Same | Agent desktop team |
| I3 | Azure OpenAI (Microsoft Foundry) | Out | HTTPS, Entra token (managed identity) | `Cognitive Services OpenAI User` on the resource | Redacted prompts | Timeouts, 1 retry, fallback | AI Platform |
| I4 | Azure AI Search | Out (via MCP) | REST hybrid + semantic | Managed identity, `Search Index Data Reader` | KB chunks | Read-only, retry-safe | Knowledge Mgmt |
| I5 | Customer / core banking API | Out (via MCP) | REST behind APIM, mTLS | OAuth2 client credentials + `X-On-Behalf-Of`, `X-Purpose-Of-Use` headers; server-side authorization | Minimised profile, transactions, card lock | `Idempotency-Key` on POST; 429/5xx transient | Core banking SMEs |
| I6 | CRM / case management | Out (via MCP) | REST behind APIM | OAuth2 client credentials | Cases (complaint, dispute, fraud referral) | Idempotency key → no duplicate cases | CRM team |
| I7 | Entra ID | Out | OIDC / JWKS | — | Token validation keys, app roles | Cached JWKS | IAM |
| I8 | Key Vault | Out | SDK, managed identity | `Key Vault Secrets User` | Signing keys, DB DSN, encryption key | Cached, rotation-aware | Security Eng |
| I9 | Azure Monitor / Sentinel | Out | OTLP / exporter; audit stream | Managed identity | Traces, metrics, audit events (redacted) | Async, non-blocking | SecOps / SRE |
| I10 | Event Hubs (future) | Out | Interaction events for analytics/QA | Managed identity | Redacted events | At-least-once, consumer dedupe | Data Platform |

## 3.1b Internal service APIs (implemented)

| Service | Endpoint | Caller permission | User context | Notes |
|---|---|---|---|---|
| Customer service | `GET /customers/{ref}/profile` | `customer.read` | delegation token for `get_customer_profile`, same client | Fields minimised by purpose; step-up → 403 `step_up_required` |
| Customer service | `GET /customers/{ref}/transactions?limit=` | `customer.read` | delegation for `list_recent_transactions` | Purpose must allow transactions |
| Customer service | `POST /customers/{ref}/cards/{id}/lock` | `customer.cards.lock` | delegation for `lock_card` + `X-Approval-Token` + `X-Run-Id` | Four-eyes re-checked; `Idempotency-Key` required; replay returns the original confirmation |
| Case service | `POST /cases` | `cases.write` | delegation for `create_case` | Client from token; purpose must match case type; large disputes need approval; `Idempotency-Key` required |
| Case service | `GET /cases`, `GET /cases/{id}` | `cases.read` | none (reporting) | Used by the agent API for supervisor KPIs |
| All | `GET /healthz`, `GET /metrics` | none | none | Health probed by the gateway |

Errors use one body shape: `{"error": "<code>", "message": "<text>"}`. Every refused request is written to
the shared audit store as `service_access_denied` with the service name.

## 3.2 Public API (summary)

| Method | Path | Roles | Notes |
|---|---|---|---|
| POST | `/v1/interactions` | channel_service, contact_centre_agent | Requires `Idempotency-Key`; optional `thread_id` for multi-turn; returns response or `awaiting_review` |
| GET | `/v1/runs/{run_id}` | owner, supervisor, reviewer, auditor | |
| GET | `/v1/runs/{run_id}/explain` | owner, supervisor, reviewer, auditor | Explainability: redacted input, intent, routing, agent path, tools used, citations, controls, QA and the run's audit trail |
| GET | `/v1/reviews/pending` | reviewer, supervisor | Review queue with `can_review` (four-eyes) |
| POST | `/v1/runs/{run_id}/review` | reviewer | Body: decision, `interrupt_id`, `action_hash`, comment. 403 self-approval, 409 stale/mismatch/double |
| GET | `/v1/ops/kpis` · POST `/v1/ops/staffing` · GET `/v1/ops/cases` | supervisor (auditor for cases) | |
| GET | `/v1/audit/runs/{id}` · `/v1/audit/verify` | auditor | |
| GET | `/healthz` · `/readyz` | — | Liveness / readiness (DB + audit chain) |

All public routes are served through the API gateway (`:8000` locally). The gateway adds
`X-Correlation-Id`, `X-Upstream` and `X-Gateway-Latency-Ms` to every response, and exposes
`/gateway/health` (public), `/gateway/routes` (public) and `/gateway/metrics` (supervisor or auditor).

Error contract: `{"error": "<code>", "message": "<text>"}` with codes `forbidden`, `four_eyes_violation`,
`review_mismatch`, `not_awaiting_review`, `conflict`, `review_pending`, `invalid_request`, `not_found`.
Every response carries `X-Correlation-Id`, propagated into the agent run, tool calls and audit records.

## 3.3 MCP tool catalogue

| Tool | Purpose of use | Min auth | Side effect | Extra controls |
|---|---|---|---|---|
| `search_knowledge` | servicing | 0 | none | Indirect-injection filter |
| `get_customer_profile` | servicing, card_servicing, dispute, complaint, fraud_referral | 1 | none | Customer from token; fields minimised by purpose |
| `list_recent_transactions` | servicing, dispute, fraud_referral | 1 | none | Max 25 rows |
| `create_case` | complaint, dispute, fraud_referral | — | creates case | Idempotency key; disputes above threshold need approval token |
| `lock_card` | card_servicing | 1 | changes card state | Approval token bound to run+action hash; four-eyes; idempotent |

Per-agent allow-lists (`AGENT_TOOL_ALLOWLIST`) enforce least privilege, e.g. `knowledge_agent` can only search.

## 3.4 Integration example talking points
* **Adding a new enterprise system** = new MCP tool with a declared purpose, min auth, allow-list entry,
  idempotency behaviour and audit event — reviewed once, reusable by every agent and channel.
* **Contract testing:** consumer-driven contracts (e.g. Pact) between the MCP server and each backend API;
  the MCP tool schemas are themselves versioned contracts for agents.
* **Versioning:** URL-versioned public API (`/v1`); MCP tool names stable, new behaviour → new tool or optional args.
* **Back-pressure:** APIM quotas per channel; circuit breakers per tool; HITL queue depth alerting.
