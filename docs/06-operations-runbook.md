# 06 — Operations Runbook, Troubleshooting & RCA

## 6.1 SLOs and signals

| SLO | Target | Signal |
|---|---|---|
| API availability | 99.9% | `/readyz`, HTTP 5xx rate |
| Turn latency | p95 ≤ 5 s | `turn_latency_s`, `llm_latency_s.*`, `tool_latency_s.*` |
| Fallback rate | < 5% of turns | `fallbacks_total`, KPI `fallback_rate` |
| Review wait | 95% < 2 min | `awaiting_review`, `waiting_s` in queue |
| Audit integrity | 100% | `/v1/audit/verify` (scheduled) |

Every request has an `X-Correlation-Id`; search logs, traces and audit records by it.

## 6.2 Playbooks

**A. Fallback rate spike.** Check `llm_output_invalid_total` (model format drift after a deployment change?),
`llm_latency_s` (throttling → check Azure OpenAI quota / PTU utilisation), circuit-breaker state per tool.
Mitigate: roll back model deployment/prompt version; raise quota; disable affected intent flag.

**B. Search failures / no grounding.** Symptom: many `no_grounding` escalations. Check AI Search health,
managed-identity role assignment, index name, private endpoint DNS. Mitigate: fail over to secondary index/region.

**C. Reviews stuck in `awaiting_review`.** Check reviewer staffing (Erlang C with review volume), Entra group
membership for reviewers, `409 conflict` errors (double clicks — expected), runs whose checkpoint is missing
(DB restore?). Paused runs resume on any worker; no restart needed.

**D. Prompt-injection spike.** `guardrail_blocks_total{stage=input}` up. Review blocked samples (redacted) in audit;
coordinate with InfoSec; consider Prompt Shields strictness; check for a coordinated campaign by channel.

**E. Audit chain verification fails.** Sev1 security incident: freeze writes, preserve DB snapshot, compare with WORM
archive to locate the altered record (`broken_at_seq`), engage SecOps.

**F. Duplicate case / card action reported.** Check idempotency key in audit for the run; verify CRM honours
`Idempotency-Key`; look for retries without keys (should be impossible — `KEYED_TOOLS`).

**G. Customer data shown to wrong caller.** Sev1 privacy incident: check `data_access_granted` events for the
run (customer_ref vs session), CCaaS session binding, token claims. Notify Privacy per incident process.

## 6.3 Root-cause analysis template
1. **Impact:** who/what/how long; customer harm; regulatory reportability.
2. **Timeline:** detection → mitigation → resolution (UTC), with correlation ids.
3. **What happened:** facts from logs, traces, audit.
4. **Why (5 Whys):** continue until a process or design cause is found.
5. **Contributing factors (fishbone):** people, process, technology, data, third party.
6. **Corrective actions:** immediate fix, preventive control, detective control — each with owner and date.
7. **Evaluation update:** add the failing scenario to `evals/golden_dataset.jsonl` so it can never regress.

### Worked example (synthetic)
*Symptom:* fallback rate rose from 2% to 18% after a release. *Why 1:* responder outputs failed schema validation.
*Why 2:* the new model deployment wrapped JSON in markdown fences. *Why 3:* response-format setting not applied to
the new deployment. *Why 4:* deployment config not part of the eval-gated release. *Root cause:* model deployment
changes bypassed the release gate. *Actions:* `_extract_json` tolerates fences (fix); model deployment changes now
run `evals.run_eval` against the real model in CI (preventive); alert on `llm_output_invalid_total` (detective).
