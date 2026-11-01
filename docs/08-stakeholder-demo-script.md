# 08 — Stakeholder demo script (about 12 minutes)

Two ways to run it:
* **Shared link (no setup):** the published demo page replays real runs recorded from the agent service.
  Rebuild it with `python -m scripts.record_demo && python -m scripts.build_demo_page`.
* **Live, full architecture:** `python -m scripts.run_all`, then open `http://127.0.0.1:8000/console`
  (the console goes through the API gateway). Same screens, plus you can type your own caller questions.

| Minute | Screen | Click | What to say | Audience it lands with |
|---|---|---|---|---|
| 0–1 | Call desk | (page opens on "Lost credit card") | "This is one call. Left: what the caller hears. Right: what the AI decided and why, every step." | Everyone |
| 1–3 | Call desk → Behind the scenes | Point at Agent path, Systems used | "The orchestrator understood a lost card with 97% confidence and sent it to the card agent. It looked up the profile through a governed tool, with a declared purpose. It proposed a lock and stopped. It cannot lock a card on its own." | Ops, Risk |
| 3–4 | Architecture | Keep "Lost credit card" selected | "Here's the same call across the platform: the gateway checked the sign-in, the agent API ran the card agent, and the MCP tool service is the only way the agents reach business systems. The customer service re-checks everything itself. Every service writes to one tamper-evident audit trail." | Architecture, InfoSec |
| 4–5 | Review queue | "Try approving as the requester", then Approve | "The system that asked for the action is refused. A second person approves, and the approval is tied to this call and this exact action. Then the call resumes and the card is locked." | Compliance, Operational risk |
| 5–6 | Call desk | "Caller reads out card number" | "The card number and email are removed before the AI sees them. Look at 'What the AI received'." | Privacy, InfoSec |
| 6–7 | Call desk | "Prompt injection attempt" | "Someone tries to talk the AI into approving itself. Blocked before the model, and logged." | InfoSec, Model risk |
| 7–8 | Call desk | "Complaint", then "Suspected scam" | "Every complaint becomes a case with a reference and a 48-hour acknowledgement. Fraud goes straight to the fraud team as P1 with a referral case. The AI does not investigate." | Client Care, Fraud |
| 8–10 | Supervisor | Move the "Calls fully handled by the AI" slider | "Containment, transfers, approvals and QA for a shift. The staffing what-if uses Erlang C: at 25% containment we need fewer agents for the same service level. We prove the containment number in the pilot before anyone plans on it." | Contact centre leadership, Finance |
| 10–12 | Audit & controls | Pick the lost-card call | "Every access, approval and action is recorded, chained so that edits are detectable. The controls table maps to PIPEDA, FCAC complaint handling and OSFI E-23 / B-13." | Audit, Model risk |

**Close:** "Next step is a pilot in agent-assist mode for one team, measured against these KPIs, with Model Risk validating the evaluation results before any self-service."

**Optional resilience moment (live only):** stop the customer service (`docker compose stop customer`; with `run_all`, end the process on port 8101:
`lsof -ti:8101 | xargs kill` on Mac/Linux, or Resource Monitor → Network → port 8101 on Windows),
then ask "What's my balance?". The assistant hands the caller to a colleague and shares no data, while
policy questions keep working. The Architecture tab shows the service as down.

**Be upfront if asked:** the recorded runs use a deterministic offline model so results are repeatable. The same release gate runs against the Azure OpenAI model in Microsoft Foundry before any real use. All clients and data are synthetic.
