"""Skills-based routing & priority rules (contact-centre operations policy).

Business-owned configuration: changes go through the contact-centre
operations change process, not code reviews alone.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QueueRoute:
    queue: str
    skill: str
    priority: str          # P1 highest
    answer_sla_s: int      # target speed of answer for a warm transfer
    case_sla_hours: int    # back-office SLA when a case is created


ROUTES: dict[str, QueueRoute] = {
    "fraud_report": QueueRoute("FRAUD_PRIORITY", "fraud", "P1", 30, 4),
    "card_lost_stolen": QueueRoute("CARD_SERVICES", "cards", "P1", 60, 24),
    "vulnerable_support": QueueRoute("CLIENT_CARE_SPECIALIST", "vulnerable_clients", "P1", 60, 24),
    "transaction_dispute": QueueRoute("CARD_DISPUTES", "disputes", "P2", 120, 72),
    "complaint": QueueRoute("CLIENT_CARE_COMPLAINTS", "complaints", "P2", 120, 48),
    "account_inquiry": QueueRoute("GENERAL_BANKING", "general", "P3", 180, 72),
    "product_question": QueueRoute("GENERAL_BANKING", "general", "P3", 180, 72),
    "human_agent_request": QueueRoute("GENERAL_BANKING", "general", "P3", 180, 72),
    "general": QueueRoute("GENERAL_BANKING", "general", "P3", 180, 72),
}


def route_for(intent: str, *, sentiment: str = "neutral", vulnerability: bool = False) -> QueueRoute:
    route = ROUTES.get(intent, ROUTES["general"])
    if vulnerability and route.priority != "P1":
        return ROUTES["vulnerable_support"]
    if sentiment == "negative" and route.priority == "P3":
        return QueueRoute(route.queue, route.skill, "P2", route.answer_sla_s // 2, route.case_sla_hours)
    return route
