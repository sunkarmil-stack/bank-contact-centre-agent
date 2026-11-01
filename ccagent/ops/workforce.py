"""Workforce management: Erlang C staffing calculator.

Used by contact-centre planners to size human staffing for the residual
(non-contained) volume after AI containment — e.g. "if the assistant contains
30% of card-status calls, how many agents does the 80/20 service level need?"
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass


def erlang_c(traffic_erlangs: float, agents: int) -> float:
    """Probability a contact waits (Erlang C)."""
    if agents <= traffic_erlangs:
        return 1.0
    # stable recursive Erlang B, then convert to C
    b = 1.0
    for n in range(1, agents + 1):
        b = traffic_erlangs * b / (n + traffic_erlangs * b)
    rho = traffic_erlangs / agents
    return b / (1 - rho + rho * b)


@dataclass
class StaffingResult:
    contacts_per_interval: float
    residual_contacts: float
    aht_s: float
    traffic_erlangs: float
    agents_required: int
    agents_with_shrinkage: int
    service_level: float
    asa_s: float
    occupancy: float


def required_agents(
    contacts_per_interval: float,
    aht_s: float,
    *,
    interval_s: int = 1800,
    target_service_level: float = 0.80,
    target_answer_s: int = 20,
    max_occupancy: float = 0.85,
    shrinkage: float = 0.30,
    ai_containment_rate: float = 0.0,
) -> dict:
    residual = contacts_per_interval * (1 - ai_containment_rate)
    a = residual * aht_s / interval_s
    n = max(1, math.ceil(a))
    while True:
        pw = erlang_c(a, n)
        sl = 1 - pw * math.exp(-(n - a) * target_answer_s / aht_s) if n > a else 0.0
        occ = a / n if n else 1.0
        if sl >= target_service_level and occ <= max_occupancy:
            break
        n += 1
    asa = pw * aht_s / (n - a) if n > a else float("inf")
    return asdict(
        StaffingResult(
            contacts_per_interval=contacts_per_interval,
            residual_contacts=round(residual, 1),
            aht_s=aht_s,
            traffic_erlangs=round(a, 2),
            agents_required=n,
            agents_with_shrinkage=math.ceil(n / (1 - shrinkage)),
            service_level=round(sl, 4),
            asa_s=round(asa, 1),
            occupancy=round(occ, 4),
        )
    )
