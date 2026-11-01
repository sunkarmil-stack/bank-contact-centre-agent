from ccagent.ops.qa import score_interaction
from ccagent.ops.routing import route_for
from ccagent.ops.workforce import erlang_c, required_agents


def test_erlang_c_reference_value():
    # 10 Erlangs on 11 agents: P(wait) ≈ 0.682 (standard Erlang C table)
    assert abs(erlang_c(10, 11) - 0.682) < 0.01


def test_staffing_meets_service_level_and_containment_reduces_staff():
    base = required_agents(200, 300)
    with_ai = required_agents(200, 300, ai_containment_rate=0.3)
    assert base["service_level"] >= 0.8 and base["occupancy"] <= 0.85
    assert with_ai["agents_required"] < base["agents_required"]
    assert base["agents_with_shrinkage"] > base["agents_required"]


def test_routing_rules():
    assert route_for("fraud_report").priority == "P1"
    assert route_for("product_question", vulnerability=True).queue == "CLIENT_CARE_SPECIALIST"
    assert route_for("product_question", sentiment="negative").priority == "P2"


def test_qa_penalises_disclosure_without_verification():
    good = score_interaction({"intent": "account_inquiry", "account_data_disclosed": True, "cust_auth_level": 1,
                              "resolved": True, "final_response": "Your balance is..."})
    bad = score_interaction({"intent": "account_inquiry", "account_data_disclosed": True, "cust_auth_level": 0,
                             "resolved": True, "final_response": "Your balance is..."})
    assert good["score"] == 100 and bad["score"] < 80 and bad["needs_human_qa"]
