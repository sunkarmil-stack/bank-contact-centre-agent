"""Run the golden dataset as a LangSmith experiment (regression tracking over
prompt / model / code versions).

    export LANGSMITH_API_KEY=...  LANGSMITH_TRACING=true
    python -m evals.langsmith_eval

Data sent to LangSmith is synthetic and additionally passes through the PII
anonymiser. For a bank deployment use a self-hosted / data-residency LangSmith
instance (LANGSMITH_ENDPOINT) approved by the privacy office.
"""

from __future__ import annotations

import asyncio
import dataclasses
import tempfile
from pathlib import Path

from langsmith import aevaluate

from ccagent.config import Settings
from ccagent.container import build_container
from ccagent.service import ContactCentreService
from ccagent.telemetry import langsmith_client

from .run_eval import load_cases, run_case

DATASET = "ccagent-golden-v1"


def ensure_dataset(client) -> None:
    if client.has_dataset(dataset_name=DATASET):
        return
    ds = client.create_dataset(DATASET, description="Contact-centre golden cases (synthetic)")
    client.create_examples(
        dataset_id=ds.id,
        examples=[{"inputs": {"case": c}, "outputs": c["expect"]} for c in load_cases()],
    )


async def target(inputs: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        s = dataclasses.replace(Settings.from_env(), env="test", data_dir=Path(tmp), sqlite_path=f"{tmp}/e.db")
        async with build_container(s) as c:
            r = await run_case(ContactCentreService(c), c, inputs["case"])
    o = r["out"]
    return {"intent": o.get("intent") or r["first_intent"], "trace": (o.get("trace") or []) + r["first_trace"],
            "reviewed": r["reviewed"], "citations": o.get("citations") or [], "escalation": o.get("escalation"),
            "response": o.get("response") or ""}


def intent_correct(outputs: dict, reference_outputs: dict) -> dict:
    if reference_outputs.get("blocked"):
        return {"key": "intent_correct", "score": outputs["intent"] == "blocked"}
    return {"key": "intent_correct", "score": outputs["intent"] == reference_outputs.get("intent")}


def routed_correctly(outputs: dict, reference_outputs: dict) -> dict:
    node = reference_outputs.get("node")
    return {"key": "routed_correctly", "score": True if not node else node in outputs["trace"]}


def hitl_correct(outputs: dict, reference_outputs: dict) -> dict:
    return {"key": "hitl_correct", "score": outputs["reviewed"] == bool(reference_outputs.get("review", False))}


def grounded(outputs: dict, reference_outputs: dict) -> dict:
    need = set(reference_outputs.get("citations_include", []))
    return {"key": "grounded", "score": need <= set(outputs["citations"])}


async def main() -> None:
    client = langsmith_client()
    ensure_dataset(client)
    await aevaluate(
        target,
        data=DATASET,
        evaluators=[intent_correct, routed_correctly, hitl_correct, grounded],
        experiment_prefix="ccagent",
        max_concurrency=4,
        client=client,
        metadata={"prompt_version": __import__("ccagent.llm.prompts", fromlist=["x"]).PROMPT_VERSION},
    )


if __name__ == "__main__":
    asyncio.run(main())
