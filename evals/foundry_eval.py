"""Model-graded evaluation with Microsoft Foundry (``azure-ai-evaluation``):
groundedness, relevance and coherence of knowledge answers, with results
logged to the Foundry project for model-risk review.

    pip install azure-ai-evaluation
    export AZURE_AI_FOUNDRY_PROJECT_ENDPOINT=... AZURE_OPENAI_ENDPOINT=... AZURE_OPENAI_DEPLOYMENT=...
    python -m evals.foundry_eval

Requires Azure access; not part of the offline CI gate.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import tempfile
from pathlib import Path

from ccagent.config import Settings
from ccagent.container import build_container
from ccagent.service import ContactCentreService

from .run_eval import load_cases, run_case

HERE = Path(__file__).resolve().parent


async def build_rows() -> list[dict]:
    rows = []
    for case in [c for c in load_cases() if c["expect"].get("citations_include")]:
        with tempfile.TemporaryDirectory() as tmp:
            s = dataclasses.replace(Settings.from_env(), env="test", data_dir=Path(tmp), sqlite_path=f"{tmp}/e.db")
            async with build_container(s) as c:
                r = await run_case(ContactCentreService(c), c, case)
                docs = await c.retriever.ainvoke(case["message"])
        rows.append({"query": case["message"], "response": r["out"].get("response", ""),
                     "context": "\n\n".join(d.page_content for d in docs)})
    return rows


def main() -> None:
    from azure.ai.evaluation import (
        AzureOpenAIModelConfiguration,
        CoherenceEvaluator,
        GroundednessEvaluator,
        RelevanceEvaluator,
        evaluate,
    )

    rows = asyncio.run(build_rows())
    data = HERE / "reports" / "foundry_input.jsonl"
    data.parent.mkdir(exist_ok=True)
    data.write_text("\n".join(json.dumps(r) for r in rows))
    judge = AzureOpenAIModelConfiguration(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        azure_deployment=os.environ.get("AZURE_OPENAI_JUDGE_DEPLOYMENT", os.environ["AZURE_OPENAI_DEPLOYMENT"]),
        api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
    )
    result = evaluate(
        data=str(data),
        evaluators={
            "groundedness": GroundednessEvaluator(judge),
            "relevance": RelevanceEvaluator(judge),
            "coherence": CoherenceEvaluator(judge),
        },
        azure_ai_project=os.environ["AZURE_AI_FOUNDRY_PROJECT_ENDPOINT"],
        evaluation_name="ccagent-knowledge-answers",
        output_path=str(HERE / "reports" / "foundry_eval.json"),
    )
    print(json.dumps(result.get("metrics", {}), indent=2))


if __name__ == "__main__":
    main()
