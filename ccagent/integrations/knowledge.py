"""Knowledge retrieval (the "R" in RAG) as LangChain retrievers.

* ``LocalBM25Retriever`` — offline, deterministic, over the synthetic KB.
* ``AzureAISearchRetriever`` — production: Azure AI Search hybrid query
  (BM25 + vector via integrated vectorisation) with semantic ranking and
  security trimming by audience/classification. Authenticated with managed
  identity (Entra ID), reached over a private endpoint.

Both return ``langchain_core.documents.Document`` with ``doc_id``, ``title``,
``effective_date``, ``owner`` and ``score`` metadata, so the agent can cite
sources and the output guard can verify citations.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from langchain_core.callbacks import AsyncCallbackManagerForRetrieverRun, CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from typing import ClassVar

from pydantic import ConfigDict, PrivateAttr

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = set("a an the and or of to for in on is are be by with your you my i it this that can do does how what when".split())


def _tokens(text: str) -> list[str]:
    toks = [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]
    # light stemming so "disputing"/"dispute", "stolen"/"steal" match
    return [re.sub(r"(ing|ed|es|s)$", "", t) if len(t) > 4 else t for t in toks]


class LocalBM25Retriever(BaseRetriever):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    backend_name: ClassVar[str] = "knowledge index (local)"

    kb_path: Path
    k: int = 4
    audience: str = "agent"
    min_score: float = 0.5
    _docs: list[dict] = PrivateAttr(default_factory=list)
    _tf: list[Counter] = PrivateAttr(default_factory=list)
    _df: Counter = PrivateAttr(default_factory=Counter)
    _avgdl: float = PrivateAttr(default=1.0)

    def model_post_init(self, __context) -> None:
        raw = json.loads(Path(self.kb_path).read_text())
        self._docs = raw["documents"]
        for d in self._docs:
            tf = Counter(_tokens(d["title"] + " " + d["title"] + " " + d["content"]))
            self._tf.append(tf)
            self._df.update(tf.keys())
        self._avgdl = sum(sum(tf.values()) for tf in self._tf) / max(1, len(self._tf))

    def _score(self, query: str) -> list[tuple[float, dict]]:
        q = _tokens(query)
        n = len(self._docs)
        k1, b = 1.5, 0.75
        out = []
        for d, tf in zip(self._docs, self._tf):
            if self.audience not in d.get("audience", []):
                continue  # security trimming
            dl = sum(tf.values())
            s = 0.0
            for t in q:
                if t not in tf:
                    continue
                idf = math.log(1 + (n - self._df[t] + 0.5) / (self._df[t] + 0.5))
                s += idf * tf[t] * (k1 + 1) / (tf[t] + k1 * (1 - b + b * dl / self._avgdl))
            if s >= self.min_score:
                out.append((s, d))
        out.sort(key=lambda x: x[0], reverse=True)
        return out[: self.k]

    def _get_relevant_documents(self, query: str, *, run_manager: CallbackManagerForRetrieverRun) -> list[Document]:
        return [
            Document(
                page_content=d["content"],
                metadata={k: d[k] for k in ("doc_id", "title", "owner", "effective_date", "classification")}
                | {"score": round(s, 3), "source": "local-kb"},
            )
            for s, d in self._score(query)
        ]

    async def _aget_relevant_documents(
        self, query: str, *, run_manager: AsyncCallbackManagerForRetrieverRun
    ) -> list[Document]:
        return self._get_relevant_documents(query, run_manager=run_manager.get_sync())  # type: ignore[arg-type]


class AzureAISearchRetriever(BaseRetriever):
    """Hybrid + semantic retrieval from an Azure AI Search index.

    Expected index fields: id, title, content, owner, effective_date,
    classification, audience (Collection(Edm.String)), content_vector.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)
    backend_name: ClassVar[str] = "Azure AI Search"

    endpoint: str
    index: str
    k: int = 4
    audience: str = "agent"
    semantic_config: str | None = "default"
    api_version: str = "2024-07-01"
    timeout_s: float = 5.0

    def _body(self, query: str) -> dict:
        body = {
            "search": query,
            "top": self.k,
            "select": "id,title,content,owner,effective_date,classification",
            "filter": f"audience/any(a: a eq '{self.audience}') and classification ne 'restricted'",
            "vectorQueries": [{"kind": "text", "text": query, "fields": "content_vector", "k": 50}],
        }
        if self.semantic_config:
            body |= {"queryType": "semantic", "semanticConfiguration": self.semantic_config}
        return body

    async def _token(self) -> str:
        from azure.identity.aio import DefaultAzureCredential

        async with DefaultAzureCredential() as cred:
            return (await cred.get_token("https://search.azure.com/.default")).token

    def _to_docs(self, payload: dict) -> list[Document]:
        docs = []
        for v in payload.get("value", []):
            docs.append(
                Document(
                    page_content=v["content"],
                    metadata={
                        "doc_id": v["id"],
                        "title": v.get("title", ""),
                        "owner": v.get("owner", ""),
                        "effective_date": v.get("effective_date", ""),
                        "classification": v.get("classification", ""),
                        "score": v.get("@search.rerankerScore") or v.get("@search.score"),
                        "source": "azure-ai-search",
                    },
                )
            )
        return docs

    async def _aget_relevant_documents(
        self, query: str, *, run_manager: AsyncCallbackManagerForRetrieverRun
    ) -> list[Document]:
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            r = await client.post(
                f"{self.endpoint.rstrip('/')}/indexes/{self.index}/docs/search",
                params={"api-version": self.api_version},
                headers={"Authorization": f"Bearer {await self._token()}"},
                json=self._body(query),
            )
            r.raise_for_status()
            return self._to_docs(r.json())

    def _get_relevant_documents(self, query: str, *, run_manager: CallbackManagerForRetrieverRun) -> list[Document]:
        import asyncio

        return asyncio.run(self._aget_relevant_documents(query, run_manager=None))  # type: ignore[arg-type]


def docs_to_chunks(docs: list[Document]) -> list[dict]:
    return [
        {
            "doc_id": d.metadata["doc_id"],
            "title": d.metadata.get("title", ""),
            "content": d.page_content,
            "score": d.metadata.get("score"),
            "effective_date": d.metadata.get("effective_date"),
        }
        for d in docs
    ]
