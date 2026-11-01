"""Observability: OpenTelemetry + OpenInference + LangSmith.

* OpenTelemetry traces/metrics for every request, agent node, tool call and
  retrieval. Exporters: console | OTLP (collector → Azure Monitor / Grafana /
  Arize Phoenix) | Azure Monitor (connection string discovered from the
  Microsoft Foundry project).
* OpenInference semantic conventions (``openinference.span.kind`` = AGENT, TOOL,
  RETRIEVER, LLM, GUARDRAIL, CHAIN, EVALUATOR) so LLM-aware backends render
  the agent trace tree. ``LangChainInstrumentor`` auto-instruments LangChain /
  LangGraph model and tool calls.
* LangSmith tracing (``LANGSMITH_TRACING=true``) with a PII anonymizer so no
  raw customer data leaves the bank's boundary.

All span attributes are PII-redacted before being set.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter, defaultdict
from contextlib import contextmanager

from opentelemetry import trace

from .config import Settings
from .security.pii import redact_obj

log = logging.getLogger("ccagent.telemetry")
_tracer = trace.get_tracer("ccagent")


class SpanKind:
    AGENT = "AGENT"
    CHAIN = "CHAIN"
    TOOL = "TOOL"
    RETRIEVER = "RETRIEVER"
    LLM = "LLM"
    GUARDRAIL = "GUARDRAIL"
    EVALUATOR = "EVALUATOR"


@contextmanager
def span(name: str, kind: str = SpanKind.CHAIN, **attributes):
    with _tracer.start_as_current_span(name) as s:
        s.set_attribute("openinference.span.kind", kind)
        for k, v in redact_obj(attributes).items():
            if v is None:
                continue
            s.set_attribute(k, v if isinstance(v, (str, bool, int, float)) else str(v))
        yield s


class Metrics:
    """Process-local counters for /v1/ops endpoints, mirrored to OTel meters when
    the SDK is installed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: Counter[str] = Counter()
        self.histograms: dict[str, list[float]] = defaultdict(list)
        self._otel_counters: dict = {}
        try:
            from opentelemetry import metrics

            self._meter = metrics.get_meter("ccagent")
        except Exception:  # pragma: no cover
            self._meter = None

    def inc(self, name: str, value: int = 1, **labels) -> None:
        key = name + "".join(f"|{k}={v}" for k, v in sorted(labels.items()))
        with self._lock:
            self.counters[key] += value
        if self._meter is not None:
            c = self._otel_counters.get(name)
            if c is None:
                c = self._otel_counters[name] = self._meter.create_counter(name)
            c.add(value, {k: str(v) for k, v in labels.items()})

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self.histograms[name].append(value)
            if len(self.histograms[name]) > 5000:
                self.histograms[name] = self.histograms[name][-5000:]

    def snapshot(self) -> dict:
        with self._lock:
            hist = {
                k: {"count": len(v), "p50": _pct(v, 50), "p95": _pct(v, 95)} for k, v in self.histograms.items() if v
            }
            return {"counters": dict(self.counters), "latency": hist}


def _pct(values: list[float], p: int) -> float:
    s = sorted(values)
    idx = min(len(s) - 1, max(0, round(p / 100 * (len(s) - 1))))
    return round(s[idx], 4)


METRICS = Metrics()


def setup_telemetry(settings: Settings, foundry_connection_string: str | None = None) -> None:
    """Configure OTel SDK + OpenInference if the optional packages are installed."""
    if settings.otel_exporter == "none":
        return
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    except ImportError:
        log.warning("opentelemetry-sdk not installed; telemetry export disabled")
        return

    provider = TracerProvider(resource=Resource.create({"service.name": settings.otel_service_name}))
    if settings.otel_exporter == "console":
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    elif settings.otel_exporter == "otlp":
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))  # OTEL_EXPORTER_OTLP_ENDPOINT
    elif settings.otel_exporter == "azure_monitor":
        from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter

        provider.add_span_processor(
            BatchSpanProcessor(AzureMonitorTraceExporter(connection_string=foundry_connection_string))
        )
    trace.set_tracer_provider(provider)

    try:
        from openinference.instrumentation.langchain import LangChainInstrumentor

        LangChainInstrumentor().instrument(tracer_provider=provider)
        log.info("OpenInference LangChain instrumentation enabled")
    except ImportError:
        log.warning("openinference-instrumentation-langchain not installed")


def langsmith_client():
    """LangSmith client that anonymizes PII in every traced payload."""
    try:
        from langsmith import Client
        from langsmith.anonymizer import create_anonymizer
    except ImportError:  # pragma: no cover
        return None
    from .security.pii import redact

    return Client(anonymizer=create_anonymizer(lambda text, _path: redact(text)[0]))
