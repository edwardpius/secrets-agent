"""OpenTelemetry to the hub's Collector (Phoenix project `secrets-agent`).

On only when OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is set. Spans carry the tool name, a hashed
user id and OpenBao's status: never tokens, never secret values (spec 001 GUARD-02).
"""
from __future__ import annotations

import contextlib
import hashlib
import os
from typing import Iterator, Mapping

_tracer = None


def setup(service: str = "secrets-mcp") -> bool:
    global _tracer
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    if not endpoint:
        return False
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    provider = TracerProvider(resource=Resource.create({
        "service.name": service, "openinference.project.name": "secrets-agent"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("secrets_agent")
    return True


def user_hash(sub: str) -> str:
    return hashlib.sha256(sub.encode()).hexdigest()[:16]


@contextlib.contextmanager
def tool_span(name: str, headers: Mapping[str, str] | None) -> Iterator[object]:
    if _tracer is None:
        yield None
        return
    from opentelemetry import propagate
    ctx = propagate.extract({k.lower(): v for k, v in (headers or {}).items()
                             if k.lower() in ("traceparent", "tracestate")})
    with _tracer.start_as_current_span(f"tool {name}", context=ctx) as span:
        span.set_attribute("openinference.span.kind", "TOOL")
        span.set_attribute("tool.name", name)
        yield span
