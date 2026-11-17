"""Spec 002: create_secret (REQ-02..07, GUARD-01..03, EVAL-01..04), offline."""
from __future__ import annotations

import json
import logging
import re
import uuid

import pytest

from secrets_agent import otel
from secrets_agent.create import CREATE_SECRET, PLACEHOLDER, credential_like
from secrets_agent.tools import ANNOTATIONS, TOOLS

WRITER = ("openbao-secrets-writers", "openbao-secrets-readers")
ADMIN = ("openbao-admins",)
READER = ("openbao-secrets-readers",)
ENGINEER = ("openbao-engineers",)


def request(**over):
    args = {
        "product": "payments", "service": "checkout-api", "environment": "dev",
        "description": "Database credentials for the checkout API",
        "team": "platform", "jira_ticket": "PAY-1234",
        "keys": [{"name": "DB_PASSWORD", "source": "generate", "kind": "password"},
                 {"name": "DB_USER", "source": "ui"}],
        "sync_aws": True,
    }
    args.update(over)
    return args


def create(svc, cognito, groups=WRITER, email="dev@example.com", **over):
    token = cognito.token(groups=groups, email=email)
    return svc.call("create_secret", request(**over), {"authorization": f"Bearer {token}"})


def writes(bao):
    return [c for c in bao.calls if c[0] == "POST" and c[1].startswith("/v1/apps/")]


# ------------------------------------------------------------------ EVAL-01 / EVAL-02
@pytest.mark.parametrize("env", ["dev", "staging"])
def test_eval01_writer_creates_dev_and_staging(service, cognito, bao, env):
    text, err = create(service, cognito, environment=env)
    assert not err, text
    out = json.loads(text)
    assert out["created"] == f"apps/payments/checkout-api/{env}"
    assert f"payments/checkout-api/{env}" in bao.data


def test_eval01_writer_refused_prod_with_group_named(service, cognito, bao):
    text, err = create(service, cognito, environment="prod")
    assert err and "403" in text and "openbao-admins" in text
    assert bao.data == {} and bao.metadata == {}


def test_eval02_admin_creates_prod(service, cognito, bao):
    text, err = create(service, cognito, groups=ADMIN, environment="prod")
    assert not err, text
    assert "payments/checkout-api/prod" in bao.data


@pytest.mark.parametrize("groups", [READER, ENGINEER])
@pytest.mark.parametrize("env", ["dev", "staging", "prod"])
def test_eval02_reader_and_others_refused_everywhere(service, cognito, bao, groups, env):
    text, err = create(service, cognito, groups=groups, environment=env)
    assert err and "403" in text and "openbao-" in text
    assert bao.data == {} and bao.metadata == {}


# ------------------------------------------------------------------ REQ-03 / REQ-04 / REQ-05
def test_req03_data_first_then_metadata_with_cas0(service, cognito, bao):
    create(service, cognito)
    posts = writes(bao)
    assert [p[1] for p in posts] == ["/v1/apps/data/payments/checkout-api/dev",
                                     "/v1/apps/metadata/payments/checkout-api/dev"]
    assert json.loads(bao.bodies[0])["options"] == {"cas": 0}
    assert set(json.loads(bao.bodies[1])) == {"custom_metadata"}


def test_req03_metadata_content_and_created_by_from_token(service, cognito, bao):
    create(service, cognito, email="alice@example.com")
    assert bao.metadata["payments/checkout-api/dev"] == {
        "description": "Database credentials for the checkout API",
        "team": "platform", "jira_ticket": "PAY-1234", "created_by": "alice@example.com",
        "sync_aws": "true", "aws_secret_name": "openbao/payments/checkout-api/dev",
        "schema": "1", "key.DB_PASSWORD": "generated:password", "key.DB_USER": "pending-ui"}


def test_req03_created_by_cannot_be_passed_in(service, cognito, bao):
    text, err = create(service, cognito, created_by="someone@else.com")
    assert err and "unknown fields" in text and writes(bao) == []


@pytest.mark.parametrize("kind,check", [
    ("password", lambda v: len(v) == 32 and any(c.isupper() for c in v)
     and any(c.islower() for c in v) and any(c.isdigit() for c in v)),
    ("hex", lambda v: re.fullmatch(r"[0-9a-f]{64}", v)),
    ("uuid", lambda v: uuid.UUID(v).version == 4),
])
def test_req04_generated_kinds(service, cognito, bao, kind, check):
    text, err = create(service, cognito, keys=[{"name": "K", "source": "generate", "kind": kind}])
    assert not err, text
    assert check(bao.data["payments/checkout-api/dev"]["K"])
    assert json.loads(text)["keys"] == [{"name": "K", "set": f"generated ({kind})"}]


def test_req04_kind_defaults_to_password(service, cognito, bao):
    create(service, cognito, keys=[{"name": "K", "source": "generate"}])
    assert len(bao.data["payments/checkout-api/dev"]["K"]) == 32


def test_req05_ui_placeholder_and_links(service, cognito, bao):
    out = json.loads(create(service, cognito)[0])
    assert bao.data["payments/checkout-api/dev"]["DB_USER"] == PLACEHOLDER
    assert out["ui_link"] == "https://openbao.example.com/ui/vault/secrets/apps/show/payments/checkout-api/dev"
    assert out["set_values_here"] == "https://openbao.example.com/ui/vault/secrets/apps/edit/payments/checkout-api/dev"
    assert "DB_USER" in out["note"] and "AWS sync waits" in out["note"]


# ------------------------------------------------------------------ REQ-07 / EVAL-03
def test_eval03_existing_path_refused_unchanged(service, cognito, bao):
    assert not create(service, cognito, email="alice@example.com")[1]
    before = json.dumps(bao.data, sort_keys=True), json.dumps(bao.metadata, sort_keys=True)
    n = len(writes(bao))
    text, err = create(service, cognito, email="bob@example.com", jira_ticket="PAY-9")
    assert err
    assert "already exists, created by alice@example.com for PAY-1234" in text
    assert (json.dumps(bao.data, sort_keys=True), json.dumps(bao.metadata, sort_keys=True)) == before
    assert len(writes(bao)) == n                  # not even attempted


def test_req07_existing_data_without_metadata_still_refused(service, cognito, bao):
    bao.data["payments/checkout-api/dev"] = {"X": "old"}
    text, err = create(service, cognito)
    assert err and "already exists" in text
    assert bao.data["payments/checkout-api/dev"] == {"X": "old"}


def test_metadata_failure_reported_as_partial(service, cognito, bao):
    bao.fail_metadata_write = True
    text, err = create(service, cognito)
    assert err and "was created, but its metadata could not be written" in text
    assert "Don't create it again" in text


# ------------------------------------------------------------------ REQ-02 validation
@pytest.mark.parametrize("over,field", [
    ({"product": "Payments"}, "product"),
    ({"service": "x"}, "service"),
    ({"environment": "qa"}, "environment"),
    ({"description": "short"}, "description"),
    ({"team": "Platform Team"}, "team"),
    ({"jira_ticket": "pay-12"}, "jira_ticket"),
    ({"keys": []}, "keys"),
    ({"keys": [{"name": "1BAD", "source": "ui"}]}, "keys[0].name"),
    ({"keys": [{"name": "A", "source": "ui"}, {"name": "A", "source": "ui"}]}, "appears twice"),
    ({"keys": [{"name": "A", "source": "typed"}]}, "keys[0].source"),
    ({"keys": [{"name": "A", "source": "generate", "kind": "rsa"}]}, "keys[0].kind"),
    ({"keys": [{"name": "A", "source": "ui", "kind": "hex"}]}, "only for source"),
    ({"aws_secret_name": "prod/payments"}, "aws_secret_name"),
    ({"aws_secret_name": "openbao/../x"}, "aws_secret_name"),
    ({"sync_aws": False, "aws_secret_name": "openbao/x"}, "only when sync_aws"),
    ({"sync_aws": "yes"}, "sync_aws"),
])
def test_req02_validation_names_field_with_example(service, cognito, bao, over, field):
    text, err = create(service, cognito, **over)
    assert err and "nothing was written" in text and field in text
    assert bao.calls == []                       # refused before the OpenBao login


def test_req02_aws_name_default_and_custom(service, cognito, bao):
    out = json.loads(create(service, cognito)[0])
    assert out["aws_secret_name"] == "openbao/payments/checkout-api/dev"
    out = json.loads(create(service, cognito, service="billing",
                            aws_secret_name="openbao/custom/name")[0])
    assert out["aws_secret_name"] == "openbao/custom/name"
    out = json.loads(create(service, cognito, service="orders", sync_aws=False)[0])
    assert out["aws_secret_name"] is None
    assert bao.metadata["payments/orders/dev"]["sync_aws"] == "false"


# ------------------------------------------------------------------ GUARD-01
def _walk(schema, path="$"):
    yield path, schema
    for name, sub in (schema.get("properties") or {}).items():
        yield from _walk(sub, f"{path}.{name}")
    if isinstance(schema.get("items"), dict):
        yield from _walk(schema["items"], f"{path}[]")


def test_guard01_schema_has_no_value_field():
    for path, node in _walk(CREATE_SECRET["input_schema"]):
        name = path.rsplit(".", 1)[-1].rstrip("[]").lower()
        # A field meant to carry a value, by any common name (whole name or *_value).
        assert not re.fullmatch(r"(value|values|secret|secrets|secret_value|password|"
                                r"token|data|content|plaintext|.*_value)", name), path
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, path


def test_guard01_value_field_refused_by_server(service, cognito, bao):
    keys = [{"name": "DB_PASSWORD", "source": "generate", "value": "hunter2hunter2"}]
    text, err = create(service, cognito, keys=keys)
    assert err and "unknown fields" in text and writes(bao) == []


def test_create_is_a_write_in_annotations():
    assert ANNOTATIONS["create_secret"]["read_only_hint"] is False
    assert {t["name"] for t in TOOLS} == set(ANNOTATIONS)


# ------------------------------------------------------------------ GUARD-02
def test_guard02_values_never_in_output_logs_or_spans(service, cognito, bao, caplog):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    saved, otel._tracer = otel._tracer, provider.get_tracer("test")
    caplog.set_level(logging.DEBUG)
    try:
        keys = [{"name": n, "source": "generate", "kind": k}
                for n, k in (("P", "password"), ("H", "hex"), ("U", "uuid"))]
        text, err = create(service, cognito, keys=keys)
        assert not err, text
        # and a refusal path, which also logs and sets span attributes
        create(service, cognito, keys=keys)
    finally:
        otel._tracer = saved
    values = list(bao.data["payments/checkout-api/dev"].values())
    assert len(values) == 3
    spans = json.dumps([{"name": s.name, "attrs": dict(s.attributes or {}),
                         "events": [dict(e.attributes or {}) for e in s.events]}
                        for s in exporter.get_finished_spans()])
    assert exporter.get_finished_spans()
    for v in values:
        assert v not in text
        assert v not in caplog.text
        assert v not in spans


# ------------------------------------------------------------------ GUARD-03 / EVAL-04
@pytest.mark.parametrize("field,text", [
    ("description", "Use password=Sup3rS3cret! for the db login please"),
    ("description", "Key is AKIAIOSFODNN7EXAMPLE for the bucket sync job"),
    ("description", "token ghp_aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5 for CI"),
    ("description", "-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA..."),
    ("description", "The value is 9fK2xQ7LmN4pR8sT1vW3yZ6bC0dE5gH for prod use"),
    ("description", "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc for tests"),
    ("team", "Xk9mQ2vL7pR4sT8wZ1bN6cF3"),
])
def test_eval04_pasted_credentials_refused_nothing_written(service, cognito, bao, field, text):
    out, err = create(service, cognito, **{field: text})
    assert err and "Refused" in out and "never taken from chat" in out
    assert writes(bao) == []
    assert bao.calls == []                       # refused before even logging in


def test_guard03_pasted_value_in_key_name_refused(service, cognito, bao):
    keys = [{"name": "Xk9mQ2vL7pR4sT8wZ1bN6cF3dJ", "source": "ui"}]
    out, err = create(service, cognito, keys=keys)
    assert err and "Refused" in out and writes(bao) == []


@pytest.mark.parametrize("text", [
    "Database password for the checkout API, rotated quarterly",
    "API key for the Stripe sandbox, see https://wiki.example.com/payments/stripe-integration",
    "Credentials used by internationalization service batch jobs (PAY-1234)",
    "Token signing secret for the session service",
])
def test_guard03_ordinary_descriptions_pass(text):
    assert credential_like(text) is None
