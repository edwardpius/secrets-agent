"""Spec 004: the sync reconciler (REQ-01..06, GUARD), offline: fake OpenBao + fake Kube."""
from __future__ import annotations

import json
import logging

import httpx
import pytest

from secrets_agent import sync as sync_mod
from secrets_agent.create import PLACEHOLDER
from secrets_agent.openbao import Client, Session
from secrets_agent.sync import Kube, SyncSettings, object_name, push_status, reconcile

SETTINGS = SyncSettings(reserved_aws_names=frozenset({"openbao/demo-llm-api-key"}))


class FakeKube:
    """ExternalSecrets and PushSecrets in one namespace, as server-side apply leaves them."""

    def __init__(self) -> None:
        self.objs: dict[tuple[str, str], dict] = {}
        self.ready: dict[str, dict] = {}            # name -> Ready condition for PushSecret

    def handler(self, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        kind = {"externalsecrets": "ExternalSecret", "pushsecrets": "PushSecret"}[parts[5]]
        name = parts[6] if len(parts) > 6 else None
        if request.method == "PATCH":
            assert request.headers["content-type"] == "application/apply-patch+yaml"
            obj = json.loads(request.content)
            self.objs[(kind, name)] = obj
            return httpx.Response(200, json=obj)
        if request.method == "GET" and name:
            obj = self.objs.get((kind, name))
            if obj is None:
                return httpx.Response(404, json={})
            if kind == "PushSecret" and name in self.ready:
                obj = dict(obj, status={"conditions": [self.ready[name]]})
            return httpx.Response(200, json=obj)
        if request.method == "GET":
            sel = request.url.params["labelSelector"]
            assert sel == f"{sync_mod.LABEL}={sync_mod.MANAGED_BY}"
            return httpx.Response(200, json={"items": [o for (k, _), o in self.objs.items()
                                                       if k == kind]})
        if request.method == "DELETE":
            self.objs.pop((kind, name), None)
            return httpx.Response(200, json={})
        return httpx.Response(405)


@pytest.fixture
def kube():
    return FakeKube()


@pytest.fixture
def run(bao, kube, settings):
    client = Client(settings.openbao_addr, transport=httpx.MockTransport(bao.handler))
    bao.tokens["hvs.sync"] = ("apps-sync",)
    k = Kube(httpx.Client(base_url="https://kube", transport=httpx.MockTransport(kube.handler)),
             SETTINGS.namespace)
    return lambda: reconcile(SETTINGS, Session(client, "hvs.sync"), k)


def seed(bao, rel, aws=None, sync="true", **keys):
    bao.data[rel] = {k: v for k, v in keys.items()}
    bao.metadata[rel] = {"schema": "1", "sync_aws": sync, "description": "x" * 12,
                         **({"aws_secret_name": aws} if aws else {}),
                         **{f"key.{k}": ("pending-ui" if v == PLACEHOLDER else "generated:password")
                            for k, v in keys.items()}}


def kinds(kube):
    return sorted(k for k, _ in kube.objs)


# ------------------------------------------------------------------ REQ-01/02
def test_req02_synced_entry_gets_external_and_push_secret(run, bao, kube):
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod", DB="v-1")
    seed(bao, "billing/api/dev", sync="false", DB="v-2")                  # not synced
    res = run()
    name = object_name("billing/api/prod")
    assert kinds(kube) == ["ExternalSecret", "PushSecret"]
    es, ps = kube.objs[("ExternalSecret", name)], kube.objs[("PushSecret", name)]
    assert es["spec"]["dataFrom"] == [{"extract": {"key": "billing/api/prod"}}]
    assert es["spec"]["secretStoreRef"] == {"kind": "SecretStore", "name": "openbao-apps"}
    assert ps["spec"]["data"][0]["match"]["remoteRef"]["remoteKey"] == "openbao/billing/api/prod"
    assert ps["spec"]["deletionPolicy"] == "None"
    assert ps["spec"]["data"][0]["metadata"]["spec"]["secretPushFormat"] == "string"
    assert bao.metadata["billing/api/prod"]["sync_status"] == "pending"
    assert "sync_status" not in bao.metadata["billing/api/dev"]
    assert res.metadata_writes == 1


def test_req02_flag_removed_deletes_objects(run, bao, kube):
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod", DB="v")
    run()
    bao.metadata["billing/api/prod"]["sync_aws"] = "false"
    res = run()
    assert kube.objs == {} and res.deleted == ["apps/billing/api/prod"]


def test_object_names_are_unique_and_dns_safe():
    a, b = object_name("a-b/c/dev"), object_name("a/b-c/dev")
    assert a != b
    long = object_name("p" * 31 + "/" + "s" * 31 + "/staging")
    assert len(long) <= 63 and long == long.lower()


# ------------------------------------------------------------------ REQ-03
@pytest.mark.parametrize("aws,why", [
    ("prod/billing", "must start with openbao/"),
    ("openbao/../x", "must start with openbao/"),
    ("openbao/demo-llm-api-key", "kv/sync replication"),
])
def test_req03_bad_names_skipped_with_reason(run, bao, kube, aws, why):
    seed(bao, "billing/api/prod", aws=aws, DB="v")
    res = run()
    assert kube.objs == {}
    assert why in bao.metadata["billing/api/prod"]["sync_status"]
    assert "billing/api/prod" in res.errors


def test_req03_duplicate_name_second_path_skipped(run, bao, kube):
    seed(bao, "a/api/prod", aws="openbao/shared", DB="v")
    seed(bao, "b/api/prod", aws="openbao/shared", DB="v")
    run()
    assert len(kube.objs) == 2                                   # only a/api/prod
    assert "already used by apps/a/api/prod" in bao.metadata["b/api/prod"]["sync_status"]


# ------------------------------------------------------------------ REQ-04
def test_req04_status_from_push_secret(run, bao, kube):
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod", DB="v")
    run()
    name = object_name("billing/api/prod")
    kube.ready[name] = {"type": "Ready", "status": "True",
                        "lastTransitionTime": "2026-11-17T23:00:00Z"}
    res = run()
    assert bao.metadata["billing/api/prod"]["sync_status"] == "synced 2026-11-17T23:00:00Z"
    assert res.synced == ["billing/api/prod"]
    writes = res.metadata_writes
    assert run().metadata_writes == 0 and writes == 1            # no rewrite when unchanged


def test_req04_push_error_reported():
    st = push_status({"status": {"conditions": [{"type": "Ready", "status": "False",
                                                 "reason": "Errored",
                                                 "message": "secret not managed by\nESO"}]}})
    assert st == "error: secret not managed by ESO"


# ------------------------------------------------------------------ REQ-05/06
def test_req05_waits_while_placeholder(run, bao, kube):
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod",
         DB="v", API_KEY=PLACEHOLDER)
    run()
    assert kube.objs == {}
    md = bao.metadata["billing/api/prod"]
    assert md["sync_status"] == "waiting: values not set in OpenBao UI"
    assert md["key.API_KEY"] == "pending-ui"


def test_req06_value_set_in_ui_then_synced(run, bao, kube):
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod",
         DB="v", API_KEY=PLACEHOLDER)
    run()
    bao.data["billing/api/prod"]["API_KEY"] = "set-by-a-human"     # new version in the UI
    run()
    md = bao.metadata["billing/api/prod"]
    assert md["key.API_KEY"] == "set" and md["sync_status"] == "pending"
    assert kinds(kube) == ["ExternalSecret", "PushSecret"]


def test_req06_data_read_only_when_something_is_pending(run, bao):
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod", DB="v")
    run()
    assert bao.data_reads == 0


def test_guard_values_never_logged_or_written(run, bao, kube, caplog):
    caplog.set_level(logging.DEBUG)
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod",
         DB="hunter2-real-value", API_KEY=PLACEHOLDER)
    run()
    bao.data["billing/api/prod"]["API_KEY"] = "another-real-value"
    run()
    blob = caplog.text + json.dumps(bao.metadata) + json.dumps(list(kube.objs.values()))
    assert "hunter2-real-value" not in blob and "another-real-value" not in blob
    assert all("data/" not in b for b in bao.bodies if "custom_metadata" not in b)


def test_metadata_write_keeps_user_fields(run, bao):
    seed(bao, "billing/api/prod", aws="openbao/billing/api/prod", DB="v")
    before = dict(bao.metadata["billing/api/prod"])
    run()
    after = bao.metadata["billing/api/prod"]
    assert {k: v for k, v in after.items() if k != "sync_status"} == before
