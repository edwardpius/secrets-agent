"""secrets-sync: reconciles apps/ secrets marked sync_aws=true into ESO objects (spec 004).

Every minute, with its own OpenBao role (`apps-sync`, Kubernetes auth):
  1. list apps/ metadata, keep entries with sync_aws = "true";
  2. REQ-03: the AWS name must be under openbao/, not used by another entry, not a
     kv/sync name (layer 60);
  3. REQ-05/06: keys still `pending-ui` are checked against the placeholder (data read in
     memory only); any placeholder left -> waiting, else those keys become `set`;
  4. REQ-02: server-side apply an ExternalSecret (OpenBao -> k8s Secret) and a PushSecret
     (k8s Secret -> Secrets Manager) in namespace secrets-sync; delete ours that are no
     longer wanted (the AWS copy stays: deletionPolicy None);
  5. REQ-04: write sync_status back to the metadata when it changed.

Values are compared and dropped: never logged, stored, returned or put on a span (GUARD).
It has no AWS rights; ESO does the AWS calls with its own role.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

import httpx

from .create import AWS_RE, ENVIRONMENTS, PLACEHOLDER
from .openbao import Client, OpenBaoError, Session

log = logging.getLogger("secrets_sync")

MANAGED_BY = "secrets-agent-sync"
LABEL = "app.kubernetes.io/managed-by"
ESO_REFRESH = "1m"
MAX_ENTRIES = 2000


@dataclass(frozen=True)
class SyncSettings:
    namespace: str = "secrets-sync"
    apps_mount: str = "apps"
    openbao_store: str = "openbao-apps"
    aws_store: str = "aws-secrets-manager"
    resource_policy_configmap: str = "apps-resource-policy"
    reserved_aws_names: frozenset[str] = frozenset()     # kv/sync names (layer 60)


# --------------------------------------------------------------------- Kubernetes
class Kube:
    """The few calls the reconciler needs, on ExternalSecrets and PushSecrets only."""

    PATHS = {
        "ExternalSecret": "/apis/external-secrets.io/v1/namespaces/{ns}/externalsecrets",
        "PushSecret": "/apis/external-secrets.io/v1alpha1/namespaces/{ns}/pushsecrets",
    }

    def __init__(self, http: httpx.Client, namespace: str) -> None:
        self.http = http
        self.ns = namespace

    def _url(self, kind: str, name: str = "") -> str:
        base = self.PATHS[kind].format(ns=self.ns)
        return f"{base}/{name}" if name else base

    def apply(self, obj: dict) -> None:
        import json
        r = self.http.patch(self._url(obj["kind"], obj["metadata"]["name"]),
                            params={"fieldManager": MANAGED_BY, "force": "true"},
                            content=json.dumps(obj),
                            headers={"Content-Type": "application/apply-patch+yaml"})
        r.raise_for_status()

    def list_ours(self, kind: str) -> list[dict]:
        r = self.http.get(self._url(kind), params={"labelSelector": f"{LABEL}={MANAGED_BY}"})
        r.raise_for_status()
        return r.json().get("items") or []

    def get(self, kind: str, name: str) -> dict | None:
        r = self.http.get(self._url(kind, name))
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def delete(self, kind: str, name: str) -> None:
        r = self.http.delete(self._url(kind, name))
        if r.status_code not in (200, 202, 404):
            r.raise_for_status()


# --------------------------------------------------------------------- desired objects
def object_name(rel: str) -> str:
    """DNS-safe and collision-free ("a-b/c" vs "a/b-c")."""
    product, service, env = rel.split("/")
    h = hashlib.sha256(rel.encode()).hexdigest()[:8]
    return f"apps-{product}-{service}-{env}"[:50].rstrip("-") + f"-{h}"


def manifests(s: SyncSettings, rel: str, aws_name: str) -> list[dict]:
    name = object_name(rel)
    product, service, env = rel.split("/")
    meta = {"name": name, "namespace": s.namespace,
            "labels": {LABEL: MANAGED_BY, "secrets-agent/product": product,
                       "secrets-agent/service": service, "secrets-agent/environment": env},
            "annotations": {"secrets-agent/path": f"{s.apps_mount}/{rel}",
                            "secrets-agent/aws-secret-name": aws_name}}
    external = {
        "apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret", "metadata": meta,
        "spec": {
            "refreshInterval": ESO_REFRESH,
            "secretStoreRef": {"kind": "SecretStore", "name": s.openbao_store},
            "target": {"name": name, "creationPolicy": "Owner"},
            "dataFrom": [{"extract": {"key": rel}}],
        },
    }
    push = {
        "apiVersion": "external-secrets.io/v1alpha1", "kind": "PushSecret", "metadata": meta,
        "spec": {
            "refreshInterval": ESO_REFRESH,
            "updatePolicy": "Replace",
            "deletionPolicy": "None",          # the AWS copy outlives the k8s objects
            "secretStoreRefs": [{"kind": "SecretStore", "name": s.aws_store}],
            "selector": {"secret": {"name": name}},
            "data": [{
                "match": {"remoteRef": {"remoteKey": aws_name}},
                "metadata": {
                    "apiVersion": "kubernetes.external-secrets.io/v1alpha1",
                    "kind": "PushSecretMetadata",
                    "spec": {
                        "secretPushFormat": "string",
                        "resourcePolicy": {
                            "blockPublicPolicy": True,
                            "policySourceRef": {"kind": "ConfigMap",
                                                "name": s.resource_policy_configmap,
                                                "key": "policy.json"}},
                    },
                },
            }],
        },
    }
    return [external, push]


def push_status(obj: dict | None) -> str:
    """REQ-04 from the PushSecret's Ready condition."""
    if obj is None:
        return "pending"
    for c in (obj.get("status") or {}).get("conditions") or []:
        if c.get("type") == "Ready":
            if c.get("status") == "True":
                return f"synced {c.get('lastTransitionTime', '')}".strip()
            msg = " ".join(str(c.get("message") or c.get("reason") or "not ready").split())
            return f"error: {msg[:200]}" if c.get("reason") == "Errored" else "pending"
    return "pending"


# --------------------------------------------------------------------- one pass
@dataclass
class Result:
    synced: list[str] = field(default_factory=list)
    waiting: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    deleted: list[str] = field(default_factory=list)
    metadata_writes: int = 0


def _walk(session: Session, mount: str) -> list[str]:
    out: list[str] = []
    for p in session.list(f"{mount}/metadata/"):
        for sv in session.list(f"{mount}/metadata/{p}"):
            for env in session.list(f"{mount}/metadata/{p}{sv}"):
                env = env.rstrip("/")
                if env in ENVIRONMENTS and len(out) < MAX_ENTRIES:
                    out.append(f"{p.rstrip('/')}/{sv.rstrip('/')}/{env}")
    return out


def reconcile(s: SyncSettings, session: Session, kube: Kube) -> Result:
    res = Result()
    m = s.apps_mount
    entries: dict[str, dict] = {}
    for rel in _walk(session, m):
        md = session.read(f"{m}/metadata/{rel}")
        cm = ((md or {}).get("data") or {}).get("custom_metadata") or {}
        if cm.get("sync_aws") == "true":
            entries[rel] = dict(cm)

    wanted: set[str] = set()
    names_seen: dict[str, str] = {}
    for rel in sorted(entries):                       # path order decides duplicates
        cm = entries[rel]
        new = dict(cm)
        aws = cm.get("aws_secret_name") or ""
        status = None
        if not AWS_RE.match(aws) or ".." in aws:
            status = "error: aws_secret_name must start with openbao/"
        elif aws in s.reserved_aws_names:
            status = f"error: {aws} is used by the kv/sync replication (layer 60)"
        elif aws in names_seen:
            status = f"error: {aws} is already used by {m}/{names_seen[aws]}"
        else:
            names_seen[aws] = rel
            pending = [k for k, v in cm.items() if k.startswith("key.") and v == "pending-ui"]
            if pending:
                data = ((session.read(f"{m}/data/{rel}") or {}).get("data") or {}).get("data") or {}
                still = [k for k in pending if data.get(k.removeprefix("key.")) == PLACEHOLDER
                         or k.removeprefix("key.") not in data]
                data = {}                              # values dropped here (GUARD)
                for k in pending:
                    if k not in still:
                        new[k] = "set"                 # REQ-06
                if still:
                    status = "waiting: values not set in OpenBao UI"
                    res.waiting.append(rel)
            if status is None:
                name = object_name(rel)
                for obj in manifests(s, rel, aws):
                    kube.apply(obj)
                wanted.add(name)
                status = push_status(kube.get("PushSecret", name))
                if status.startswith("synced"):
                    res.synced.append(rel)
        if status.startswith("error"):
            res.errors[rel] = status
        new["sync_status"] = status
        if new != cm:                                  # REQ-04: only when it changed
            session.write(f"{m}/metadata/{rel}", {"custom_metadata": new})
            res.metadata_writes += 1

    for kind in ("PushSecret", "ExternalSecret"):      # flag removed -> objects removed
        for obj in kube.list_ours(kind):
            name = obj["metadata"]["name"]
            if name not in wanted:
                kube.delete(kind, name)
                if kind == "PushSecret":
                    res.deleted.append((obj["metadata"].get("annotations") or {})
                                       .get("secrets-agent/path", name))
    return res


# --------------------------------------------------------------------- process
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


def kube_from_cluster(namespace: str) -> Kube:
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token = open(f"{SA_DIR}/token").read().strip()
    http = httpx.Client(base_url=f"https://{host}:{port}", verify=f"{SA_DIR}/ca.crt",
                        headers={"Authorization": f"Bearer {token}"}, timeout=15.0)
    return Kube(http, namespace)


def login(client: Client, role: str, mount: str = "kubernetes") -> Session:
    token = open(f"{SA_DIR}/token").read().strip()
    r = client._http.post(f"/v1/auth/{mount}/login", json={"role": role, "jwt": token})
    if r.status_code != 200:
        raise OpenBaoError(r.status_code, "kubernetes login refused")
    auth = r.json()["auth"]
    return Session(client, auth["client_token"], policies=tuple(auth.get("policies") or ()))


def run(interval: float = 60.0, once: bool = False,
        sleep: Callable[[float], None] = time.sleep) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    reserved = frozenset(n.strip() for n in os.environ.get("RESERVED_AWS_NAMES", "").split(",")
                         if n.strip())
    s = SyncSettings(namespace=os.environ.get("SYNC_NAMESPACE", "secrets-sync"),
                     reserved_aws_names=reserved)
    client = Client(os.environ["OPENBAO_ADDR"], verify=os.environ.get("OPENBAO_CACERT") or True)
    role = os.environ.get("OPENBAO_ROLE", "apps-sync")
    while True:
        try:
            res = reconcile(s, login(client, role), kube_from_cluster(s.namespace))
            log.info("synced=%d waiting=%d errors=%d deleted=%d metadata_writes=%d",
                     len(res.synced), len(res.waiting), len(res.errors), len(res.deleted),
                     res.metadata_writes)
            for rel, why in res.errors.items():
                log.info("skip %s: %s", rel, why)
        except (OpenBaoError, httpx.HTTPError, OSError, KeyError) as e:
            log.warning("pass failed: %s", type(e).__name__ + ": " + str(e)[:300])
        if once:
            return 0
        sleep(interval)


def main(argv: list[str] | None = None) -> int:
    return run(interval=float(os.environ.get("SYNC_INTERVAL_SECONDS", "60")),
               once="--once" in (argv if argv is not None else sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(main())
