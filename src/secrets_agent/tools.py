"""The MCP tools. Each takes the verified Identity and that user's OpenBao Session."""
from __future__ import annotations

from .auth import Identity
from .config import Settings
from .openbao import Session

ENVIRONMENTS = ("dev", "staging", "prod")
# Placeholder product/service used only to ask OpenBao what this token may do per
# environment (policies match apps/data/+/+/<env>).
_PROBE = "_probe/_probe"

WHOAMI = {
    "name": "whoami",
    "description": (
        "Show who you (the signed-in user) are to OpenBao: email, Identity Center groups, "
        "OpenBao policies, and whether you may create secrets in dev, staging and prod "
        "under apps/ and search them. Use before creating a secret or to explain a denial."
    ),
    "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
}

TOOLS = [WHOAMI]


def whoami(settings: Settings, who: Identity, session: Session) -> dict:
    """Spec 001 REQ-04: identity and rights under apps/, nothing else."""
    m = settings.apps_mount
    data_paths = {env: f"{m}/data/{_PROBE}/{env}" for env in ENVIRONMENTS}
    search_path = f"{m}/metadata/"
    caps = session.capabilities(list(data_paths.values()) + [search_path])
    return {
        "email": who.email,
        "groups": list(who.groups),
        "openbao_policies": list(session.policies),
        "may_create": {env: "create" in caps[p] for env, p in data_paths.items()},
        "may_search": "list" in caps[search_path],
        "secrets_path": f"{m}/<product>/<service>/<environment>",
    }
