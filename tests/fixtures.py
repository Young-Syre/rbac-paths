"""Builders for small, entirely fabricated cluster dumps.

Every name here is invented.  Nothing is copied from a real cluster, no token
value is real, and image references use the reserved ``.example`` domain.
"""

from __future__ import annotations

import os
from typing import Any

from rbac_paths.loader import cluster_from_payload
from rbac_paths.model import Cluster

EXAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"
)
VULNERABLE = os.path.join(EXAMPLES_DIR, "cluster-vulnerable.json")
HARDENED = os.path.join(EXAMPLES_DIR, "cluster-hardened.json")

RBAC_API = "rbac.authorization.k8s.io/v1"
RBAC_GROUP = "rbac.authorization.k8s.io"

#: A short, obviously synthetic stand-in. The tool never parses a token value;
#: it only ever cares that a Secret of the service-account-token type exists.
FAKE_TOKEN_B64 = "UkVEQUNURUQtVEVTVC1WQUxVRQ=="


def rule(
    verbs: list[str],
    api_groups: list[str] | None = None,
    resources: list[str] | None = None,
    resource_names: list[str] | None = None,
    non_resource_urls: list[str] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"verbs": verbs}
    if non_resource_urls is not None:
        out["nonResourceURLs"] = non_resource_urls
        return out
    out["apiGroups"] = api_groups if api_groups is not None else [""]
    out["resources"] = resources or []
    if resource_names:
        out["resourceNames"] = resource_names
    return out


def cluster_role(
    name: str,
    rules: list[dict[str, Any]],
    labels: dict[str, str] | None = None,
    aggregation: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name}
    if labels:
        meta["labels"] = labels
    out = {"apiVersion": RBAC_API, "kind": "ClusterRole", "metadata": meta, "rules": rules}
    if aggregation is not None:
        out["aggregationRule"] = {"clusterRoleSelectors": aggregation}
    return out


def namespaced_role(name: str, namespace: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "apiVersion": RBAC_API,
        "kind": "Role",
        "metadata": {"name": name, "namespace": namespace},
        "rules": rules,
    }


def sa_subject(namespace: str, name: str) -> dict[str, str]:
    return {"kind": "ServiceAccount", "name": name, "namespace": namespace}


def group_subject(name: str) -> dict[str, str]:
    return {"kind": "Group", "name": name, "apiGroup": RBAC_GROUP}


def user_subject(name: str) -> dict[str, str]:
    return {"kind": "User", "name": name, "apiGroup": RBAC_GROUP}


def cluster_role_binding(
    name: str, role: str, subjects: list[dict[str, str]], role_kind: str = "ClusterRole"
) -> dict[str, Any]:
    return {
        "apiVersion": RBAC_API,
        "kind": "ClusterRoleBinding",
        "metadata": {"name": name},
        "roleRef": {"apiGroup": RBAC_GROUP, "kind": role_kind, "name": role},
        "subjects": subjects,
    }


def role_binding(
    name: str,
    namespace: str,
    role: str,
    role_kind: str,
    subjects: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "apiVersion": RBAC_API,
        "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": namespace},
        "roleRef": {"apiGroup": RBAC_GROUP, "kind": role_kind, "name": role},
        "subjects": subjects,
    }


def service_account(namespace: str, name: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace},
    }


def namespace(name: str, psa: str | None = None) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name}
    if psa:
        meta["labels"] = {"pod-security.kubernetes.io/enforce": psa}
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": meta}


def node(name: str, control_plane: bool = False) -> dict[str, Any]:
    labels = {"kubernetes.io/hostname": name}
    if control_plane:
        labels["node-role.kubernetes.io/control-plane"] = ""
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {"name": name, "labels": labels},
    }


def pod(
    name: str,
    ns: str,
    sa: str = "default",
    node_name: str | None = None,
    labels: dict[str, str] | None = None,
    node_selector: dict[str, str] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "serviceAccountName": sa,
        "containers": [{"name": "app", "image": "registry.example/app:1.0.0"}],
    }
    if node_name:
        spec["nodeName"] = node_name
    if node_selector:
        spec["nodeSelector"] = node_selector
    meta: dict[str, Any] = {"name": name, "namespace": ns}
    if labels:
        meta["labels"] = labels
    return {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}


def token_secret(name: str, ns: str, sa: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": ns,
            "annotations": {"kubernetes.io/service-account.name": sa},
        },
        "type": "kubernetes.io/service-account-token",
        "data": {"token": FAKE_TOKEN_B64},
    }


def opaque_secret(name: str, ns: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": ns},
        "type": "Opaque",
        "data": {"value": FAKE_TOKEN_B64},
    }


def listing(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"apiVersion": "v1", "kind": "List", "items": items}


def build(items: list[dict[str, Any]]) -> Cluster:
    return cluster_from_payload(listing(items))
