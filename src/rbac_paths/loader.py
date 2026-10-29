"""Read ``kubectl -o json`` dumps off disk.

JSON only, on purpose.  Parsing YAML would mean a dependency, and a dependency
on a YAML parser is a parser you have to trust with input you may have been
handed by someone else.  ``kubectl get ... -o json`` produces exactly what this
module reads, so there is nothing lost:

    kubectl get clusterroles,clusterrolebindings,roles,rolebindings,\\
        serviceaccounts,pods -A -o json > cluster.json

Four shapes are accepted: a ``List`` with ``items``, a bare JSON array of
objects, a single object, and a stream of concatenated objects (what you get
from appending several ``kubectl get`` runs to one file).
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any

from .model import (
    Binding,
    Cluster,
    Container,
    Namespace,
    Node,
    Pod,
    PolicyRule,
    Role,
    RoleRef,
    Secret,
    ServiceAccount,
    Subject,
)
from .selectors import parse_label_selector

RBAC_GROUP = "rbac.authorization.k8s.io"

MODELLED_KINDS = frozenset(
    {
        "Role",
        "ClusterRole",
        "RoleBinding",
        "ClusterRoleBinding",
        "ServiceAccount",
        "Secret",
        "Pod",
        "Node",
        "Namespace",
    }
)


class LoadError(Exception):
    """Raised when input cannot be read or is not the expected JSON shape."""


def _labels(obj: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    meta = obj.get("metadata") or {}
    labels = meta.get("labels") if isinstance(meta, dict) else None
    if not isinstance(labels, dict):
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _annotations(obj: Mapping[str, Any]) -> dict[str, str]:
    meta = obj.get("metadata") or {}
    annotations = meta.get("annotations") if isinstance(meta, dict) else None
    if not isinstance(annotations, dict):
        return {}
    return {str(k): str(v) for k, v in annotations.items()}


def _name(obj: Mapping[str, Any]) -> str:
    meta = obj.get("metadata") or {}
    return str(meta.get("name", "")) if isinstance(meta, dict) else ""


def _namespace(obj: Mapping[str, Any]) -> str | None:
    meta = obj.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    ns = meta.get("namespace")
    return str(ns) if ns else None


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(v) for v in value)


def parse_policy_rule(raw: Mapping[str, Any]) -> PolicyRule:
    return PolicyRule(
        verbs=_str_tuple(raw.get("verbs")),
        api_groups=_str_tuple(raw.get("apiGroups")),
        resources=_str_tuple(raw.get("resources")),
        resource_names=_str_tuple(raw.get("resourceNames")),
        non_resource_urls=_str_tuple(raw.get("nonResourceURLs")),
    )


def parse_role(raw: Mapping[str, Any]) -> Role:
    kind = str(raw.get("kind"))
    rules = raw.get("rules") or []
    parsed_rules = tuple(
        parse_policy_rule(r) for r in rules if isinstance(r, dict)
    )
    selectors: tuple[Any, ...] = ()
    aggregation = raw.get("aggregationRule")
    if isinstance(aggregation, dict):
        raw_selectors = aggregation.get("clusterRoleSelectors") or []
        if isinstance(raw_selectors, list):
            selectors = tuple(parse_label_selector(s) for s in raw_selectors)
    return Role(
        kind="Role" if kind == "Role" else "ClusterRole",
        name=_name(raw),
        namespace=_namespace(raw) if kind == "Role" else None,
        rules=parsed_rules,
        labels=_labels(raw),
        aggregation_selectors=selectors,
    )


def parse_subject(raw: Mapping[str, Any], binding_namespace: str | None) -> Subject | None:
    kind = str(raw.get("kind", ""))
    name = str(raw.get("name", ""))
    if not name or kind not in ("User", "Group", "ServiceAccount"):
        return None
    if kind == "ServiceAccount":
        # A ServiceAccount subject in a RoleBinding may omit the namespace, in
        # which case it means the binding's own namespace.
        namespace = raw.get("namespace") or binding_namespace
        if not namespace:
            return None
        return Subject("ServiceAccount", name, str(namespace))
    return Subject(kind, name)  # type: ignore[arg-type]


def parse_binding(raw: Mapping[str, Any], warnings: list[str]) -> Binding | None:
    kind = str(raw.get("kind"))
    kind = "RoleBinding" if kind == "RoleBinding" else "ClusterRoleBinding"
    namespace = _namespace(raw) if kind == "RoleBinding" else None
    name = _name(raw)
    role_ref_raw = raw.get("roleRef")
    if not isinstance(role_ref_raw, dict):
        warnings.append(f"{kind} {namespace or ''}/{name}: missing roleRef, ignored")
        return None
    role_kind = str(role_ref_raw.get("kind", ""))
    role_name = str(role_ref_raw.get("name", ""))
    if role_kind == "Role" and kind == "ClusterRoleBinding":
        # The API server rejects this: a ClusterRoleBinding may only reference
        # a ClusterRole.  Drop it rather than pretend it grants anything.
        warnings.append(
            f"ClusterRoleBinding {name}: roleRef.kind=Role is invalid and grants nothing, ignored"
        )
        return None
    if role_kind not in ("Role", "ClusterRole"):
        warnings.append(
            f"{kind} {namespace or ''}/{name}: roleRef.kind={role_kind!r} is not RBAC, ignored"
        )
        return None
    role_ref = RoleRef(
        kind="Role" if role_kind == "Role" else "ClusterRole",
        name=role_name,
        namespace=namespace if role_kind == "Role" else None,
    )
    subjects_raw = raw.get("subjects") or []
    subjects: list[Subject] = []
    if isinstance(subjects_raw, list):
        for entry in subjects_raw:
            if not isinstance(entry, dict):
                continue
            subject = parse_subject(entry, namespace)
            if subject is not None:
                subjects.append(subject)
    return Binding(
        kind=kind,  # type: ignore[arg-type]
        name=name,
        namespace=namespace,
        role_ref=role_ref,
        subjects=tuple(subjects),
    )


def parse_pod(raw: Mapping[str, Any]) -> Pod:
    spec = raw.get("spec") if isinstance(raw.get("spec"), dict) else {}
    assert isinstance(spec, dict)
    service_account = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
    host_paths: list[str] = []
    volumes = spec.get("volumes") or []
    if isinstance(volumes, list):
        for volume in volumes:
            if not isinstance(volume, dict):
                continue
            host_path = volume.get("hostPath")
            if isinstance(host_path, dict) and host_path.get("path"):
                host_paths.append(str(host_path["path"]))
    containers: list[Container] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        entries = spec.get(key) or []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            security = entry.get("securityContext")
            privileged = bool(security.get("privileged")) if isinstance(security, dict) else False
            containers.append(Container(name=str(entry.get("name", "")), privileged=privileged))
    node_selector = spec.get("nodeSelector")
    selector: tuple[tuple[str, str], ...] = ()
    if isinstance(node_selector, dict):
        selector = tuple(sorted((str(k), str(v)) for k, v in node_selector.items()))
    return Pod(
        name=_name(raw),
        namespace=_namespace(raw) or "default",
        service_account=str(service_account),
        node_name=str(spec.get("nodeName")) if spec.get("nodeName") else None,
        host_network=bool(spec.get("hostNetwork")),
        host_pid=bool(spec.get("hostPID")),
        host_path_volumes=tuple(host_paths),
        containers=tuple(containers),
        labels=_labels(raw),
        node_selector=selector,
    )


def parse_service_account(raw: Mapping[str, Any]) -> ServiceAccount:
    secrets_raw = raw.get("secrets") or []
    names: list[str] = []
    if isinstance(secrets_raw, list):
        for entry in secrets_raw:
            if isinstance(entry, dict) and entry.get("name"):
                names.append(str(entry["name"]))
    return ServiceAccount(
        name=_name(raw),
        namespace=_namespace(raw) or "default",
        secrets=tuple(names),
    )


def parse_secret(raw: Mapping[str, Any]) -> Secret:
    annotations = _annotations(raw)
    return Secret(
        name=_name(raw),
        namespace=_namespace(raw) or "default",
        type=str(raw.get("type", "Opaque")),
        service_account_name=annotations.get("kubernetes.io/service-account.name"),
    )


def iter_objects(payload: Any) -> Iterator[Mapping[str, Any]]:
    """Yield every API object in a parsed JSON payload, recursing into Lists."""
    if isinstance(payload, list):
        for entry in payload:
            yield from iter_objects(entry)
        return
    if not isinstance(payload, dict):
        return
    kind = payload.get("kind")
    items = payload.get("items")
    if isinstance(items, list) and (kind is None or str(kind).endswith("List")):
        for entry in items:
            yield from iter_objects(entry)
        return
    if kind:
        yield payload


def _decode_stream(text: str, origin: str) -> list[Any]:
    """Parse one or more concatenated JSON values out of ``text``."""
    decoder = json.JSONDecoder()
    values: list[Any] = []
    index = 0
    length = len(text)
    while True:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            value, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            raise LoadError(f"{origin}: not valid JSON ({exc})") from exc
        values.append(value)
    if not values:
        raise LoadError(f"{origin}: empty input")
    return values


def discover_files(path: str) -> list[str]:
    """Expand a path into the list of JSON files to read."""
    if path == "-":
        return ["-"]
    if os.path.isdir(path):
        found = sorted(
            os.path.join(path, entry)
            for entry in os.listdir(path)
            if entry.endswith(".json")
        )
        if not found:
            raise LoadError(f"{path}: directory contains no .json files")
        return found
    if not os.path.exists(path):
        raise LoadError(f"{path}: no such file or directory")
    return [path]


def load_cluster(paths: Sequence[str], stdin_text: str | None = None) -> Cluster:
    """Read every dump in ``paths`` into one Cluster."""
    cluster = Cluster()
    expanded: list[str] = []
    for path in paths:
        expanded.extend(discover_files(path))
    for path in expanded:
        if path == "-":
            if stdin_text is None:
                raise LoadError("- requested but no stdin was provided")
            text, origin = stdin_text, "<stdin>"
        else:
            try:
                with open(path, encoding="utf-8") as handle:
                    text = handle.read()
            except OSError as exc:
                raise LoadError(f"{path}: cannot read ({exc.strerror})") from exc
            origin = os.path.basename(path)
        cluster.sources.append(origin)
        for payload in _decode_stream(text, origin):
            _absorb(cluster, iter_objects(payload))
    if not cluster.roles and not cluster.bindings:
        raise LoadError(
            "no RBAC objects found; expected the output of `kubectl get "
            "clusterroles,clusterrolebindings,roles,rolebindings -o json`"
        )
    return cluster


def cluster_from_payload(payload: Any, origin: str = "<memory>") -> Cluster:
    """Build a Cluster from already-parsed JSON, without touching the disk.

    The same code path as :func:`load_cluster`, exposed because it is the
    natural unit for a test and for anything embedding this package.
    """
    cluster = Cluster()
    cluster.sources.append(origin)
    _absorb(cluster, iter_objects(payload))
    return cluster


def _absorb(cluster: Cluster, objects: Iterable[Mapping[str, Any]]) -> None:
    for obj in objects:
        kind = str(obj.get("kind", ""))
        if kind not in MODELLED_KINDS:
            cluster.skipped_kinds[kind] = cluster.skipped_kinds.get(kind, 0) + 1
            continue
        if kind in ("Role", "ClusterRole"):
            role = parse_role(obj)
            if role.ref in cluster.roles:
                cluster.warnings.append(f"{role.ref}: appears twice in the input, last wins")
            cluster.roles[role.ref] = role
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            binding = parse_binding(obj, cluster.warnings)
            if binding is not None:
                cluster.bindings.append(binding)
        elif kind == "ServiceAccount":
            cluster.service_accounts.append(parse_service_account(obj))
        elif kind == "Secret":
            cluster.secrets.append(parse_secret(obj))
        elif kind == "Pod":
            cluster.pods.append(parse_pod(obj))
        elif kind == "Node":
            cluster.nodes.append(Node(name=_name(obj), labels=_labels(obj)))
        elif kind == "Namespace":
            cluster.namespaces.append(Namespace(name=_name(obj), labels=_labels(obj)))
