"""The object model.

These types are a deliberately thin reading of the Kubernetes API objects that
matter for RBAC.  Fields the authorizer never consults are dropped, so what is
left is exactly the input to an authorization decision plus the handful of pod
spec fields that decide what a created pod can reach on its node.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .selectors import LabelSelector

RoleKind = Literal["Role", "ClusterRole"]
BindingKind = Literal["RoleBinding", "ClusterRoleBinding"]
SubjectKind = Literal["User", "Group", "ServiceAccount"]

#: ``rbacv1.VerbAll`` / ``rbacv1.APIGroupAll`` / ``rbacv1.ResourceAll``.
ALL = "*"

#: Verbs that address a collection, so the authorizer is given no object name.
COLLECTION_VERBS = frozenset({"list", "watch", "deletecollection"})

#: Verbs for which the authorizer sees no object name in the common case.  Kept
#: for the CLI's ``--name`` warning; the exact rule is
#: :func:`verb_has_no_object_name`, which has to know about subresources.
NAMELESS_VERBS = COLLECTION_VERBS | {"create"}


def verb_has_no_object_name(verb: str, subresource: str = "") -> bool:
    """Whether the authorizer is given no object name for this request.

    ``create`` on a resource carries the name in the request body, so the
    authorizer has none - which is why ``resourceNames`` cannot authorize it.
    ``create`` on a *subresource* is different: the request path is
    ``.../serviceaccounts/<name>/token``, so the name is known and
    ``resourceNames`` applies.  The same holds for ``pods/exec``, which is why
    a ``bind``-style grant can be pinned to one object.  The collection verbs
    never carry a name.
    """
    if verb in COLLECTION_VERBS:
        return True
    return verb == "create" and not subresource


@dataclass(frozen=True)
class PolicyRule:
    """One entry of a Role's or ClusterRole's ``rules`` list."""

    verbs: tuple[str, ...] = ()
    api_groups: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    resource_names: tuple[str, ...] = ()
    non_resource_urls: tuple[str, ...] = ()

    @property
    def is_non_resource_only(self) -> bool:
        """True for a rule that can only authorize non-resource paths.

        ``nonResourceURLs`` and ``resources`` are mutually exclusive in a valid
        rule, and only a ClusterRole may carry ``nonResourceURLs`` at all.
        """
        return bool(self.non_resource_urls) and not self.resources


@dataclass(frozen=True)
class RoleRef:
    """Identity of a Role or ClusterRole, used as a dictionary key."""

    kind: RoleKind
    name: str
    namespace: str | None = None

    def __str__(self) -> str:
        if self.kind == "Role":
            return f"Role {self.namespace}/{self.name}"
        return f"ClusterRole {self.name}"


@dataclass(frozen=True)
class Role:
    """A Role or a ClusterRole.

    ``aggregation_selectors`` is non-empty only for a ClusterRole that carries
    an ``aggregationRule``.  In a dump taken from a running cluster the
    controller has usually already written the aggregated rules into ``rules``,
    but a dump of un-applied manifests has not, so the resolver recomputes the
    union either way.
    """

    kind: RoleKind
    name: str
    namespace: str | None = None
    rules: tuple[PolicyRule, ...] = ()
    labels: tuple[tuple[str, str], ...] = ()
    aggregation_selectors: tuple[LabelSelector, ...] = ()

    @property
    def ref(self) -> RoleRef:
        return RoleRef(self.kind, self.name, self.namespace)

    @property
    def label_map(self) -> dict[str, str]:
        return dict(self.labels)


@dataclass(frozen=True)
class Subject:
    """A binding subject: a user, a group, or a service account."""

    kind: SubjectKind
    name: str
    namespace: str | None = None

    @property
    def id(self) -> str:
        """The canonical identifier used for graph nodes and CLI arguments."""
        if self.kind == "ServiceAccount":
            return f"sa:{self.namespace}:{self.name}"
        if self.kind == "Group":
            return f"group:{self.name}"
        return f"user:{self.name}"

    def __str__(self) -> str:
        if self.kind == "ServiceAccount":
            return f"ServiceAccount {self.namespace}/{self.name}"
        return f"{self.kind} {self.name}"


@dataclass(frozen=True)
class Binding:
    """A RoleBinding or a ClusterRoleBinding."""

    kind: BindingKind
    name: str
    namespace: str | None = None
    role_ref: RoleRef = RoleRef("ClusterRole", "")
    subjects: tuple[Subject, ...] = ()

    def __str__(self) -> str:
        if self.kind == "RoleBinding":
            return f"RoleBinding {self.namespace}/{self.name}"
        return f"ClusterRoleBinding {self.name}"

    @property
    def scope(self) -> str | None:
        """The namespace the grant is confined to, or None for cluster-wide.

        A RoleBinding that references a ClusterRole grants that ClusterRole's
        rules inside the RoleBinding's namespace only.
        """
        return self.namespace if self.kind == "RoleBinding" else None


@dataclass(frozen=True)
class ServiceAccount:
    name: str
    namespace: str
    secrets: tuple[str, ...] = ()


@dataclass(frozen=True)
class Secret:
    name: str
    namespace: str
    type: str = "Opaque"
    service_account_name: str | None = None

    @property
    def is_service_account_token(self) -> bool:
        return self.type == "kubernetes.io/service-account-token"


@dataclass(frozen=True)
class Container:
    name: str
    privileged: bool = False


@dataclass(frozen=True)
class Pod:
    name: str
    namespace: str
    service_account: str = "default"
    node_name: str | None = None
    host_network: bool = False
    host_pid: bool = False
    host_path_volumes: tuple[str, ...] = ()
    containers: tuple[Container, ...] = ()
    labels: tuple[tuple[str, str], ...] = ()
    node_selector: tuple[tuple[str, str], ...] = ()

    @property
    def label_map(self) -> dict[str, str]:
        return dict(self.labels)

    @property
    def has_privileged_container(self) -> bool:
        return any(c.privileged for c in self.containers)


#: Labels that mark a node as part of the control plane.  Both spellings are
#: recognised: the ``master`` form was the only one before 1.20 and lingers on
#: clusters that were upgraded rather than rebuilt.
CONTROL_PLANE_LABELS = (
    "node-role.kubernetes.io/control-plane",
    "node-role.kubernetes.io/master",
)


@dataclass(frozen=True)
class Node:
    name: str
    labels: tuple[tuple[str, str], ...] = ()

    @property
    def label_map(self) -> dict[str, str]:
        return dict(self.labels)

    @property
    def is_control_plane(self) -> bool:
        keys = {k for k, _ in self.labels}
        return any(label in keys for label in CONTROL_PLANE_LABELS)


#: Pod Security Standards levels, weakest first.
PSA_LEVELS = ("privileged", "baseline", "restricted")


@dataclass(frozen=True)
class Namespace:
    name: str
    labels: tuple[tuple[str, str], ...] = ()

    @property
    def psa_enforce(self) -> str | None:
        """The enforced Pod Security Standards level, if the label is set."""
        for key, value in self.labels:
            if key == "pod-security.kubernetes.io/enforce":
                return value if value in PSA_LEVELS else None
        return None


@dataclass
class Cluster:
    """Everything parsed out of one or more dumps."""

    roles: dict[RoleRef, Role] = field(default_factory=dict)
    bindings: list[Binding] = field(default_factory=list)
    service_accounts: list[ServiceAccount] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    pods: list[Pod] = field(default_factory=list)
    nodes: list[Node] = field(default_factory=list)
    namespaces: list[Namespace] = field(default_factory=list)
    #: Kinds that were present in the input but are not modelled, kept so the
    #: CLI can tell the user what it ignored rather than silently dropping it.
    skipped_kinds: dict[str, int] = field(default_factory=dict)
    #: Objects the API server would have rejected, or references that do not
    #: resolve.  Surfaced by the CLI rather than swallowed.
    warnings: list[str] = field(default_factory=list)
    #: Input files the dump was read from, by basename only.
    sources: list[str] = field(default_factory=list)

    def role(self, ref: RoleRef) -> Role | None:
        return self.roles.get(ref)

    def cluster_roles(self) -> list[Role]:
        return [r for r in self.roles.values() if r.kind == "ClusterRole"]

    def service_accounts_in(self, namespace: str) -> list[ServiceAccount]:
        return [sa for sa in self.service_accounts if sa.namespace == namespace]

    def pods_in(self, namespace: str) -> list[Pod]:
        return [p for p in self.pods if p.namespace == namespace]

    def pods_on(self, node: str) -> list[Pod]:
        return [p for p in self.pods if p.node_name == node]

    def namespace(self, name: str) -> Namespace | None:
        for ns in self.namespaces:
            if ns.name == name:
                return ns
        return None

    def known_namespaces(self) -> list[str]:
        """Every namespace name that appears anywhere in the dump."""
        names: set[str] = {ns.name for ns in self.namespaces}
        names.update(sa.namespace for sa in self.service_accounts)
        names.update(p.namespace for p in self.pods)
        names.update(s.namespace for s in self.secrets)
        names.update(r.namespace for r in self.roles.values() if r.namespace)
        names.update(b.namespace for b in self.bindings if b.namespace)
        for binding in self.bindings:
            for subject in binding.subjects:
                if subject.kind == "ServiceAccount" and subject.namespace:
                    names.add(subject.namespace)
        return sorted(n for n in names if n)

    def control_plane_nodes(self) -> list[str]:
        """Control-plane node names, by label or by what runs on them.

        The ``kubectl get`` command this tool documents does not include node
        objects, so when they are absent the control plane is inferred from the
        node a ``kube-apiserver`` pod is bound to.  That inference is reported
        in the output so a reader can see which of the two happened.
        """
        named = {n.name for n in self.nodes if n.is_control_plane}
        for pod in self.pods:
            if not pod.node_name:
                continue
            labels = pod.label_map
            component = labels.get("component") or labels.get("tier")
            if component in {"kube-apiserver", "control-plane"} or pod.name.startswith(
                ("kube-apiserver-", "kube-controller-manager-")
            ):
                named.add(pod.node_name)
        return sorted(named)

    def node_names(self) -> list[str]:
        names = {n.name for n in self.nodes}
        names.update(p.node_name for p in self.pods if p.node_name)
        return sorted(n for n in names if n)
