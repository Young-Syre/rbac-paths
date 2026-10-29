"""Resolve a subject to the set of permissions it actually holds.

Three things make this more than a dictionary lookup.

**Scope.**  A ClusterRole's rules apply cluster-wide through a
ClusterRoleBinding but only inside one namespace through a RoleBinding.  A rule
naming a cluster-scoped resource (``nodes``, ``clusterroles``,
``validatingwebhookconfigurations``, ``users`` and ``groups`` for
``impersonate``) grants nothing at all when it arrives through a RoleBinding,
because there is no namespaced instance of it to authorize.

**Aggregation.**  A ClusterRole with an ``aggregationRule`` has its ``rules``
filled in by the controller-manager from every ClusterRole whose labels match
one of its selectors.  An operator that ships a ClusterRole labelled
``rbac.authorization.k8s.io/aggregate-to-edit: "true"`` has added its
permissions to everyone who holds ``edit``.  A dump of a running cluster
usually already has the merged rules written back, but a dump of manifests does
not, so the union is recomputed here either way and the contributing role is
recorded.

**Groups.**  There is no in-cluster object that maps a user to a group; that
comes from the authenticator, so it cannot be read from a dump.  What *can* be
read is the membership the API server synthesises itself, which is where most
accidental cluster-admin comes from:

* every service account is in ``system:serviceaccounts``,
  ``system:serviceaccounts:<its namespace>`` and ``system:authenticated``;
* every authenticated user is in ``system:authenticated``;
* ``system:anonymous`` is in ``system:unauthenticated`` and nothing else.

Group membership that comes from OIDC claims or a certificate's Organization
field can be supplied on the command line with ``--group``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .matching import rule_allows, rule_allows_non_resource, split_resource
from .model import Binding, Cluster, PolicyRule, Role, RoleRef, Subject

#: Resources that have no namespaced instance.  A rule naming one of these is
#: inert when it reaches a subject through a RoleBinding.  ``users``, ``groups``
#: and ``uids`` are the virtual resources used by the ``impersonate`` verb.
CLUSTER_SCOPED_RESOURCES = frozenset(
    {
        "apiservices",
        "certificatesigningrequests",
        "clusterrolebindings",
        "clusterroles",
        "clustertrustbundles",
        "csidrivers",
        "csinodes",
        "customresourcedefinitions",
        "flowschemas",
        "groups",
        "ingressclasses",
        "mutatingadmissionpolicies",
        "mutatingwebhookconfigurations",
        "namespaces",
        "nodes",
        "persistentvolumes",
        "priorityclasses",
        "prioritylevelconfigurations",
        "runtimeclasses",
        "selfsubjectaccessreviews",
        "selfsubjectreviews",
        "selfsubjectrulesreviews",
        "storageclasses",
        "subjectaccessreviews",
        "tokenreviews",
        "uids",
        "users",
        "validatingadmissionpolicies",
        "validatingadmissionpolicybindings",
        "validatingwebhookconfigurations",
        "volumeattachments",
    }
)

GROUP_AUTHENTICATED = "system:authenticated"
GROUP_UNAUTHENTICATED = "system:unauthenticated"
GROUP_ALL_SERVICE_ACCOUNTS = "system:serviceaccounts"
GROUP_MASTERS = "system:masters"
USER_ANONYMOUS = "system:anonymous"

#: Groups that every pod in the cluster, or every user with any credential,
#: lands in.  A ClusterRoleBinding to one of these grants to the whole cluster.
OPEN_GROUPS = frozenset({GROUP_AUTHENTICATED, GROUP_UNAUTHENTICATED, GROUP_ALL_SERVICE_ACCOUNTS})


def is_cluster_scoped(resource: str) -> bool:
    base, _ = split_resource(resource)
    return base in CLUSTER_SCOPED_RESOURCES


@dataclass(frozen=True)
class Grant:
    """One PolicyRule, reaching one subject, within one scope."""

    rule: PolicyRule
    #: The namespace the rule is confined to, or None for cluster-wide.
    namespace: str | None
    binding: Binding
    role: RoleRef
    #: The binding subject that matched: the subject itself, or a group it is in.
    via: Subject
    #: Set when the rule arrived through ``aggregationRule`` rather than being
    #: written in the referenced role.
    aggregated_from: RoleRef | None = None

    @property
    def scope_text(self) -> str:
        return f"namespace {self.namespace}" if self.namespace else "all namespaces"

    def source_text(self) -> str:
        parts = [f"{self.binding} -> {self.role}"]
        if self.aggregated_from is not None:
            parts.append(f"aggregated from {self.aggregated_from}")
        if self.via.kind == "Group":
            parts.append(f"via group {self.via.name}")
        return "; ".join(parts)

    def rule_text(self) -> str:
        return render_rule(self.rule)


def render_rule(rule: PolicyRule) -> str:
    """A one-line rendering of a PolicyRule, in the order a reader expects."""
    if rule.is_non_resource_only:
        return (
            f"verbs={list(rule.verbs)} nonResourceURLs={list(rule.non_resource_urls)}"
        )
    # The core group is the empty string.  Printing it as [] would read as "no
    # groups", so it is spelled out.
    groups = "[" + ", ".join(repr(g) if g else '""' for g in rule.api_groups) + "]"
    text = (
        f"verbs={list(rule.verbs)} apiGroups={groups} resources={list(rule.resources)}"
    )
    if rule.resource_names:
        text += f" resourceNames={list(rule.resource_names)}"
    return text


@dataclass
class Reach:
    """Where a subject holds a particular permission."""

    cluster_wide: list[Grant] = field(default_factory=list)
    by_namespace: dict[str, list[Grant]] = field(default_factory=dict)

    @property
    def anywhere(self) -> bool:
        return bool(self.cluster_wide or self.by_namespace)

    def namespaces(self, known: Sequence[str]) -> list[str]:
        """The namespaces the permission is held in.

        A cluster-wide grant reaches every namespace, including namespaces that
        do not exist yet; the dump can only name the ones it knows about, which
        is stated in the output.
        """
        if self.cluster_wide:
            return list(known)
        return sorted(self.by_namespace)

    def grants_in(self, namespace: str | None) -> list[Grant]:
        if namespace is None:
            return list(self.cluster_wide)
        return list(self.cluster_wide) + list(self.by_namespace.get(namespace, []))

    def all_grants(self) -> list[Grant]:
        out = list(self.cluster_wide)
        for grants in self.by_namespace.values():
            out.extend(grants)
        return out


def implicit_groups(subject: Subject) -> set[str]:
    """Group membership the API server synthesises, with no cluster object."""
    if subject.kind == "ServiceAccount":
        return {
            GROUP_AUTHENTICATED,
            GROUP_ALL_SERVICE_ACCOUNTS,
            f"{GROUP_ALL_SERVICE_ACCOUNTS}:{subject.namespace}",
        }
    if subject.kind == "User":
        if subject.name == USER_ANONYMOUS:
            return {GROUP_UNAUTHENTICATED}
        return {GROUP_AUTHENTICATED}
    # A Group subject stands for its members.  Members of any group other than
    # system:unauthenticated presented a credential, so they are also in
    # system:authenticated; asking about system:unauthenticated must not pick
    # up authenticated grants.
    if subject.name in (GROUP_UNAUTHENTICATED,):
        return set()
    return {GROUP_AUTHENTICATED}


class Resolver:
    """Answers permission questions about one Cluster."""

    def __init__(self, cluster: Cluster) -> None:
        self.cluster = cluster
        self._aggregated: dict[RoleRef, tuple[tuple[PolicyRule, RoleRef | None], ...]] = {}
        self._grant_cache: dict[tuple[str, tuple[str, ...]], list[Grant]] = {}

    # -- roles ---------------------------------------------------------------

    def role_rules(self, ref: RoleRef) -> tuple[tuple[PolicyRule, RoleRef | None], ...]:
        """The rules of a role, paired with the role they were aggregated from.

        A ``None`` source means the rule is written in the role itself.
        """
        cached = self._aggregated.get(ref)
        if cached is not None:
            return cached
        resolved = self._resolve_role_rules(ref, set())
        self._aggregated[ref] = resolved
        return resolved

    def _resolve_role_rules(
        self, ref: RoleRef, seen: set[RoleRef]
    ) -> tuple[tuple[PolicyRule, RoleRef | None], ...]:
        role = self.cluster.role(ref)
        if role is None or ref in seen:
            return ()
        seen = seen | {ref}
        out: list[tuple[PolicyRule, RoleRef | None]] = [(rule, None) for rule in role.rules]
        if role.aggregation_selectors:
            for contributor in self.aggregation_contributors(role):
                for rule, _ in self._resolve_role_rules(contributor.ref, seen):
                    out.append((rule, contributor.ref))
        # The controller writes aggregated rules back into .rules, so a dump of
        # a live cluster lists them twice once recomputed.  Keep the first
        # occurrence of each rule so a reader is not shown duplicates, but
        # prefer the entry that names its contributing role.
        deduped: dict[PolicyRule, RoleRef | None] = {}
        for rule, source in out:
            if (rule in deduped and deduped[rule] is None and source is not None) or rule not in deduped:
                deduped[rule] = source
        return tuple((rule, source) for rule, source in deduped.items())

    def aggregation_contributors(self, role: Role) -> list[Role]:
        """ClusterRoles whose labels match one of ``role``'s selectors."""
        if not role.aggregation_selectors:
            return []
        out: list[Role] = []
        for candidate in self.cluster.cluster_roles():
            if candidate.ref == role.ref:
                continue
            labels = candidate.label_map
            if any(selector.matches(labels) for selector in role.aggregation_selectors):
                out.append(candidate)
        return sorted(out, key=lambda r: r.name)

    # -- subjects ------------------------------------------------------------

    def groups_for(self, subject: Subject, extra_groups: Iterable[str] = ()) -> set[str]:
        groups = implicit_groups(subject)
        groups.update(extra_groups)
        if subject.kind == "Group":
            groups.add(subject.name)
        return groups

    def grants(self, subject: Subject, extra_groups: Sequence[str] = ()) -> list[Grant]:
        """Every rule that reaches ``subject``, with its scope and provenance."""
        key = (subject.id, tuple(sorted(extra_groups)))
        cached = self._grant_cache.get(key)
        if cached is not None:
            return cached
        groups = self.groups_for(subject, extra_groups)
        out: list[Grant] = []
        for binding in self.cluster.bindings:
            matched = self._matching_subject(binding, subject, groups)
            if matched is None:
                continue
            # A RoleBinding may only reference a Role in its own namespace.
            if (
                binding.kind == "RoleBinding"
                and binding.role_ref.kind == "Role"
                and binding.role_ref.namespace != binding.namespace
            ):
                continue
            for rule, aggregated_from in self.role_rules(binding.role_ref):
                out.append(
                    Grant(
                        rule=rule,
                        namespace=binding.scope,
                        binding=binding,
                        role=binding.role_ref,
                        via=matched,
                        aggregated_from=aggregated_from,
                    )
                )
        self._grant_cache[key] = out
        return out

    @staticmethod
    def _matching_subject(
        binding: Binding, subject: Subject, groups: set[str]
    ) -> Subject | None:
        for candidate in binding.subjects:
            if candidate == subject:
                return candidate
            if candidate.kind == "Group" and candidate.name in groups:
                return candidate
        return None

    # -- queries -------------------------------------------------------------

    def reach(
        self,
        subject: Subject,
        verb: str,
        api_group: str,
        resource: str,
        subresource: str = "",
        name: str | None = None,
        extra_groups: Sequence[str] = (),
        any_name: bool = False,
        namespaced_attributes: bool = False,
    ) -> Reach:
        """Where ``subject`` may perform ``verb`` on this resource.

        ``any_name=True`` means "on at least one object", which is the question
        an escalation check asks; the default means "on any object", which is
        the question an access review asks.  They differ exactly where a rule
        carries ``resourceNames``.

        ``namespaced_attributes=True`` keeps namespaced grants of a
        cluster-scoped resource.  Normally they authorize nothing, but the
        ``bind`` check the API server performs when a RoleBinding is created
        carries the *binding's* namespace even when the referenced role is a
        ClusterRole.  That is what makes the documented ``role-grantor``
        pattern work: a Role with ``resources: ["clusterroles"]``,
        ``verbs: ["bind"]`` and ``resourceNames: ["admin", "edit", "view"]``
        lets its holder create RoleBindings in that one namespace referencing
        those ClusterRoles.
        """
        combined = f"{resource}/{subresource}" if subresource else resource
        cluster_only = is_cluster_scoped(combined) and not namespaced_attributes
        result = Reach()
        for grant in self.grants(subject, extra_groups):
            if not rule_allows(
                grant.rule, verb, api_group, resource, subresource, name, any_name
            ):
                continue
            if grant.namespace is None:
                result.cluster_wide.append(grant)
            elif not cluster_only:
                result.by_namespace.setdefault(grant.namespace, []).append(grant)
            # A namespaced grant of a cluster-scoped resource authorizes
            # nothing, so it is dropped rather than reported.
        return result

    def reach_non_resource(
        self,
        subject: Subject,
        verb: str,
        path: str,
        extra_groups: Sequence[str] = (),
    ) -> list[Grant]:
        """Non-resource grants only ever arrive cluster-wide."""
        return [
            grant
            for grant in self.grants(subject, extra_groups)
            if grant.namespace is None
            and rule_allows_non_resource(grant.rule, verb, path)
        ]

    def allows(
        self,
        subject: Subject,
        verb: str,
        api_group: str,
        resource: str,
        subresource: str = "",
        namespace: str | None = None,
        name: str | None = None,
        extra_groups: Sequence[str] = (),
    ) -> bool:
        """A direct yes/no, the question ``kubectl auth can-i`` answers."""
        reach = self.reach(
            subject, verb, api_group, resource, subresource, name, extra_groups
        )
        if reach.cluster_wide:
            return True
        if namespace is None:
            return bool(reach.by_namespace)
        return bool(reach.by_namespace.get(namespace))

    # -- enumeration ---------------------------------------------------------

    def all_subjects(self) -> list[Subject]:
        """Every subject worth asking about: bound subjects plus every SA."""
        seen: dict[str, Subject] = {}
        for binding in self.cluster.bindings:
            for subject in binding.subjects:
                seen.setdefault(subject.id, subject)
        for sa in self.cluster.service_accounts:
            subject = Subject("ServiceAccount", sa.name, sa.namespace)
            seen.setdefault(subject.id, subject)
        for pod in self.cluster.pods:
            subject = Subject("ServiceAccount", pod.service_account, pod.namespace)
            seen.setdefault(subject.id, subject)
        return [seen[key] for key in sorted(seen)]

    def open_bindings(self) -> list[tuple[Binding, Subject]]:
        """Bindings whose subject list includes a whole-cluster group."""
        out: list[tuple[Binding, Subject]] = []
        for binding in self.cluster.bindings:
            for subject in binding.subjects:
                if subject.kind != "Group":
                    continue
                if subject.name in OPEN_GROUPS or subject.name.startswith(
                    f"{GROUP_ALL_SERVICE_ACCOUNTS}:"
                ):
                    out.append((binding, subject))
        return out
