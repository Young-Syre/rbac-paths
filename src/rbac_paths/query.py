"""The ``who-can`` query.

This answers the question ``kubectl auth can-i --list`` answers one subject at
a time, for every subject at once and without an API server.  The expansion
that matters is in the resolver: wildcards, ClusterRole aggregation, and the
groups the API server synthesises.  A ClusterRoleBinding to
``system:authenticated`` shows up here as the group itself, because enumerating
"every identity in the cluster" by name would be a longer and less useful
answer than naming the group.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Subject, verb_has_no_object_name
from .resolver import Grant, Resolver, is_cluster_scoped


@dataclass(frozen=True)
class ResourceSpec:
    """A resource as written on the command line."""

    resource: str
    subresource: str = ""
    api_group: str = ""

    @property
    def combined(self) -> str:
        return f"{self.resource}/{self.subresource}" if self.subresource else self.resource

    def __str__(self) -> str:
        text = self.combined
        if self.api_group:
            text = f"{self.resource}.{self.api_group}"
            if self.subresource:
                text += f"/{self.subresource}"
        return text


def parse_resource(spec: str, api_group: str | None = None) -> ResourceSpec:
    """Parse ``secrets``, ``pods/exec``, ``deployments.apps``, ``nodes.../proxy``.

    The API group may be given either as a suffix after a dot or with
    ``--api-group``; the flag wins.  The core group is the empty string, and
    ``core`` is accepted as an alias for it because ``kubectl`` prints it that
    way in some places.
    """
    raw = spec.strip()
    if not raw:
        raise ValueError("empty resource")
    head, _, subresource = raw.partition("/")
    resource, _, suffix_group = head.partition(".")
    if not resource:
        raise ValueError(f"{spec!r}: no resource name")
    group = api_group if api_group is not None else suffix_group
    if group in ("core", '""'):
        group = ""
    return ResourceSpec(resource=resource, subresource=subresource, api_group=group)


@dataclass
class WhoCanRow:
    subject: Subject
    cluster_wide: bool
    namespaces: list[str]
    grants: list[Grant]

    @property
    def scope_text(self) -> str:
        if self.cluster_wide:
            return "all namespaces"
        if not self.namespaces:
            return "none"
        return ", ".join(self.namespaces)

    @property
    def via_groups(self) -> list[str]:
        return sorted({g.via.name for g in self.grants if g.via.kind == "Group"})

    @property
    def aggregated_from(self) -> list[str]:
        return sorted({str(g.aggregated_from) for g in self.grants if g.aggregated_from})


def who_can(
    resolver: Resolver,
    verb: str,
    spec: ResourceSpec,
    namespace: str | None = None,
    name: str | None = None,
    extra_groups: tuple[str, ...] = (),
) -> list[WhoCanRow]:
    """Every subject that may perform ``verb`` on ``spec``.

    ``name`` narrows to one object, which also lets rules carrying
    ``resourceNames`` match.  It is ignored for the verbs the authorizer has no
    name for, and the caller is told so rather than being quietly given a
    different answer.
    """
    effective_name = None if verb_has_no_object_name(verb, spec.subresource) else name
    rows: list[WhoCanRow] = []
    for subject in resolver.all_subjects():
        reach = resolver.reach(
            subject,
            verb,
            spec.api_group,
            spec.resource,
            spec.subresource,
            effective_name,
            extra_groups=extra_groups,
        )
        if not reach.anywhere:
            continue
        namespaces = reach.namespaces(resolver.cluster.known_namespaces())
        if namespace is not None and not reach.cluster_wide:
            if namespace not in reach.by_namespace:
                continue
            namespaces = [namespace]
        rows.append(
            WhoCanRow(
                subject=subject,
                cluster_wide=bool(reach.cluster_wide),
                namespaces=namespaces,
                grants=reach.all_grants(),
            )
        )
    rows.sort(key=lambda r: (not r.cluster_wide, r.subject.kind, r.subject.id))
    return rows


def query_warnings(verb: str, spec: ResourceSpec, name: str | None) -> list[str]:
    """Things about a query the user should know before reading the answer."""
    out: list[str] = []
    if name and verb_has_no_object_name(verb, spec.subresource):
        out.append(
            f"--name is ignored for `{verb} {spec.combined}`: the authorizer is given "
            "no object name for that request, so resourceNames cannot apply to it"
        )
    if verb == "create" and spec.subresource and not name:
        out.append(
            f"`create {spec.combined}` addresses a named object, so a rule with "
            "resourceNames can restrict it; pass --name to ask about one object"
        )
    if is_cluster_scoped(spec.combined):
        out.append(
            f"{spec.combined} is cluster-scoped, so only ClusterRoleBindings can grant "
            "it; grants arriving through a RoleBinding are excluded because they "
            "authorize nothing"
        )
    if spec.subresource:
        out.append(
            f"a rule must name {spec.combined}, */{spec.subresource} or * to match: a "
            f"rule listing only {spec.resource} does not cover its subresources"
        )
    return out
