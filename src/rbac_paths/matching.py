"""Rule matching, following the upstream authorizer.

The functions here mirror ``k8s.io/kubernetes/pkg/registry/rbac/validation``
(``VerbMatches``, ``APIGroupMatches``, ``ResourceMatches``,
``ResourceNameMatches``, ``NonResourceURLMatches``).  Modelled against
Kubernetes 1.29-1.34, in which these functions have not changed.

Three results surprise people and are each covered by a test:

1. ``resources: ["pods"]`` does **not** cover ``pods/exec``.  Subresources are
   separate resource strings; a rule must name ``pods/exec``, ``*/exec`` or
   ``*``.
2. ``resources: ["*"]`` **does** cover ``pods/exec``.  ``ResourceMatches``
   returns true for ``*`` before it ever looks at the subresource.  A wildcard
   resource in a namespace is therefore exec into every pod in it.
3. A rule with ``resourceNames`` cannot authorize ``create``, ``list``,
   ``watch`` or ``deletecollection``, because the authorizer is given no object
   name for those requests.  ``create`` on a *subresource* is the exception:
   ``create serviceaccounts/token`` addresses ``.../serviceaccounts/<name>/token``,
   so the name is known and ``resourceNames`` does restrict it.
"""

from __future__ import annotations

from .model import ALL, PolicyRule, verb_has_no_object_name


def split_resource(resource: str) -> tuple[str, str]:
    """Split ``pods/exec`` into ``("pods", "exec")``.

    A bare resource yields an empty subresource.  Only the first slash is
    significant: the API server has no nested subresources.
    """
    head, _, tail = resource.partition("/")
    return head, tail


def verb_matches(rule: PolicyRule, verb: str) -> bool:
    return ALL in rule.verbs or verb in rule.verbs


def api_group_matches(rule: PolicyRule, api_group: str) -> bool:
    """Match an API group.  The core group is the empty string, not "core"."""
    return ALL in rule.api_groups or api_group in rule.api_groups


def resource_matches(rule: PolicyRule, resource: str, subresource: str = "") -> bool:
    combined = f"{resource}/{subresource}" if subresource else resource
    for rule_resource in rule.resources:
        if rule_resource == ALL:
            return True
        if rule_resource == combined:
            return True
        if not subresource:
            continue
        if rule_resource == f"{ALL}/{subresource}":
            return True
    return False


def resource_name_matches(rule: PolicyRule, name: str | None) -> bool:
    """Match the requested object name against ``resourceNames``.

    ``name=None`` asks whether the rule grants the verb over *any* object.  A
    rule carrying ``resourceNames`` does not, so it answers False.
    """
    if not rule.resource_names:
        return True
    if name is None:
        return False
    return name in rule.resource_names


def non_resource_url_matches(rule: PolicyRule, path: str) -> bool:
    """Match a non-resource path.  Only a trailing ``*`` is a wildcard."""
    for pattern in rule.non_resource_urls:
        if pattern == ALL:
            return True
        if pattern == path:
            return True
        if pattern.endswith(ALL) and path.startswith(pattern[:-1]):
            return True
    return False


def rule_allows(
    rule: PolicyRule,
    verb: str,
    api_group: str,
    resource: str,
    subresource: str = "",
    name: str | None = None,
    any_name: bool = False,
) -> bool:
    """Whether one PolicyRule authorizes one resource request.

    Scope is not considered here; the resolver decides which namespaces a rule
    reaches before calling this.

    ``any_name=True`` asks a different question: can the verb be performed on
    *at least one* object?  That is what an escalation check wants, because an
    attacker picks the object.  It does not relax the rule that a
    ``resourceNames`` rule cannot authorize a nameless verb, so
    ``create`` + ``resourceNames`` still grants nothing.
    """
    if rule.is_non_resource_only:
        return False
    if not verb_matches(rule, verb):
        return False
    if not api_group_matches(rule, api_group):
        return False
    if not resource_matches(rule, resource, subresource):
        return False
    if rule.resource_names and verb_has_no_object_name(verb, subresource):
        # The authorizer sees no object name for this request, so a rule that
        # demands a particular name can never be satisfied by it.
        return False
    if any_name:
        return True
    return resource_name_matches(rule, name)


def rule_allows_non_resource(rule: PolicyRule, verb: str, path: str) -> bool:
    if not rule.non_resource_urls:
        return False
    if not verb_matches(rule, verb):
        return False
    return non_resource_url_matches(rule, path)


def rule_is_full_wildcard(rule: PolicyRule) -> bool:
    """A rule equivalent to ``cluster-admin``'s first rule."""
    return (
        ALL in rule.verbs
        and ALL in rule.api_groups
        and ALL in rule.resources
        and not rule.resource_names
    )
