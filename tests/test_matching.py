"""Rule matching semantics, checked against the upstream authorizer."""

from __future__ import annotations

import unittest

from rbac_paths.matching import (
    api_group_matches,
    non_resource_url_matches,
    resource_matches,
    resource_name_matches,
    rule_allows,
    rule_allows_non_resource,
    rule_is_full_wildcard,
    split_resource,
    verb_matches,
)
from rbac_paths.model import PolicyRule


def pr(**kwargs) -> PolicyRule:
    return PolicyRule(
        verbs=tuple(kwargs.get("verbs", ())),
        api_groups=tuple(kwargs.get("api_groups", ())),
        resources=tuple(kwargs.get("resources", ())),
        resource_names=tuple(kwargs.get("resource_names", ())),
        non_resource_urls=tuple(kwargs.get("non_resource_urls", ())),
    )


class SplitResourceTests(unittest.TestCase):
    def test_bare_resource(self):
        self.assertEqual(split_resource("pods"), ("pods", ""))

    def test_subresource(self):
        self.assertEqual(split_resource("pods/exec"), ("pods", "exec"))

    def test_only_first_slash_is_significant(self):
        self.assertEqual(split_resource("pods/exec/extra"), ("pods", "exec/extra"))

    def test_wildcard_subresource_form(self):
        self.assertEqual(split_resource("*/exec"), ("*", "exec"))


class VerbTests(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(verb_matches(pr(verbs=["get"]), "get"))

    def test_miss(self):
        self.assertFalse(verb_matches(pr(verbs=["get"]), "list"))

    def test_wildcard(self):
        self.assertTrue(verb_matches(pr(verbs=["*"]), "deletecollection"))

    def test_wildcard_covers_escalate(self):
        self.assertTrue(verb_matches(pr(verbs=["*"]), "escalate"))


class ApiGroupTests(unittest.TestCase):
    def test_core_group_is_the_empty_string(self):
        self.assertTrue(api_group_matches(pr(api_groups=[""]), ""))

    def test_core_rule_does_not_cover_apps(self):
        self.assertFalse(api_group_matches(pr(api_groups=[""]), "apps"))

    def test_apps_rule_does_not_cover_core(self):
        self.assertFalse(api_group_matches(pr(api_groups=["apps"]), ""))

    def test_wildcard_group(self):
        self.assertTrue(api_group_matches(pr(api_groups=["*"]), "rbac.authorization.k8s.io"))


class ResourceMatchTests(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(resource_matches(pr(resources=["pods"]), "pods"))

    def test_plain_resource_does_not_cover_subresource(self):
        # The point people get wrong: `pods` is not `pods/exec`.
        self.assertFalse(resource_matches(pr(resources=["pods"]), "pods", "exec"))

    def test_named_subresource_matches(self):
        self.assertTrue(resource_matches(pr(resources=["pods/exec"]), "pods", "exec"))

    def test_named_subresource_does_not_cover_the_parent(self):
        self.assertFalse(resource_matches(pr(resources=["pods/exec"]), "pods"))

    def test_wildcard_resource_matches_subresource(self):
        # Upstream ResourceMatches returns true for ResourceAll before it looks
        # at the subresource at all, so `*` really does include pods/exec.
        self.assertTrue(resource_matches(pr(resources=["*"]), "pods", "exec"))

    def test_wildcard_resource_matches_plain_resource(self):
        self.assertTrue(resource_matches(pr(resources=["*"]), "secrets"))

    def test_star_slash_subresource_form(self):
        self.assertTrue(resource_matches(pr(resources=["*/exec"]), "pods", "exec"))

    def test_star_slash_subresource_does_not_cross_subresources(self):
        self.assertFalse(resource_matches(pr(resources=["*/exec"]), "pods", "attach"))

    def test_star_slash_subresource_does_not_match_plain(self):
        self.assertFalse(resource_matches(pr(resources=["*/exec"]), "pods"))

    def test_different_resource(self):
        self.assertFalse(resource_matches(pr(resources=["pods"]), "secrets"))


class ResourceNameTests(unittest.TestCase):
    def test_absent_resource_names_match_anything(self):
        self.assertTrue(resource_name_matches(pr(resources=["secrets"]), "anything"))

    def test_absent_resource_names_match_the_unrestricted_question(self):
        self.assertTrue(resource_name_matches(pr(resources=["secrets"]), None))

    def test_named_match(self):
        self.assertTrue(resource_name_matches(pr(resource_names=["a", "b"]), "b"))

    def test_named_miss(self):
        self.assertFalse(resource_name_matches(pr(resource_names=["a"]), "b"))

    def test_named_rule_is_not_unrestricted(self):
        self.assertFalse(resource_name_matches(pr(resource_names=["a"]), None))


class NonResourceUrlTests(unittest.TestCase):
    def test_exact_path(self):
        self.assertTrue(non_resource_url_matches(pr(non_resource_urls=["/healthz"]), "/healthz"))

    def test_prefix_wildcard(self):
        self.assertTrue(
            non_resource_url_matches(pr(non_resource_urls=["/apis/*"]), "/apis/apps/v1")
        )

    def test_prefix_wildcard_does_not_match_a_sibling(self):
        self.assertFalse(
            non_resource_url_matches(pr(non_resource_urls=["/apis/*"]), "/version")
        )

    def test_full_wildcard(self):
        self.assertTrue(non_resource_url_matches(pr(non_resource_urls=["*"]), "/debug/pprof"))

    def test_no_mid_path_wildcard(self):
        self.assertFalse(
            non_resource_url_matches(pr(non_resource_urls=["/a/*/c"]), "/a/b/c")
        )


class RuleAllowsTests(unittest.TestCase):
    def test_simple_allow(self):
        self.assertTrue(rule_allows(pr(verbs=["get"], api_groups=[""], resources=["pods"]), "get", "", "pods"))

    def test_wrong_group_denies(self):
        self.assertFalse(
            rule_allows(pr(verbs=["get"], api_groups=["apps"], resources=["pods"]), "get", "", "pods")
        )

    def test_resource_names_block_create(self):
        # create carries the name in the body, so the authorizer has no name to
        # compare: a resourceNames rule can never authorize it.
        self.assertFalse(
            rule_allows(
                pr(verbs=["create"], api_groups=[""], resources=["secrets"], resource_names=["x"]),
                "create",
                "",
                "secrets",
                name="x",
            )
        )

    def test_resource_names_block_list(self):
        self.assertFalse(
            rule_allows(
                pr(verbs=["list"], api_groups=[""], resources=["secrets"], resource_names=["x"]),
                "list",
                "",
                "secrets",
                name="x",
            )
        )

    def test_resource_names_block_watch(self):
        self.assertFalse(
            rule_allows(
                pr(verbs=["watch"], api_groups=[""], resources=["secrets"], resource_names=["x"]),
                "watch",
                "",
                "secrets",
                name="x",
            )
        )

    def test_resource_names_block_deletecollection(self):
        self.assertFalse(
            rule_allows(
                pr(
                    verbs=["deletecollection"],
                    api_groups=[""],
                    resources=["secrets"],
                    resource_names=["x"],
                ),
                "deletecollection",
                "",
                "secrets",
                name="x",
            )
        )

    def test_resource_names_allow_get_of_that_name(self):
        self.assertTrue(
            rule_allows(
                pr(verbs=["get"], api_groups=[""], resources=["secrets"], resource_names=["x"]),
                "get",
                "",
                "secrets",
                name="x",
            )
        )

    def test_resource_names_deny_get_of_another_name(self):
        self.assertFalse(
            rule_allows(
                pr(verbs=["get"], api_groups=[""], resources=["secrets"], resource_names=["x"]),
                "get",
                "",
                "secrets",
                name="y",
            )
        )

    def test_resource_names_deny_the_unrestricted_question(self):
        self.assertFalse(
            rule_allows(
                pr(verbs=["get"], api_groups=[""], resources=["secrets"], resource_names=["x"]),
                "get",
                "",
                "secrets",
            )
        )

    def test_any_name_sees_a_restricted_rule(self):
        self.assertTrue(
            rule_allows(
                pr(verbs=["get"], api_groups=[""], resources=["secrets"], resource_names=["x"]),
                "get",
                "",
                "secrets",
                any_name=True,
            )
        )

    def test_any_name_does_not_rescue_create(self):
        self.assertFalse(
            rule_allows(
                pr(verbs=["create"], api_groups=[""], resources=["pods"], resource_names=["x"]),
                "create",
                "",
                "pods",
                any_name=True,
            )
        )

    def test_non_resource_only_rule_grants_no_resource(self):
        self.assertFalse(
            rule_allows(pr(verbs=["get"], non_resource_urls=["*"]), "get", "", "pods")
        )

    def test_non_resource_rule_grants_the_path(self):
        self.assertTrue(
            rule_allows_non_resource(pr(verbs=["get"], non_resource_urls=["*"]), "get", "/metrics")
        )

    def test_resource_rule_grants_no_non_resource_path(self):
        self.assertFalse(
            rule_allows_non_resource(
                pr(verbs=["get"], api_groups=[""], resources=["pods"]), "get", "/metrics"
            )
        )

    def test_subresource_request_needs_a_subresource_rule(self):
        self.assertFalse(
            rule_allows(pr(verbs=["create"], api_groups=[""], resources=["pods"]), "create", "", "pods", "exec")
        )
        self.assertTrue(
            rule_allows(
                pr(verbs=["create"], api_groups=[""], resources=["pods/exec"]),
                "create",
                "",
                "pods",
                "exec",
            )
        )


class FullWildcardTests(unittest.TestCase):
    def test_cluster_admin_shape(self):
        self.assertTrue(
            rule_is_full_wildcard(pr(verbs=["*"], api_groups=["*"], resources=["*"]))
        )

    def test_group_restricted_is_not_full(self):
        self.assertFalse(
            rule_is_full_wildcard(pr(verbs=["*"], api_groups=["apps"], resources=["*"]))
        )

    def test_resource_names_make_it_not_full(self):
        self.assertFalse(
            rule_is_full_wildcard(
                pr(verbs=["*"], api_groups=["*"], resources=["*"], resource_names=["x"])
            )
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
