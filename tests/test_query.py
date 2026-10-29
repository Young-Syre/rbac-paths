"""The who-can query."""

from __future__ import annotations

import unittest

import fixtures as fx
from rbac_paths.query import parse_resource, query_warnings, who_can
from rbac_paths.resolver import Resolver


def resolver(items):
    return Resolver(fx.build(items))


class ParseResourceTests(unittest.TestCase):
    def test_plain(self):
        spec = parse_resource("secrets")
        self.assertEqual((spec.resource, spec.subresource, spec.api_group), ("secrets", "", ""))

    def test_subresource(self):
        spec = parse_resource("pods/exec")
        self.assertEqual((spec.resource, spec.subresource), ("pods", "exec"))

    def test_dotted_group(self):
        spec = parse_resource("deployments.apps")
        self.assertEqual((spec.resource, spec.api_group), ("deployments", "apps"))

    def test_dotted_group_with_subresource(self):
        spec = parse_resource("certificatesigningrequests.certificates.k8s.io/approval")
        self.assertEqual(spec.resource, "certificatesigningrequests")
        self.assertEqual(spec.api_group, "certificates.k8s.io")
        self.assertEqual(spec.subresource, "approval")

    def test_flag_overrides_the_suffix(self):
        spec = parse_resource("deployments.apps", api_group="")
        self.assertEqual(spec.api_group, "")

    def test_core_alias(self):
        self.assertEqual(parse_resource("pods", api_group="core").api_group, "")

    def test_empty_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_resource("  ")

    def test_slash_only_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_resource("/exec")

    def test_rendering_round_trips(self):
        self.assertEqual(str(parse_resource("deployments.apps")), "deployments.apps")
        self.assertEqual(str(parse_resource("pods/exec")), "pods/exec")


BASE = [
    fx.cluster_role("reader", [fx.rule(["get", "list"], [""], ["secrets"])]),
    fx.cluster_role_binding("reader-crb", "reader", [fx.sa_subject("ci", "runner")]),
    fx.service_account("ci", "runner"),
    fx.service_account("ci", "idle"),
]


class WhoCanTests(unittest.TestCase):
    def test_finds_the_bound_subject(self):
        rows = who_can(resolver(BASE), "get", parse_resource("secrets"))
        self.assertEqual([r.subject.id for r in rows], ["sa:ci:runner"])

    def test_unbound_accounts_are_absent(self):
        rows = who_can(resolver(BASE), "get", parse_resource("secrets"))
        self.assertNotIn("sa:ci:idle", [r.subject.id for r in rows])

    def test_nobody_can_do_an_ungranted_verb(self):
        self.assertEqual(who_can(resolver(BASE), "delete", parse_resource("secrets")), [])

    def test_cluster_wide_rows_say_so(self):
        rows = who_can(resolver(BASE), "get", parse_resource("secrets"))
        self.assertTrue(rows[0].cluster_wide)
        self.assertEqual(rows[0].scope_text, "all namespaces")

    def test_namespace_scoped_rows_list_the_namespace(self):
        items = [
            fx.namespaced_role("reader", "ci", [fx.rule(["get"], [""], ["secrets"])]),
            fx.role_binding("rb", "ci", "reader", "Role", [fx.sa_subject("ci", "runner")]),
        ]
        rows = who_can(resolver(items), "get", parse_resource("secrets"))
        self.assertEqual(rows[0].scope_text, "ci")

    def test_wildcards_expand(self):
        items = [
            fx.cluster_role("star", [fx.rule(["*"], ["*"], ["*"])]),
            fx.cluster_role_binding("crb", "star", [fx.sa_subject("ci", "runner")]),
        ]
        rows = who_can(resolver(items), "escalate", parse_resource("clusterroles.rbac.authorization.k8s.io"))
        self.assertEqual([r.subject.id for r in rows], ["sa:ci:runner"])

    def test_group_membership_is_reported(self):
        items = [
            fx.cluster_role("reader", [fx.rule(["get"], [""], ["secrets"])]),
            fx.cluster_role_binding("crb", "reader", [fx.group_subject("system:authenticated")]),
            fx.service_account("ci", "runner"),
        ]
        rows = who_can(resolver(items), "get", parse_resource("secrets"))
        ids = [r.subject.id for r in rows]
        self.assertIn("group:system:authenticated", ids)
        self.assertIn("sa:ci:runner", ids)
        runner = next(r for r in rows if r.subject.id == "sa:ci:runner")
        self.assertEqual(runner.via_groups, ["system:authenticated"])

    def test_aggregation_is_reported(self):
        items = [
            fx.cluster_role("tenant", [], aggregation=[{"matchLabels": {"agg": "y"}}]),
            fx.cluster_role("addon", [fx.rule(["get"], [""], ["secrets"])], labels={"agg": "y"}),
            fx.cluster_role_binding("crb", "tenant", [fx.sa_subject("ci", "runner")]),
        ]
        rows = who_can(resolver(items), "get", parse_resource("secrets"))
        self.assertEqual(rows[0].aggregated_from, ["ClusterRole addon"])

    def test_resource_names_hide_a_subject_from_the_unrestricted_question(self):
        items = [
            fx.namespaced_role(
                "reader", "ci", [fx.rule(["get"], [""], ["secrets"], resource_names=["one"])]
            ),
            fx.role_binding("rb", "ci", "reader", "Role", [fx.sa_subject("ci", "runner")]),
        ]
        self.assertEqual(who_can(resolver(items), "get", parse_resource("secrets")), [])

    def test_naming_the_object_reveals_the_subject(self):
        items = [
            fx.namespaced_role(
                "reader", "ci", [fx.rule(["get"], [""], ["secrets"], resource_names=["one"])]
            ),
            fx.role_binding("rb", "ci", "reader", "Role", [fx.sa_subject("ci", "runner")]),
        ]
        rows = who_can(resolver(items), "get", parse_resource("secrets"), name="one")
        self.assertEqual([r.subject.id for r in rows], ["sa:ci:runner"])

    def test_naming_another_object_does_not(self):
        items = [
            fx.namespaced_role(
                "reader", "ci", [fx.rule(["get"], [""], ["secrets"], resource_names=["one"])]
            ),
            fx.role_binding("rb", "ci", "reader", "Role", [fx.sa_subject("ci", "runner")]),
        ]
        self.assertEqual(
            who_can(resolver(items), "get", parse_resource("secrets"), name="two"), []
        )

    def test_namespace_filter_excludes_other_namespaces(self):
        items = [
            fx.namespaced_role("reader", "ci", [fx.rule(["get"], [""], ["secrets"])]),
            fx.role_binding("rb", "ci", "reader", "Role", [fx.sa_subject("ci", "runner")]),
        ]
        self.assertEqual(
            who_can(resolver(items), "get", parse_resource("secrets"), namespace="platform"), []
        )

    def test_cluster_scoped_resource_through_a_role_binding_is_absent(self):
        items = [
            fx.cluster_role("noder", [fx.rule(["get"], [""], ["nodes"])]),
            fx.role_binding("rb", "ci", "noder", "ClusterRole", [fx.sa_subject("ci", "runner")]),
        ]
        self.assertEqual(who_can(resolver(items), "get", parse_resource("nodes")), [])

    def test_cluster_wide_rows_sort_first(self):
        items = [
            fx.cluster_role("reader", [fx.rule(["get"], [""], ["secrets"])]),
            fx.cluster_role_binding("crb", "reader", [fx.sa_subject("ci", "wide")]),
            fx.namespaced_role("local", "ci", [fx.rule(["get"], [""], ["secrets"])]),
            fx.role_binding("rb", "ci", "local", "Role", [fx.sa_subject("ci", "narrow")]),
        ]
        rows = who_can(resolver(items), "get", parse_resource("secrets"))
        self.assertTrue(rows[0].cluster_wide)
        self.assertFalse(rows[-1].cluster_wide)


class WarningTests(unittest.TestCase):
    def test_name_with_list_is_flagged(self):
        warnings = query_warnings("list", parse_resource("secrets"), "one")
        self.assertTrue(any("ignored for `list" in w for w in warnings))

    def test_name_with_get_is_not_flagged(self):
        warnings = query_warnings("get", parse_resource("secrets"), "one")
        self.assertFalse(any("ignored" in w for w in warnings))

    def test_name_with_create_on_a_subresource_is_not_flagged(self):
        warnings = query_warnings("create", parse_resource("serviceaccounts/token"), "one")
        self.assertFalse(any("ignored" in w for w in warnings))

    def test_name_with_create_on_a_resource_is_flagged(self):
        warnings = query_warnings("create", parse_resource("pods"), "one")
        self.assertTrue(any("ignored" in w for w in warnings))

    def test_cluster_scoped_resources_are_explained(self):
        warnings = query_warnings("get", parse_resource("nodes"), None)
        self.assertTrue(any("cluster-scoped" in w for w in warnings))

    def test_subresource_queries_explain_the_matching_rule(self):
        warnings = query_warnings("create", parse_resource("pods/exec"), None)
        self.assertTrue(any("*/exec" in w for w in warnings))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
