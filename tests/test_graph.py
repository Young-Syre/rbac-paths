"""Path search: ordering, de-duplication, cycles and custom targets."""

from __future__ import annotations

import unittest

import fixtures as fx
from rbac_paths.graph import (
    GOAL,
    Analysis,
    collect_all_edges,
    find_paths,
    known_cluster_summary,
    node_label,
    parse_subject,
    parse_target,
    reachable_subjects,
)
from rbac_paths.resolver import Resolver

RBAC = "rbac.authorization.k8s.io"
ADMISSION = "admissionregistration.k8s.io"


def analyse(items, psa="privileged"):
    cluster = fx.build(items)
    return Analysis(cluster=cluster, resolver=Resolver(cluster), assume_psa=psa)


class ParseSubjectTests(unittest.TestCase):
    def test_sa_form(self):
        self.assertEqual(parse_subject("sa:ci:runner").id, "sa:ci:runner")

    def test_system_serviceaccount_form(self):
        self.assertEqual(
            parse_subject("system:serviceaccount:ci:runner").id, "sa:ci:runner"
        )

    def test_user_form(self):
        self.assertEqual(parse_subject("user:alice").id, "user:alice")

    def test_group_form(self):
        self.assertEqual(parse_subject("group:platform").id, "group:platform")

    def test_bare_system_name_is_a_group(self):
        self.assertEqual(parse_subject("system:authenticated").kind, "Group")

    def test_incomplete_sa_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_subject("sa:ci")

    def test_bare_name_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_subject("runner")

    def test_empty_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_subject("  ")

    def test_whitespace_is_trimmed(self):
        self.assertEqual(parse_subject(" sa:ci:runner ").id, "sa:ci:runner")


class ParseTargetTests(unittest.TestCase):
    def test_cluster_admin(self):
        self.assertEqual(parse_target("cluster-admin"), GOAL)

    def test_permission_target(self):
        self.assertEqual(parse_target("get:secrets"), "perm:get::secrets")

    def test_permission_target_with_a_group(self):
        self.assertEqual(parse_target("patch:deployments.apps"), "perm:patch:apps:deployments")

    def test_rubbish_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_target("secrets")


class NodeLabelTests(unittest.TestCase):
    def test_goal(self):
        self.assertIn("cluster-admin", node_label(GOAL))

    def test_service_account(self):
        self.assertEqual(node_label("sa:ci:runner"), "ServiceAccount ci/runner")

    def test_node(self):
        self.assertEqual(node_label("node:worker-1"), "node worker-1")

    def test_namespace_admin(self):
        self.assertIn("namespace ci", node_label("nsadmin:ci"))

    def test_permission(self):
        self.assertEqual(node_label("perm:get::secrets"), "get secrets")

    def test_permission_with_a_group(self):
        self.assertEqual(node_label("perm:patch:apps:deployments"), "patch deployments.apps")

    def test_user_and_group(self):
        self.assertEqual(node_label("user:alice"), "User alice")
        self.assertEqual(node_label("group:platform"), "Group platform")


#: pipeline-runner -> (patch deployments in platform) -> operator -> (webhooks) -> admin
TWO_HOP = [
    fx.namespace("platform"),
    fx.service_account("ci", "pipeline-runner"),
    fx.service_account("platform", "operator"),
    fx.cluster_role("deployer", [fx.rule(["patch"], ["apps"], ["deployments"])]),
    fx.role_binding(
        "deployer", "platform", "deployer", "ClusterRole", [fx.sa_subject("ci", "pipeline-runner")]
    ),
    fx.cluster_role(
        "injector", [fx.rule(["create"], [ADMISSION], ["mutatingwebhookconfigurations"])]
    ),
    fx.cluster_role_binding("injector", "injector", [fx.sa_subject("platform", "operator")]),
]


class PathSearchTests(unittest.TestCase):
    def test_a_two_hop_path_is_found(self):
        paths = find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner")
        self.assertTrue(paths)
        self.assertEqual(paths[0].length, 2)

    def test_the_chain_names_both_rules(self):
        paths = find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner")
        self.assertEqual([e.rule_id for e in paths[0].edges], ["RBAC-011", "RBAC-006"])

    def test_the_path_nodes_run_source_to_target(self):
        paths = find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner")
        self.assertEqual(paths[0].nodes()[0], "sa:ci:pipeline-runner")
        self.assertEqual(paths[0].nodes()[-1], GOAL)

    def test_a_subject_with_nothing_has_no_path(self):
        self.assertEqual(find_paths(analyse(TWO_HOP), "sa:ci:nobody"), [])

    def test_shortest_first(self):
        items = [
            *TWO_HOP,
            fx.cluster_role("direct", [fx.rule(["impersonate"], [""], ["groups"])]),
            fx.cluster_role_binding(
                "direct", "direct", [fx.sa_subject("ci", "pipeline-runner")]
            ),
        ]
        paths = find_paths(analyse(items), "sa:ci:pipeline-runner")
        self.assertEqual(paths[0].length, 1)
        self.assertEqual(paths[0].edges[0].rule_id, "RBAC-004")

    def test_max_depth_prunes_long_paths(self):
        self.assertEqual(find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner", max_depth=1), [])

    def test_max_paths_caps_the_result(self):
        items = [
            *TWO_HOP,
            fx.cluster_role("direct", [fx.rule(["impersonate"], [""], ["groups"])]),
            fx.cluster_role_binding(
                "direct", "direct", [fx.sa_subject("ci", "pipeline-runner")]
            ),
        ]
        paths = find_paths(analyse(items), "sa:ci:pipeline-runner", max_paths=1)
        self.assertEqual(len(paths), 1)

    def test_paths_are_de_duplicated(self):
        paths = find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner")
        self.assertEqual(len(paths), len({p.key for p in paths}))

    def test_no_path_revisits_a_node(self):
        paths = find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner")
        for path in paths:
            nodes = path.nodes()
            self.assertEqual(len(nodes), len(set(nodes)))

    def test_a_cycle_terminates(self):
        # Two service accounts that can each exec into the other's pod.
        items = [
            fx.pod("a-1", "a", sa="a-sa"),
            fx.pod("b-1", "b", sa="b-sa"),
            fx.service_account("a", "a-sa"),
            fx.service_account("b", "b-sa"),
            fx.cluster_role("exec", [fx.rule(["create"], [""], ["pods/exec"])]),
            fx.role_binding("x", "b", "exec", "ClusterRole", [fx.sa_subject("a", "a-sa")]),
            fx.role_binding("y", "a", "exec", "ClusterRole", [fx.sa_subject("b", "b-sa")]),
        ]
        self.assertEqual(find_paths(analyse(items), "sa:a:a-sa"), [])

    def test_a_cycle_does_not_stop_a_real_path(self):
        items = [
            fx.pod("a-1", "a", sa="a-sa"),
            fx.pod("b-1", "b", sa="b-sa"),
            fx.service_account("a", "a-sa"),
            fx.service_account("b", "b-sa"),
            fx.cluster_role("exec", [fx.rule(["create"], [""], ["pods/exec"])]),
            fx.role_binding("x", "b", "exec", "ClusterRole", [fx.sa_subject("a", "a-sa")]),
            fx.role_binding("y", "a", "exec", "ClusterRole", [fx.sa_subject("b", "b-sa")]),
            fx.cluster_role("wh", [fx.rule(["create"], [ADMISSION], ["mutatingwebhookconfigurations"])]),
            fx.cluster_role_binding("wh", "wh", [fx.sa_subject("b", "b-sa")]),
        ]
        paths = find_paths(analyse(items), "sa:a:a-sa")
        self.assertTrue(paths)
        self.assertEqual(paths[0].length, 2)

    def test_worst_severity_is_the_most_severe_hop(self):
        paths = find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner")
        self.assertEqual(paths[0].worst_severity, "critical")

    def test_source_and_target_properties(self):
        path = find_paths(analyse(TWO_HOP), "sa:ci:pipeline-runner")[0]
        self.assertEqual(path.source, "sa:ci:pipeline-runner")
        self.assertEqual(path.target, GOAL)


class PermissionTargetTests(unittest.TestCase):
    def test_a_permission_target_is_reached_directly(self):
        items = [
            fx.cluster_role("reader", [fx.rule(["get"], [""], ["secrets"])]),
            fx.cluster_role_binding("crb", "reader", [fx.sa_subject("ci", "runner")]),
            fx.service_account("ci", "runner"),
        ]
        paths = find_paths(analyse(items), "sa:ci:runner", parse_target("get:secrets"))
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].length, 1)

    def test_a_permission_target_is_reached_through_a_hop(self):
        items = [
            fx.pod("app-1", "platform", sa="operator"),
            fx.service_account("platform", "operator"),
            fx.service_account("ci", "runner"),
            fx.cluster_role("exec", [fx.rule(["create"], [""], ["pods/exec"])]),
            fx.role_binding("x", "platform", "exec", "ClusterRole", [fx.sa_subject("ci", "runner")]),
            fx.cluster_role("reader", [fx.rule(["get"], [""], ["secrets"])]),
            fx.cluster_role_binding("crb", "reader", [fx.sa_subject("platform", "operator")]),
        ]
        paths = find_paths(analyse(items), "sa:ci:runner", parse_target("get:secrets"))
        self.assertTrue(paths)
        self.assertEqual(paths[0].length, 2)

    def test_an_unreachable_permission_target_yields_nothing(self):
        items = [
            fx.cluster_role("reader", [fx.rule(["get"], [""], ["pods"])]),
            fx.cluster_role_binding("crb", "reader", [fx.sa_subject("ci", "runner")]),
            fx.service_account("ci", "runner"),
        ]
        self.assertEqual(
            find_paths(analyse(items), "sa:ci:runner", parse_target("get:secrets")), []
        )

    def test_a_group_qualified_permission_target(self):
        items = [
            fx.cluster_role("deployer", [fx.rule(["patch"], ["apps"], ["deployments"])]),
            fx.cluster_role_binding("crb", "deployer", [fx.sa_subject("ci", "runner")]),
            fx.service_account("ci", "runner"),
        ]
        paths = find_paths(
            analyse(items), "sa:ci:runner", parse_target("patch:deployments.apps")
        )
        self.assertEqual(len(paths), 1)


class AuditHelperTests(unittest.TestCase):
    def test_reachable_subjects_finds_the_chain(self):
        analysis = analyse(TWO_HOP)
        reachable = reachable_subjects(analysis, analysis.resolver.all_subjects())
        self.assertIn("sa:ci:pipeline-runner", reachable)
        self.assertIn("sa:platform:operator", reachable)

    def test_reachable_subjects_omits_the_powerless(self):
        analysis = analyse(TWO_HOP)
        reachable = reachable_subjects(analysis, analysis.resolver.all_subjects())
        self.assertNotIn("sa:platform:default", reachable)

    def test_collect_all_edges_is_de_duplicated(self):
        analysis = analyse(TWO_HOP)
        edges = collect_all_edges(analysis, analysis.resolver.all_subjects())
        self.assertEqual(len(edges), len({e.key for e in edges}))

    def test_collect_all_edges_sorts_critical_first(self):
        analysis = analyse(TWO_HOP)
        edges = collect_all_edges(analysis, analysis.resolver.all_subjects())
        self.assertEqual(edges[0].severity, "critical")

    def test_collect_all_edges_walks_into_node_footholds(self):
        items = [
            fx.node("cp-1", control_plane=True),
            fx.namespace("ci"),
            fx.namespaced_role("builder", "ci", [fx.rule(["create"], [""], ["pods"])]),
            fx.role_binding("rb", "ci", "builder", "Role", [fx.sa_subject("ci", "runner")]),
            fx.service_account("ci", "runner"),
        ]
        analysis = analyse(items)
        edges = collect_all_edges(analysis, analysis.resolver.all_subjects())
        self.assertIn("RBAC-021", {e.rule_id for e in edges})

    def test_cluster_summary_counts(self):
        summary = known_cluster_summary(fx.build(TWO_HOP))
        self.assertEqual(summary["clusterRoles"], 2)
        self.assertEqual(summary["roleBindings"], 1)
        self.assertEqual(summary["clusterRoleBindings"], 1)
        self.assertEqual(summary["serviceAccounts"], 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
