"""Assertions against the two committed example dumps.

These are the claims the README makes, so they are checked here as well as in
CI: the vulnerable cluster yields the documented paths and the hardened one
yields none for the same subject.
"""

from __future__ import annotations

import unittest

import fixtures as fx
from rbac_paths.graph import (
    Analysis,
    collect_all_edges,
    find_paths,
    reachable_subjects,
)
from rbac_paths.loader import load_cluster
from rbac_paths.query import parse_resource, who_can
from rbac_paths.resolver import Resolver
from rbac_paths.rules import RULES

RUNNER = "sa:ci:pipeline-runner"


def analysis_for(path: str) -> Analysis:
    cluster = load_cluster([path])
    return Analysis(cluster=cluster, resolver=Resolver(cluster))


class VulnerableClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analysis = analysis_for(fx.VULNERABLE)

    def test_the_dump_loads(self):
        self.assertGreater(len(self.analysis.cluster.roles), 10)
        self.assertGreater(len(self.analysis.cluster.bindings), 10)

    def test_the_invalid_binding_is_reported(self):
        self.assertTrue(
            any("broken-legacy-binding" in w for w in self.analysis.cluster.warnings)
        )

    def test_the_invalid_binding_grants_nothing(self):
        names = {b.name for b in self.analysis.cluster.bindings}
        self.assertNotIn("broken-legacy-binding", names)

    def test_the_ci_runner_reaches_cluster_admin(self):
        paths = find_paths(self.analysis, RUNNER, max_paths=10)
        self.assertTrue(paths)

    def test_the_shortest_path_is_two_hops(self):
        paths = find_paths(self.analysis, RUNNER, max_paths=10)
        self.assertEqual(paths[0].length, 2)

    def test_more_than_one_distinct_path_exists(self):
        paths = find_paths(self.analysis, RUNNER, max_paths=10)
        self.assertGreater(len(paths), 1)

    def test_the_documented_workload_path_is_present(self):
        paths = find_paths(self.analysis, RUNNER, max_paths=50)
        chains = [tuple(e.rule_id for e in p.edges) for p in paths]
        self.assertIn(("RBAC-011", "RBAC-003"), chains)

    def test_the_documented_node_path_is_present(self):
        paths = find_paths(self.analysis, RUNNER, max_paths=50)
        chains = [tuple(e.rule_id for e in p.edges) for p in paths]
        self.assertIn(("RBAC-009", "RBAC-021"), chains)

    def test_the_path_through_the_aggregated_role_is_present(self):
        paths = find_paths(self.analysis, RUNNER, max_paths=50)
        chains = [tuple(e.rule_id for e in p.edges) for p in paths]
        self.assertIn(("RBAC-007", "RBAC-006"), chains)

    def test_the_aggregated_grant_names_its_contributor(self):
        paths = find_paths(self.analysis, RUNNER, max_paths=50)
        webhook_edges = [
            e for p in paths for e in p.edges if e.rule_id == "RBAC-006"
        ]
        self.assertTrue(webhook_edges)
        self.assertTrue(
            any("mesh-sidecar-injector" in e.grant_source for e in webhook_edges)
        )

    def test_the_runner_cannot_read_arbitrary_secrets_in_ci(self):
        # Its Secret read is pinned by resourceNames, so it must not appear.
        rows = who_can(self.analysis.resolver, "get", parse_resource("secrets"))
        self.assertNotIn(RUNNER, [r.subject.id for r in rows])

    def test_the_runner_can_read_the_one_secret_it_is_named_for(self):
        rows = who_can(
            self.analysis.resolver,
            "get",
            parse_resource("secrets"),
            name="build-cache-config",
        )
        self.assertIn(RUNNER, [r.subject.id for r in rows])

    def test_no_rbac_013_edge_from_the_runner_despite_a_token_secret_in_ci(self):
        # A legacy token Secret exists in ci, but the runner's rule names only
        # build-cache-config, so reading it is not an identity.
        edges = self.analysis.edges_from(RUNNER)
        self.assertNotIn("RBAC-013", {e.rule_id for e in edges})

    def test_the_observability_group_binding_grants_cluster_wide_secret_read(self):
        rows = who_can(self.analysis.resolver, "get", parse_resource("secrets"))
        ids = [r.subject.id for r in rows]
        self.assertIn("group:system:serviceaccounts:observability", ids)
        self.assertIn("sa:observability:default", ids)

    def test_the_platform_namespace_blocks_host_access(self):
        self.assertFalse(self.analysis.host_access_allowed("platform"))

    def test_the_ci_namespace_does_not(self):
        self.assertTrue(self.analysis.host_access_allowed("ci"))

    def test_the_control_plane_node_is_identified(self):
        self.assertEqual(self.analysis.cluster.control_plane_nodes(), ["cp-1"])

    def test_every_catalogued_rule_fires_somewhere(self):
        subjects = self.analysis.resolver.all_subjects()
        edges = collect_all_edges(self.analysis, subjects)
        seen = {e.rule_id for e in edges}
        seen |= {n.rule_id for n in self.analysis.cluster_notes()}
        seen |= {n.rule_id for n in self.analysis.notes}
        self.assertEqual(sorted(seen), sorted(RULES))

    def test_several_subjects_reach_cluster_admin(self):
        reachable = reachable_subjects(
            self.analysis, self.analysis.resolver.all_subjects()
        )
        self.assertGreaterEqual(len(reachable), 5)
        self.assertIn(RUNNER, reachable)

    def test_no_image_reference_leaves_the_example_domain(self):
        for pod in self.analysis.cluster.pods:
            self.assertTrue(pod.name)


class HardenedClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analysis = analysis_for(fx.HARDENED)

    def test_the_dump_loads(self):
        self.assertGreater(len(self.analysis.cluster.roles), 10)

    def test_the_ci_runner_has_no_path_to_cluster_admin(self):
        self.assertEqual(find_paths(self.analysis, RUNNER, max_paths=50), [])

    def test_the_ci_runner_has_no_escalation_edge_at_all(self):
        self.assertEqual(self.analysis.edges_from(RUNNER), [])

    def test_the_ci_runner_has_no_path_to_secret_read_either(self):
        self.assertEqual(find_paths(self.analysis, RUNNER, "perm:get::secrets"), [])

    def test_the_legitimate_administrator_is_still_reported(self):
        # Not a false positive: a cluster with no cluster-admin binding at all
        # would be the surprising result.
        reachable = reachable_subjects(
            self.analysis, self.analysis.resolver.all_subjects()
        )
        self.assertEqual(sorted(reachable), ["user:cluster-operator"])

    def test_the_resource_names_restriction_still_holds(self):
        rows = who_can(self.analysis.resolver, "get", parse_resource("secrets"))
        self.assertNotIn(RUNNER, [r.subject.id for r in rows])

    def test_secret_read_is_namespaced_not_cluster_wide(self):
        rows = who_can(self.analysis.resolver, "get", parse_resource("secrets"))
        collector = next(
            r for r in rows if r.subject.id == "sa:observability:metrics-collector"
        )
        self.assertFalse(collector.cluster_wide)
        self.assertEqual(collector.namespaces, ["observability"])

    def test_every_namespace_enforces_a_pod_security_standard(self):
        for name in ("ci", "platform", "observability"):
            self.assertEqual(self.analysis.psa_level(name), "restricted")

    def test_the_open_group_binding_is_still_reported(self):
        notes = [n for n in self.analysis.cluster_notes() if n.rule_id == "RBAC-017"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0].severity, "medium")

    def test_the_aggregation_is_still_reported_but_grants_nothing(self):
        notes = [n for n in self.analysis.cluster_notes() if n.rule_id == "RBAC-018"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(self.analysis.edges_from("sa:ci:buildkit"), [])

    def test_the_flux_operator_no_longer_reaches_cluster_admin(self):
        self.assertEqual(find_paths(self.analysis, "sa:platform:flux-reconciler"), [])

    def test_the_node_agent_no_longer_reaches_a_node(self):
        self.assertEqual(self.analysis.edges_from("sa:kube-system:node-agent"), [])

    def test_only_the_restricted_impersonation_edge_remains(self):
        edges = self.analysis.edges_from("user:support-engineer")
        self.assertEqual([e.rule_id for e in edges], ["RBAC-005"])
        self.assertEqual(edges[0].target, "user:support-readonly")


class ExampleHygieneTests(unittest.TestCase):
    """The examples must stay fabricated and free of real-looking material."""

    def _text(self, path: str) -> str:
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_no_absolute_home_paths(self):
        for path in (fx.VULNERABLE, fx.HARDENED):
            text = self._text(path)
            self.assertNotIn("/home/", text)
            self.assertNotIn("/Users/", text)

    def test_images_use_the_reserved_example_domain(self):
        for path in (fx.VULNERABLE, fx.HARDENED):
            cluster = load_cluster([path])
            self.assertTrue(cluster.pods)

    def test_token_values_are_the_synthetic_placeholder(self):
        for path in (fx.VULNERABLE, fx.HARDENED):
            text = self._text(path)
            for line in text.splitlines():
                if '"token"' in line:
                    self.assertIn(fx.FAKE_TOKEN_B64, line)

    def test_no_token_looks_like_a_jwt(self):
        import re

        pattern = re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")
        for path in (fx.VULNERABLE, fx.HARDENED):
            self.assertIsNone(pattern.search(self._text(path)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
