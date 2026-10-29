"""Output rendering."""

from __future__ import annotations

import json
import unittest

import fixtures as fx
from rbac_paths.graph import GOAL, Analysis, Edge, Note, collect_all_edges, find_paths
from rbac_paths.render import (
    audit_to_json,
    dumps,
    paths_to_json,
    render_audit_text,
    render_dot,
    render_paths_text,
    render_rule_explanation,
    render_rule_list,
    render_who_can_text,
    rules_to_json,
    who_can_to_json,
)
from rbac_paths.resolver import Resolver
from rbac_paths.rules import get_rule

ADMISSION = "admissionregistration.k8s.io"

ITEMS = [
    fx.namespace("platform"),
    fx.service_account("ci", "runner"),
    fx.service_account("platform", "operator"),
    fx.cluster_role("deployer", [fx.rule(["patch"], ["apps"], ["deployments"])]),
    fx.role_binding(
        "deployer", "platform", "deployer", "ClusterRole", [fx.sa_subject("ci", "runner")]
    ),
    fx.cluster_role(
        "injector", [fx.rule(["create"], [ADMISSION], ["mutatingwebhookconfigurations"])]
    ),
    fx.cluster_role_binding("injector", "injector", [fx.sa_subject("platform", "operator")]),
]


def analysis() -> Analysis:
    cluster = fx.build(ITEMS)
    return Analysis(cluster=cluster, resolver=Resolver(cluster))


class PathTextTests(unittest.TestCase):
    def test_lists_every_hop(self):
        a = analysis()
        text = render_paths_text("sa:ci:runner", GOAL, find_paths(a, "sa:ci:runner"), a.notes)
        self.assertIn("1. [RBAC-011", text)
        self.assertIn("2. [RBAC-006", text)

    def test_the_empty_case_explains_itself(self):
        text = render_paths_text("sa:ci:nobody", GOAL, [])
        self.assertIn("No escalation path found", text)

    def test_the_truncation_hint_appears_only_when_asked(self):
        a = analysis()
        paths = find_paths(a, "sa:ci:runner")
        self.assertIn("--max-paths", render_paths_text("sa:ci:runner", GOAL, paths, (), True))
        self.assertNotIn(
            "--max-paths", render_paths_text("sa:ci:runner", GOAL, paths, (), False)
        )

    def test_notes_are_rendered(self):
        note = Note("RBAC-019", "low", "sa:ci:runner", None, "a detail", "src", "rule")
        text = render_paths_text("sa:ci:runner", GOAL, [], [note])
        self.assertIn("a detail", text)
        self.assertIn("RBAC-019", text)

    def test_singular_and_plural_agree(self):
        one = render_paths_text("s", GOAL, find_paths(analysis(), "sa:ci:runner")[:1])
        self.assertIn("1 path found", one)


class JsonTests(unittest.TestCase):
    def test_paths_to_json_round_trips(self):
        a = analysis()
        payload = paths_to_json("sa:ci:runner", GOAL, find_paths(a, "sa:ci:runner"), a.notes)
        reloaded = json.loads(dumps(payload))
        self.assertEqual(reloaded["source"], "sa:ci:runner")
        self.assertEqual(reloaded["paths"][0]["edges"][0]["ruleId"], "RBAC-011")

    def test_paths_to_json_labels_every_node(self):
        a = analysis()
        payload = paths_to_json("sa:ci:runner", GOAL, find_paths(a, "sa:ci:runner"), [])
        for node in payload["paths"][0]["nodes"]:
            self.assertTrue(node["label"])

    def test_audit_to_json_round_trips(self):
        a = analysis()
        edges = collect_all_edges(a, a.resolver.all_subjects())
        payload = audit_to_json(a.cluster, {"pods": 0}, edges, a.cluster_notes(), {})
        reloaded = json.loads(dumps(payload))
        self.assertIn("primitives", reloaded)

    def test_audit_to_json_titles_each_primitive(self):
        a = analysis()
        edges = collect_all_edges(a, a.resolver.all_subjects())
        payload = audit_to_json(a.cluster, {}, edges, [], {})
        for primitive in payload["primitives"]:
            self.assertTrue(primitive["title"])

    def test_who_can_to_json_shape(self):
        payload = who_can_to_json("get", _spec(), [], ["a note"])
        self.assertEqual(payload["subjectCount"], 0)
        self.assertEqual(payload["notes"], ["a note"])

    def test_rules_to_json_has_every_rule(self):
        self.assertEqual(len(rules_to_json()["rules"]), 24)


def _spec():
    from rbac_paths.query import parse_resource

    return parse_resource("secrets")


class WhoCanTextTests(unittest.TestCase):
    def test_the_empty_case(self):
        text = render_who_can_text("get", _spec(), [])
        self.assertIn("Nobody", text)

    def test_notes_are_rendered(self):
        text = render_who_can_text("get", _spec(), [], ["mind this"])
        self.assertIn("mind this", text)


class DotTests(unittest.TestCase):
    def test_quotes_in_a_node_id_are_escaped(self):
        edge = Edge("RBAC-000", "high", 'sa:ci:od"d', GOAL, None, "d", "a", "s", "r")
        text = render_dot([edge])
        self.assertIn('\\"', text)

    def test_backslashes_are_escaped(self):
        edge = Edge("RBAC-000", "high", "sa:ci:a\\b", GOAL, None, "d", "a", "s", "r")
        self.assertIn("a\\\\b", render_dot([edge]))

    def test_an_empty_graph_is_still_valid(self):
        text = render_dot([])
        self.assertTrue(text.startswith("digraph rbac {"))
        self.assertTrue(text.rstrip().endswith("}"))

    def test_severity_colours_are_applied(self):
        edge = Edge("RBAC-001", "critical", "sa:ci:a", GOAL, None, "d", "a", "s", "r")
        self.assertIn("#b00020", render_dot([edge]))

    def test_each_node_appears_once(self):
        edges = [
            Edge("RBAC-001", "critical", "sa:ci:a", GOAL, None, "d", "a", "s", "r"),
            Edge("RBAC-002", "critical", "sa:ci:a", GOAL, None, "d", "a", "s", "r"),
        ]
        text = render_dot(edges)
        self.assertEqual(text.count('"sa:ci:a" ['), 1)


class AuditTextTests(unittest.TestCase):
    def test_the_clean_case_says_so(self):
        a = analysis()
        text = render_audit_text(a.cluster, {"pods": 0}, [], [], {})
        self.assertIn("No subject in this dump reaches cluster-admin", text)

    def test_ignored_kinds_are_listed(self):
        cluster = fx.build(
            [
                fx.cluster_role("r", []),
                {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c"}},
            ]
        )
        text = render_audit_text(cluster, {}, [], [], {})
        self.assertIn("ConfigMap=1", text)

    def test_the_footer_points_at_explain(self):
        a = analysis()
        text = render_audit_text(a.cluster, {}, [], [], {})
        self.assertIn("--explain", text)


class RuleTextTests(unittest.TestCase):
    def test_an_explanation_has_all_three_sections(self):
        text = render_rule_explanation(get_rule("RBAC-013"))
        self.assertIn("mechanism", text)
        self.assertIn("remediation", text)
        self.assertIn("references", text)

    def test_the_explanation_wraps(self):
        # A reference URL is never broken, so it is exempt.
        text = render_rule_explanation(get_rule("RBAC-002"))
        for line in text.splitlines():
            if "https://" in line:
                continue
            self.assertLessEqual(len(line), 80)

    def test_the_rule_list_is_ordered_by_severity(self):
        lines = [
            line for line in render_rule_list().splitlines() if line.startswith("RBAC-")
        ]
        self.assertIn("critical", lines[0])
        self.assertIn("low", lines[-1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
