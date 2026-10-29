"""Scope, aggregation and group membership."""

from __future__ import annotations

import unittest

import fixtures as fx
from rbac_paths.model import Subject
from rbac_paths.resolver import (
    OPEN_GROUPS,
    Resolver,
    implicit_groups,
    is_cluster_scoped,
    render_rule,
)

SA = Subject("ServiceAccount", "runner", "ci")
USER = Subject("User", "alice")
ANON = Subject("User", "system:anonymous")


def resolver(items):
    return Resolver(fx.build(items))


class ImplicitGroupTests(unittest.TestCase):
    def test_service_account_groups(self):
        groups = implicit_groups(SA)
        self.assertIn("system:authenticated", groups)
        self.assertIn("system:serviceaccounts", groups)
        self.assertIn("system:serviceaccounts:ci", groups)

    def test_service_account_is_not_in_another_namespaces_group(self):
        self.assertNotIn("system:serviceaccounts:platform", implicit_groups(SA))

    def test_user_is_authenticated(self):
        self.assertEqual(implicit_groups(USER), {"system:authenticated"})

    def test_anonymous_is_unauthenticated_only(self):
        self.assertEqual(implicit_groups(ANON), {"system:unauthenticated"})

    def test_a_named_group_implies_authenticated(self):
        self.assertIn("system:authenticated", implicit_groups(Subject("Group", "platform-team")))

    def test_unauthenticated_group_implies_nothing(self):
        self.assertEqual(implicit_groups(Subject("Group", "system:unauthenticated")), set())

    def test_open_groups_set(self):
        self.assertIn("system:authenticated", OPEN_GROUPS)
        self.assertIn("system:unauthenticated", OPEN_GROUPS)
        self.assertIn("system:serviceaccounts", OPEN_GROUPS)


class ScopeTests(unittest.TestCase):
    def test_cluster_role_binding_grants_every_namespace(self):
        res = resolver(
            [
                fx.cluster_role("reader", [fx.rule(["get"], [""], ["pods"])]),
                fx.cluster_role_binding("rb", "reader", [fx.sa_subject("ci", "runner")]),
                fx.service_account("ci", "runner"),
                fx.namespace("platform"),
            ]
        )
        reach = res.reach(SA, "get", "", "pods")
        self.assertTrue(reach.cluster_wide)
        self.assertIn("platform", reach.namespaces(res.cluster.known_namespaces()))

    def test_role_binding_to_a_cluster_role_is_namespace_scoped(self):
        res = resolver(
            [
                fx.cluster_role("reader", [fx.rule(["get"], [""], ["pods"])]),
                fx.role_binding("rb", "ci", "reader", "ClusterRole", [fx.sa_subject("ci", "runner")]),
                fx.service_account("ci", "runner"),
                fx.namespace("platform"),
            ]
        )
        reach = res.reach(SA, "get", "", "pods")
        self.assertFalse(reach.cluster_wide)
        self.assertEqual(sorted(reach.by_namespace), ["ci"])

    def test_role_binding_to_a_role_in_another_namespace_grants_nothing(self):
        # A RoleBinding may only reference a Role in its own namespace.
        cluster = fx.build(
            [
                fx.namespaced_role("reader", "platform", [fx.rule(["get"], [""], ["pods"])]),
                fx.role_binding("rb", "ci", "reader", "Role", [fx.sa_subject("ci", "runner")]),
                fx.service_account("ci", "runner"),
            ]
        )
        res = Resolver(cluster)
        self.assertFalse(res.reach(SA, "get", "", "pods").anywhere)

    def test_cluster_scoped_resource_through_a_role_binding_grants_nothing(self):
        res = resolver(
            [
                fx.cluster_role("noder", [fx.rule(["get"], [""], ["nodes"])]),
                fx.role_binding("rb", "ci", "noder", "ClusterRole", [fx.sa_subject("ci", "runner")]),
                fx.service_account("ci", "runner"),
            ]
        )
        self.assertFalse(res.reach(SA, "get", "", "nodes").anywhere)

    def test_cluster_scoped_resource_through_a_cluster_role_binding_works(self):
        res = resolver(
            [
                fx.cluster_role("noder", [fx.rule(["get"], [""], ["nodes"])]),
                fx.cluster_role_binding("crb", "noder", [fx.sa_subject("ci", "runner")]),
                fx.service_account("ci", "runner"),
            ]
        )
        self.assertTrue(res.reach(SA, "get", "", "nodes").cluster_wide)

    def test_is_cluster_scoped_table(self):
        self.assertTrue(is_cluster_scoped("nodes"))
        self.assertTrue(is_cluster_scoped("clusterroles"))
        self.assertTrue(is_cluster_scoped("validatingwebhookconfigurations"))
        self.assertTrue(is_cluster_scoped("users"))
        self.assertTrue(is_cluster_scoped("groups"))
        self.assertTrue(is_cluster_scoped("nodes/proxy"))
        self.assertFalse(is_cluster_scoped("pods"))
        self.assertFalse(is_cluster_scoped("serviceaccounts"))
        self.assertFalse(is_cluster_scoped("secrets"))


class GroupMembershipTests(unittest.TestCase):
    def _res(self, group):
        return resolver(
            [
                fx.cluster_role("reader", [fx.rule(["get"], [""], ["secrets"])]),
                fx.cluster_role_binding("crb", "reader", [fx.group_subject(group)]),
                fx.service_account("ci", "runner"),
            ]
        )

    def test_system_authenticated_reaches_a_service_account(self):
        self.assertTrue(self._res("system:authenticated").allows(SA, "get", "", "secrets"))

    def test_system_serviceaccounts_reaches_a_service_account(self):
        self.assertTrue(self._res("system:serviceaccounts").allows(SA, "get", "", "secrets"))

    def test_namespaced_service_account_group(self):
        self.assertTrue(self._res("system:serviceaccounts:ci").allows(SA, "get", "", "secrets"))

    def test_another_namespaces_service_account_group_does_not_reach(self):
        self.assertFalse(
            self._res("system:serviceaccounts:platform").allows(SA, "get", "", "secrets")
        )

    def test_unauthenticated_binding_does_not_reach_a_service_account(self):
        self.assertFalse(
            self._res("system:unauthenticated").allows(SA, "get", "", "secrets")
        )

    def test_unauthenticated_binding_reaches_the_anonymous_user(self):
        self.assertTrue(self._res("system:unauthenticated").allows(ANON, "get", "", "secrets"))

    def test_authenticated_binding_does_not_reach_the_anonymous_user(self):
        self.assertFalse(self._res("system:authenticated").allows(ANON, "get", "", "secrets"))

    def test_an_extra_group_can_be_declared(self):
        res = self._res("platform-team")
        self.assertFalse(res.allows(USER, "get", "", "secrets"))
        self.assertTrue(
            res.allows(USER, "get", "", "secrets", extra_groups=("platform-team",))
        )

    def test_the_grant_records_the_group_it_came_through(self):
        res = self._res("system:authenticated")
        grant = res.reach(SA, "get", "", "secrets").cluster_wide[0]
        self.assertEqual(grant.via.kind, "Group")
        self.assertEqual(grant.via.name, "system:authenticated")
        self.assertIn("via group system:authenticated", grant.source_text())

    def test_open_bindings_are_listed(self):
        res = self._res("system:authenticated")
        self.assertEqual(len(res.open_bindings()), 1)

    def test_a_direct_binding_is_not_an_open_binding(self):
        res = resolver(
            [
                fx.cluster_role("reader", [fx.rule(["get"], [""], ["secrets"])]),
                fx.cluster_role_binding("crb", "reader", [fx.sa_subject("ci", "runner")]),
            ]
        )
        self.assertEqual(res.open_bindings(), [])


AGG_LABEL = {"rbac.example.com/aggregate-to-tenant": "true"}


class AggregationTests(unittest.TestCase):
    def _res(self, selectors, contributor_labels=AGG_LABEL):
        return resolver(
            [
                fx.cluster_role("tenant", [], aggregation=selectors),
                fx.cluster_role(
                    "addon",
                    [fx.rule(["get"], [""], ["secrets"])],
                    labels=contributor_labels,
                ),
                fx.cluster_role_binding("crb", "tenant", [fx.sa_subject("ci", "runner")]),
                fx.service_account("ci", "runner"),
            ]
        )

    def test_matching_label_contributes_rules(self):
        res = self._res([{"matchLabels": AGG_LABEL}])
        self.assertTrue(res.allows(SA, "get", "", "secrets"))

    def test_non_matching_label_contributes_nothing(self):
        res = self._res([{"matchLabels": {"other": "true"}}])
        self.assertFalse(res.allows(SA, "get", "", "secrets"))

    def test_an_empty_selector_aggregates_everything(self):
        res = self._res([{}], contributor_labels=None)
        self.assertTrue(res.allows(SA, "get", "", "secrets"))

    def test_the_contributing_role_is_recorded(self):
        res = self._res([{"matchLabels": AGG_LABEL}])
        grant = res.reach(SA, "get", "", "secrets").cluster_wide[0]
        self.assertIsNotNone(grant.aggregated_from)
        self.assertEqual(grant.aggregated_from.name, "addon")
        self.assertIn("aggregated from", grant.source_text())

    def test_contributors_are_listed(self):
        res = self._res([{"matchLabels": AGG_LABEL}])
        role = res.cluster.role(
            next(r for r in res.cluster.roles if r.name == "tenant")
        )
        self.assertEqual([c.name for c in res.aggregation_contributors(role)], ["addon"])

    def test_a_role_never_aggregates_itself(self):
        res = resolver(
            [
                fx.cluster_role(
                    "tenant",
                    [fx.rule(["get"], [""], ["pods"])],
                    labels=AGG_LABEL,
                    aggregation=[{"matchLabels": AGG_LABEL}],
                ),
                fx.cluster_role_binding("crb", "tenant", [fx.sa_subject("ci", "runner")]),
            ]
        )
        # Resolving must terminate and must not duplicate the role's own rule.
        rules = res.role_rules(next(r for r in res.cluster.roles if r.name == "tenant"))
        self.assertEqual(len(rules), 1)

    def test_an_aggregation_cycle_terminates(self):
        res = resolver(
            [
                fx.cluster_role("a", [], labels={"x": "b"}, aggregation=[{"matchLabels": {"x": "a"}}]),
                fx.cluster_role("b", [fx.rule(["get"], [""], ["pods"])], labels={"x": "a"},
                                aggregation=[{"matchLabels": {"x": "b"}}]),
                fx.cluster_role_binding("crb", "a", [fx.sa_subject("ci", "runner")]),
            ]
        )
        self.assertTrue(res.allows(SA, "get", "", "pods"))

    def test_a_rule_already_written_back_is_not_duplicated(self):
        # The controller writes aggregated rules into .rules; recomputing them
        # must not list the same rule twice.
        res = resolver(
            [
                fx.cluster_role(
                    "tenant",
                    [fx.rule(["get"], [""], ["secrets"])],
                    aggregation=[{"matchLabels": AGG_LABEL}],
                ),
                fx.cluster_role("addon", [fx.rule(["get"], [""], ["secrets"])], labels=AGG_LABEL),
                fx.cluster_role_binding("crb", "tenant", [fx.sa_subject("ci", "runner")]),
            ]
        )
        rules = res.role_rules(next(r for r in res.cluster.roles if r.name == "tenant"))
        self.assertEqual(len(rules), 1)
        self.assertIsNotNone(rules[0][1])


class MiscTests(unittest.TestCase):
    def test_render_rule_spells_out_the_core_group(self):
        cluster = fx.build(
            [fx.cluster_role("r", [fx.rule(["get"], [""], ["pods"])])]
        )
        role = next(iter(cluster.roles.values()))
        self.assertIn('apiGroups=[""]', render_rule(role.rules[0]))

    def test_render_rule_includes_resource_names(self):
        cluster = fx.build(
            [fx.cluster_role("r", [fx.rule(["get"], [""], ["secrets"], resource_names=["a"])])]
        )
        role = next(iter(cluster.roles.values()))
        self.assertIn("resourceNames=['a']", render_rule(role.rules[0]))

    def test_all_subjects_includes_unbound_service_accounts(self):
        res = resolver(
            [fx.cluster_role("r", []), fx.service_account("ci", "lonely")]
        )
        self.assertIn("sa:ci:lonely", [s.id for s in res.all_subjects()])

    def test_subject_ids(self):
        self.assertEqual(SA.id, "sa:ci:runner")
        self.assertEqual(USER.id, "user:alice")
        self.assertEqual(Subject("Group", "g").id, "group:g")

    def test_non_resource_reach_is_cluster_only(self):
        res = resolver(
            [
                fx.cluster_role("m", [fx.rule(["get"], non_resource_urls=["/metrics"])]),
                fx.role_binding("rb", "ci", "m", "ClusterRole", [fx.sa_subject("ci", "runner")]),
            ]
        )
        self.assertEqual(res.reach_non_resource(SA, "get", "/metrics"), [])

    def test_non_resource_reach_through_a_cluster_role_binding(self):
        res = resolver(
            [
                fx.cluster_role("m", [fx.rule(["get"], non_resource_urls=["/metrics"])]),
                fx.cluster_role_binding("crb", "m", [fx.sa_subject("ci", "runner")]),
            ]
        )
        self.assertEqual(len(res.reach_non_resource(SA, "get", "/metrics")), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
