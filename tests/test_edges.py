"""One test group per escalation edge rule, with a negative case for each."""

from __future__ import annotations

import unittest

import fixtures as fx
from rbac_paths.graph import GOAL, Analysis
from rbac_paths.resolver import Resolver
from rbac_paths.rules import RULES, all_rules

RBAC = "rbac.authorization.k8s.io"
CERTS = "certificates.k8s.io"
ADMISSION = "admissionregistration.k8s.io"


def analyse(items, psa: str = "privileged", groups: tuple[str, ...] = ()) -> Analysis:
    cluster = fx.build(items)
    return Analysis(
        cluster=cluster,
        resolver=Resolver(cluster),
        assume_psa=psa,
        extra_groups=groups,
    )


def ids(analysis: Analysis, node: str) -> set[str]:
    return {edge.rule_id for edge in analysis.edges_from(node)}


def targets(analysis: Analysis, node: str, rule_id: str) -> list[str]:
    return sorted(
        edge.target for edge in analysis.edges_from(node) if edge.rule_id == rule_id
    )


def note_ids(analysis: Analysis) -> set[str]:
    return {note.rule_id for note in analysis.notes}


def bind_cluster_role(name, rules, subject_ns="ci", subject="runner", **kwargs):
    """A ClusterRole bound cluster-wide to one ServiceAccount."""
    return [
        fx.cluster_role(name, rules, **kwargs),
        fx.cluster_role_binding(f"{name}-crb", name, [fx.sa_subject(subject_ns, subject)]),
        fx.service_account(subject_ns, subject),
    ]


def bind_role(name, ns, rules, subject_ns="ci", subject="runner"):
    """A Role bound inside its namespace to one ServiceAccount."""
    return [
        fx.namespaced_role(name, ns, rules),
        fx.role_binding(f"{name}-rb", ns, name, "Role", [fx.sa_subject(subject_ns, subject)]),
        fx.service_account(subject_ns, subject),
    ]


RUNNER = "sa:ci:runner"


class CatalogueTests(unittest.TestCase):
    def test_every_rule_has_a_mechanism_and_a_remediation(self):
        for rule in all_rules():
            self.assertTrue(rule.mechanism.strip(), rule.id)
            self.assertTrue(rule.remediation.strip(), rule.id)

    def test_every_rule_has_a_known_severity(self):
        for rule in all_rules():
            self.assertIn(rule.severity, ("critical", "high", "medium", "low"), rule.id)

    def test_rule_ids_are_unique_and_contiguous(self):
        ids_seen = sorted(RULES)
        self.assertEqual(len(ids_seen), len(set(ids_seen)))
        self.assertEqual(ids_seen[0], "RBAC-001")

    def test_every_rule_carries_a_reference(self):
        for rule in all_rules():
            self.assertTrue(rule.references, rule.id)


class Rbac001FullWildcardTests(unittest.TestCase):
    def test_cluster_wide_wildcard_reaches_cluster_admin(self):
        analysis = analyse(bind_cluster_role("admin", [fx.rule(["*"], ["*"], ["*"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-001"), [GOAL])

    def test_namespaced_wildcard_reaches_namespace_admin_not_cluster_admin(self):
        analysis = analyse(bind_role("admin", "ci", [fx.rule(["*"], ["*"], ["*"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-001"), ["nsadmin:ci"])

    def test_a_group_restricted_wildcard_is_not_rbac_001(self):
        analysis = analyse(bind_cluster_role("partial", [fx.rule(["*"], ["apps"], ["*"])]))
        self.assertNotIn("RBAC-001", ids(analysis, RUNNER))

    def test_resource_names_defeat_the_wildcard(self):
        analysis = analyse(
            bind_cluster_role("named", [fx.rule(["*"], ["*"], ["*"], resource_names=["x"])])
        )
        self.assertNotIn("RBAC-001", ids(analysis, RUNNER))

    def test_an_already_admin_subject_reports_only_that_edge(self):
        analysis = analyse(bind_cluster_role("admin", [fx.rule(["*"], ["*"], ["*"])]))
        self.assertEqual(ids(analysis, RUNNER), {"RBAC-001"})


class Rbac002EscalateTests(unittest.TestCase):
    def _items(self, extra_verbs):
        return bind_cluster_role(
            "composer",
            [
                fx.rule(["escalate"], [RBAC], ["clusterroles"]),
                fx.rule(extra_verbs, [RBAC], ["clusterroles"]),
            ],
        )

    def test_escalate_plus_role_write_reaches_cluster_admin(self):
        analysis = analyse(self._items(["update"]))
        self.assertIn(GOAL, targets(analysis, RUNNER, "RBAC-002"))

    def test_patch_also_counts_as_role_write(self):
        analysis = analyse(self._items(["patch"]))
        self.assertIn(GOAL, targets(analysis, RUNNER, "RBAC-002"))

    def test_escalate_alone_is_inert_and_reported_as_a_note(self):
        analysis = analyse(
            bind_cluster_role("composer", [fx.rule(["escalate"], [RBAC], ["clusterroles"])])
        )
        self.assertNotIn("RBAC-002", ids(analysis, RUNNER))
        self.assertIn("RBAC-002", note_ids(analysis))
        self.assertTrue(any("inert" in n.detail for n in analysis.notes))

    def test_escalate_on_namespaced_roles_reaches_namespace_admin(self):
        analysis = analyse(
            bind_role(
                "composer",
                "ci",
                [
                    fx.rule(["escalate"], [RBAC], ["roles"]),
                    fx.rule(["update"], [RBAC], ["roles"]),
                ],
            )
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-002"), ["nsadmin:ci"])

    def test_a_resource_names_restricted_escalate_is_still_seen(self):
        analysis = analyse(
            bind_cluster_role(
                "composer",
                [
                    fx.rule(["escalate"], [RBAC], ["clusterroles"], resource_names=["composer"]),
                    fx.rule(["update"], [RBAC], ["clusterroles"], resource_names=["composer"]),
                ],
            )
        )
        self.assertIn(GOAL, targets(analysis, RUNNER, "RBAC-002"))


class Rbac003BindTests(unittest.TestCase):
    def _items(self, bind_rule, extra=()):
        return [
            fx.cluster_role("cluster-admin", [fx.rule(["*"], ["*"], ["*"])]),
            *bind_cluster_role("binder", [bind_rule, *extra]),
        ]

    def test_bind_plus_binding_creation_reaches_cluster_admin(self):
        analysis = analyse(
            self._items(
                fx.rule(["bind"], [RBAC], ["clusterroles"]),
                [fx.rule(["create"], [RBAC], ["clusterrolebindings"])],
            )
        )
        self.assertIn(GOAL, targets(analysis, RUNNER, "RBAC-003"))

    def test_bind_without_binding_creation_is_a_note(self):
        analysis = analyse(self._items(fx.rule(["bind"], [RBAC], ["clusterroles"])))
        self.assertNotIn("RBAC-003", ids(analysis, RUNNER))
        self.assertIn("RBAC-003", note_ids(analysis))

    def test_bind_restricted_to_a_harmless_role_is_only_a_note(self):
        analysis = analyse(
            [
                fx.cluster_role("cluster-admin", [fx.rule(["*"], ["*"], ["*"])]),
                fx.cluster_role("viewer", [fx.rule(["get"], [""], ["pods"])]),
                *bind_cluster_role(
                    "binder",
                    [
                        fx.rule(["bind"], [RBAC], ["clusterroles"], resource_names=["viewer"]),
                        fx.rule(["create"], [RBAC], ["clusterrolebindings"]),
                    ],
                ),
            ]
        )
        self.assertNotIn("RBAC-003", ids(analysis, RUNNER))
        self.assertIn("RBAC-003", note_ids(analysis))

    def test_bind_restricted_to_an_admin_role_still_reaches_cluster_admin(self):
        analysis = analyse(
            [
                fx.cluster_role("cluster-admin", [fx.rule(["*"], ["*"], ["*"])]),
                *bind_cluster_role(
                    "binder",
                    [
                        fx.rule(
                            ["bind"], [RBAC], ["clusterroles"], resource_names=["cluster-admin"]
                        ),
                        fx.rule(["create"], [RBAC], ["clusterrolebindings"]),
                    ],
                ),
            ]
        )
        self.assertIn(GOAL, targets(analysis, RUNNER, "RBAC-003"))

    def test_namespaced_bind_reaches_namespace_admin(self):
        analysis = analyse(
            [
                fx.cluster_role("cluster-admin", [fx.rule(["*"], ["*"], ["*"])]),
                *bind_role(
                    "binder",
                    "ci",
                    [
                        fx.rule(["bind"], [RBAC], ["clusterroles"]),
                        fx.rule(["create"], [RBAC], ["rolebindings"]),
                    ],
                ),
            ]
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-003"), ["nsadmin:ci"])


class Rbac004And005ImpersonateTests(unittest.TestCase):
    def test_unrestricted_group_impersonation_reaches_cluster_admin(self):
        analysis = analyse(bind_cluster_role("imp", [fx.rule(["impersonate"], [""], ["groups"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-004"), [GOAL])

    def test_group_impersonation_naming_system_masters_reaches_cluster_admin(self):
        analysis = analyse(
            bind_cluster_role(
                "imp",
                [fx.rule(["impersonate"], [""], ["groups"], resource_names=["system:masters"])],
            )
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-004"), [GOAL])

    def test_group_impersonation_of_a_named_group_is_rbac_005(self):
        analysis = analyse(
            bind_cluster_role(
                "imp",
                [fx.rule(["impersonate"], [""], ["groups"], resource_names=["platform-team"])],
            )
        )
        self.assertNotIn("RBAC-004", ids(analysis, RUNNER))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-005"), ["group:platform-team"])

    def test_named_user_impersonation(self):
        analysis = analyse(
            bind_cluster_role(
                "imp", [fx.rule(["impersonate"], [""], ["users"], resource_names=["alice"])]
            )
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-005"), ["user:alice"])

    def test_service_account_impersonation(self):
        analysis = analyse(
            [
                fx.service_account("platform", "operator"),
                *bind_cluster_role("imp", [fx.rule(["impersonate"], [""], ["serviceaccounts"])]),
            ]
        )
        self.assertIn("sa:platform:operator", targets(analysis, RUNNER, "RBAC-005"))

    def test_impersonate_through_a_role_binding_grants_nothing_for_users(self):
        # `users` is cluster-scoped, so a RoleBinding cannot grant it.
        analysis = analyse(
            bind_role("imp", "ci", [fx.rule(["impersonate"], [""], ["users"])])
        )
        self.assertNotIn("RBAC-005", ids(analysis, RUNNER))

    def test_no_impersonate_no_edge(self):
        analysis = analyse(bind_cluster_role("r", [fx.rule(["get"], [""], ["pods"])]))
        self.assertNotIn("RBAC-004", ids(analysis, RUNNER))
        self.assertNotIn("RBAC-005", ids(analysis, RUNNER))


class Rbac006WebhookTests(unittest.TestCase):
    def test_create_mutating_webhook_reaches_cluster_admin(self):
        analysis = analyse(
            bind_cluster_role(
                "wh", [fx.rule(["create"], [ADMISSION], ["mutatingwebhookconfigurations"])]
            )
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-006"), [GOAL])

    def test_patch_validating_webhook_reaches_cluster_admin(self):
        analysis = analyse(
            bind_cluster_role(
                "wh", [fx.rule(["patch"], [ADMISSION], ["validatingwebhookconfigurations"])]
            )
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-006"), [GOAL])

    def test_read_only_webhook_access_is_not_an_edge(self):
        analysis = analyse(
            bind_cluster_role(
                "wh", [fx.rule(["get", "list"], [ADMISSION], ["mutatingwebhookconfigurations"])]
            )
        )
        self.assertNotIn("RBAC-006", ids(analysis, RUNNER))

    def test_create_with_resource_names_grants_nothing(self):
        analysis = analyse(
            bind_cluster_role(
                "wh",
                [
                    fx.rule(
                        ["create"],
                        [ADMISSION],
                        ["mutatingwebhookconfigurations"],
                        resource_names=["mine"],
                    )
                ],
            )
        )
        self.assertNotIn("RBAC-006", ids(analysis, RUNNER))


POD_NS = [fx.namespace("ci"), fx.service_account("ci", "privileged-app")]


class Rbac007PodCreateTests(unittest.TestCase):
    def test_pod_create_reaches_every_service_account_in_the_namespace(self):
        analysis = analyse(
            [*POD_NS, *bind_role("builder", "ci", [fx.rule(["create"], [""], ["pods"])])]
        )
        self.assertIn("sa:ci:privileged-app", targets(analysis, RUNNER, "RBAC-007"))

    def test_pod_create_does_not_reach_another_namespace(self):
        analysis = analyse(
            [
                *POD_NS,
                fx.service_account("platform", "operator"),
                *bind_role("builder", "ci", [fx.rule(["create"], [""], ["pods"])]),
            ]
        )
        self.assertNotIn("sa:platform:operator", targets(analysis, RUNNER, "RBAC-007"))

    def test_read_only_pod_access_is_not_an_edge(self):
        analysis = analyse(
            [*POD_NS, *bind_role("builder", "ci", [fx.rule(["get", "list"], [""], ["pods"])])]
        )
        self.assertNotIn("RBAC-007", ids(analysis, RUNNER))

    def test_create_with_resource_names_grants_nothing(self):
        analysis = analyse(
            [
                *POD_NS,
                *bind_role(
                    "builder", "ci", [fx.rule(["create"], [""], ["pods"], resource_names=["x"])]
                ),
            ]
        )
        self.assertNotIn("RBAC-007", ids(analysis, RUNNER))

    def test_a_wildcard_resource_rule_also_creates_pods(self):
        analysis = analyse(
            [*POD_NS, *bind_role("builder", "ci", [fx.rule(["create"], [""], ["*"])])]
        )
        self.assertIn("sa:ci:privileged-app", targets(analysis, RUNNER, "RBAC-007"))


NODES = [fx.node("cp-1", control_plane=True), fx.node("worker-1")]


class Rbac008And009HostAccessTests(unittest.TestCase):
    def _items(self, psa=None):
        return [
            fx.namespace("ci", psa=psa),
            *NODES,
            *bind_role("builder", "ci", [fx.rule(["create"], [""], ["pods"])]),
        ]

    def test_pod_create_with_no_policy_reaches_every_node(self):
        analysis = analyse(self._items())
        self.assertEqual(targets(analysis, RUNNER, "RBAC-008"), ["node:cp-1", "node:worker-1"])

    def test_control_plane_pinning_is_reported_separately(self):
        analysis = analyse(self._items())
        self.assertEqual(targets(analysis, RUNNER, "RBAC-009"), ["node:cp-1"])

    def test_restricted_psa_blocks_host_access(self):
        analysis = analyse(self._items(psa="restricted"))
        self.assertNotIn("RBAC-008", ids(analysis, RUNNER))
        self.assertIn("RBAC-008", note_ids(analysis))

    def test_baseline_psa_also_blocks_host_access(self):
        analysis = analyse(self._items(psa="baseline"))
        self.assertNotIn("RBAC-008", ids(analysis, RUNNER))

    def test_restricted_psa_does_not_remove_node_choice_but_downgrades_it(self):
        analysis = analyse(self._items(psa="restricted"))
        self.assertNotIn("RBAC-009", ids(analysis, RUNNER))
        note = next(n for n in analysis.notes if n.rule_id == "RBAC-009")
        self.assertIn("does not restrict nodeName", note.detail)

    def test_assume_psa_applies_when_the_namespace_label_is_absent(self):
        analysis = analyse(
            [
                *NODES,
                *bind_role("builder", "ci", [fx.rule(["create"], [""], ["pods"])]),
            ],
            psa="restricted",
        )
        self.assertNotIn("RBAC-008", ids(analysis, RUNNER))

    def test_the_namespace_label_wins_over_the_assumption(self):
        analysis = analyse(self._items(psa="privileged"), psa="restricted")
        self.assertIn("RBAC-008", ids(analysis, RUNNER))

    def test_a_dump_without_nodes_says_so(self):
        analysis = analyse(bind_role("builder", "ci", [fx.rule(["create"], [""], ["pods"])]))
        self.assertNotIn("RBAC-008", ids(analysis, RUNNER))
        note = next(n for n in analysis.notes if n.rule_id == "RBAC-008")
        self.assertIn("no Node objects", note.detail)


class Rbac010PodRunTests(unittest.TestCase):
    def _items(self, rules):
        return [
            fx.pod("app-1", "ci", sa="privileged-app"),
            fx.service_account("ci", "privileged-app"),
            *bind_role("debug", "ci", rules),
        ]

    def test_create_pods_exec(self):
        analysis = analyse(self._items([fx.rule(["create"], [""], ["pods/exec"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-010"), ["sa:ci:privileged-app"])

    def test_get_pods_exec_also_reaches_it(self):
        # exec is reachable over GET as well as POST, which maps to the `get` verb.
        analysis = analyse(self._items([fx.rule(["get"], [""], ["pods/exec"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-010"), ["sa:ci:privileged-app"])

    def test_pods_attach(self):
        analysis = analyse(self._items([fx.rule(["create"], [""], ["pods/attach"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-010"), ["sa:ci:privileged-app"])

    def test_pods_portforward(self):
        analysis = analyse(self._items([fx.rule(["create"], [""], ["pods/portforward"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-010"), ["sa:ci:privileged-app"])

    def test_ephemeral_containers_need_a_write_verb(self):
        analysis = analyse(
            self._items([fx.rule(["patch"], [""], ["pods/ephemeralcontainers"])])
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-010"), ["sa:ci:privileged-app"])

    def test_create_on_ephemeral_containers_is_not_the_verb_that_works(self):
        analysis = analyse(
            self._items([fx.rule(["create"], [""], ["pods/ephemeralcontainers"])])
        )
        self.assertNotIn("RBAC-010", ids(analysis, RUNNER))

    def test_plain_pods_access_does_not_grant_exec(self):
        analysis = analyse(self._items([fx.rule(["create", "get"], [""], ["pods"])]))
        self.assertNotIn("RBAC-010", ids(analysis, RUNNER))

    def test_wildcard_resources_do_grant_exec(self):
        analysis = analyse(self._items([fx.rule(["create"], [""], ["*"])]))
        self.assertIn("sa:ci:privileged-app", targets(analysis, RUNNER, "RBAC-010"))

    def test_resource_names_restrict_exec_to_the_named_pods(self):
        items = [
            fx.pod("app-1", "ci", sa="privileged-app"),
            fx.pod("app-2", "ci", sa="other-app"),
            fx.service_account("ci", "privileged-app"),
            fx.service_account("ci", "other-app"),
            *bind_role(
                "debug", "ci", [fx.rule(["get"], [""], ["pods/exec"], resource_names=["app-1"])]
            ),
        ]
        analysis = analyse(items)
        self.assertEqual(targets(analysis, RUNNER, "RBAC-010"), ["sa:ci:privileged-app"])

    def test_exec_with_no_pods_in_the_dump_is_a_note(self):
        analysis = analyse(bind_role("debug", "ci", [fx.rule(["create"], [""], ["pods/exec"])]))
        self.assertNotIn("RBAC-010", ids(analysis, RUNNER))
        self.assertIn("RBAC-010", note_ids(analysis))


class Rbac011WorkloadWriteTests(unittest.TestCase):
    def _items(self, rules):
        return [
            fx.namespace("platform"),
            fx.service_account("platform", "operator"),
            fx.role_binding(
                "deployer", "platform", "deployer", "ClusterRole", [fx.sa_subject("ci", "runner")]
            ),
            fx.cluster_role("deployer", rules),
            fx.service_account("ci", "runner"),
        ]

    def test_patch_deployments_reaches_the_namespaces_service_accounts(self):
        analysis = analyse(self._items([fx.rule(["patch"], ["apps"], ["deployments"])]))
        self.assertIn("sa:platform:operator", targets(analysis, RUNNER, "RBAC-011"))

    def test_statefulsets_daemonsets_and_cronjobs_all_count(self):
        for group, resource in (
            ("apps", "statefulsets"),
            ("apps", "daemonsets"),
            ("apps", "replicasets"),
            ("batch", "jobs"),
            ("batch", "cronjobs"),
        ):
            analysis = analyse(self._items([fx.rule(["update"], [group], [resource])]))
            self.assertIn(
                "sa:platform:operator",
                targets(analysis, RUNNER, "RBAC-011"),
                f"{group}/{resource}",
            )

    def test_replicationcontrollers_are_in_the_core_group(self):
        analysis = analyse(self._items([fx.rule(["patch"], [""], ["replicationcontrollers"])]))
        self.assertIn("sa:platform:operator", targets(analysis, RUNNER, "RBAC-011"))

    def test_read_only_workload_access_is_not_an_edge(self):
        analysis = analyse(self._items([fx.rule(["get", "list", "watch"], ["apps"], ["deployments"])]))
        self.assertNotIn("RBAC-011", ids(analysis, RUNNER))

    def test_the_wrong_api_group_is_not_an_edge(self):
        analysis = analyse(self._items([fx.rule(["patch"], [""], ["deployments"])]))
        self.assertNotIn("RBAC-011", ids(analysis, RUNNER))


class Rbac012TokenRequestTests(unittest.TestCase):
    def _items(self, rules):
        return [
            fx.service_account("ci", "privileged-app"),
            *bind_role("minter", "ci", rules),
        ]

    def test_token_request_mints_a_credential(self):
        analysis = analyse(self._items([fx.rule(["create"], [""], ["serviceaccounts/token"])]))
        self.assertIn("sa:ci:privileged-app", targets(analysis, RUNNER, "RBAC-012"))

    def test_resource_names_do_restrict_token_request(self):
        # TokenRequest is a subresource of a named object, so the authorizer
        # does see the name here, unlike a plain create.
        analysis = analyse(
            self._items(
                [
                    fx.rule(
                        ["create"],
                        [""],
                        ["serviceaccounts/token"],
                        resource_names=["privileged-app"],
                    )
                ]
            )
        )
        self.assertIn("sa:ci:privileged-app", targets(analysis, RUNNER, "RBAC-012"))

    def test_resource_names_exclude_other_accounts(self):
        items = [
            fx.service_account("ci", "privileged-app"),
            fx.service_account("ci", "innocent"),
            *bind_role(
                "minter",
                "ci",
                [
                    fx.rule(
                        ["create"],
                        [""],
                        ["serviceaccounts/token"],
                        resource_names=["privileged-app"],
                    )
                ],
            ),
        ]
        analysis = analyse(items)
        self.assertEqual(targets(analysis, RUNNER, "RBAC-012"), ["sa:ci:privileged-app"])

    def test_plain_serviceaccounts_access_does_not_mint_tokens(self):
        analysis = analyse(self._items([fx.rule(["create", "get"], [""], ["serviceaccounts"])]))
        self.assertNotIn("RBAC-012", ids(analysis, RUNNER))


class Rbac013And014SecretReadTests(unittest.TestCase):
    def test_cluster_wide_secret_read_reaches_cluster_admin(self):
        analysis = analyse(bind_cluster_role("sync", [fx.rule(["get"], [""], ["secrets"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-014"), [GOAL])

    def test_namespaced_secret_read_is_not_rbac_014(self):
        analysis = analyse(bind_role("reader", "ci", [fx.rule(["get"], [""], ["secrets"])]))
        self.assertNotIn("RBAC-014", ids(analysis, RUNNER))

    def test_a_legacy_token_secret_makes_secret_read_an_identity(self):
        analysis = analyse(
            [
                fx.token_secret("app-token-abc", "ci", "privileged-app"),
                fx.service_account("ci", "privileged-app"),
                *bind_role("reader", "ci", [fx.rule(["get"], [""], ["secrets"])]),
            ]
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-013"), ["sa:ci:privileged-app"])

    def test_without_a_legacy_token_secret_there_is_no_identity_edge(self):
        # This is the 1.24 behaviour: no auto-created token Secrets, so reading
        # Secrets is credential disclosure but not an identity.
        analysis = analyse(
            [
                fx.opaque_secret("app-config", "ci"),
                fx.service_account("ci", "privileged-app"),
                *bind_role("reader", "ci", [fx.rule(["get"], [""], ["secrets"])]),
            ]
        )
        self.assertNotIn("RBAC-013", ids(analysis, RUNNER))
        note = next(n for n in analysis.notes if n.rule_id == "RBAC-013")
        self.assertIn("1.24", note.detail)

    def test_resource_names_restrict_the_secret_read(self):
        analysis = analyse(
            [
                fx.token_secret("app-token-abc", "ci", "privileged-app"),
                fx.service_account("ci", "privileged-app"),
                *bind_role(
                    "reader",
                    "ci",
                    [fx.rule(["get"], [""], ["secrets"], resource_names=["other-secret"])],
                ),
            ]
        )
        self.assertNotIn("RBAC-013", ids(analysis, RUNNER))

    def test_resource_names_naming_the_token_secret_do_reach_it(self):
        analysis = analyse(
            [
                fx.token_secret("app-token-abc", "ci", "privileged-app"),
                fx.service_account("ci", "privileged-app"),
                *bind_role(
                    "reader",
                    "ci",
                    [fx.rule(["get"], [""], ["secrets"], resource_names=["app-token-abc"])],
                ),
            ]
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-013"), ["sa:ci:privileged-app"])

    def test_list_secrets_cannot_be_restricted_by_resource_names(self):
        analysis = analyse(
            [
                fx.token_secret("app-token-abc", "ci", "privileged-app"),
                fx.service_account("ci", "privileged-app"),
                *bind_role(
                    "reader",
                    "ci",
                    [fx.rule(["list"], [""], ["secrets"], resource_names=["app-token-abc"])],
                ),
            ]
        )
        self.assertNotIn("RBAC-013", ids(analysis, RUNNER))


class Rbac015NodeStatusTests(unittest.TestCase):
    def test_node_status_write_with_an_attractable_workload(self):
        analysis = analyse(
            [
                fx.pod("report-0", "legacy", sa="exporter", node_selector={"disktype": "ssd"}),
                *bind_cluster_role("noder", [fx.rule(["update"], [""], ["nodes/status"])]),
            ]
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-015"), ["sa:legacy:exporter"])

    def test_without_a_node_selector_it_is_only_a_note(self):
        analysis = analyse(
            [
                fx.pod("report-0", "legacy", sa="exporter"),
                *bind_cluster_role("noder", [fx.rule(["update"], [""], ["nodes/status"])]),
            ]
        )
        self.assertNotIn("RBAC-015", ids(analysis, RUNNER))
        self.assertIn("RBAC-015", note_ids(analysis))

    def test_plain_nodes_access_is_not_status_write(self):
        analysis = analyse(
            [
                fx.pod("report-0", "legacy", sa="exporter", node_selector={"disktype": "ssd"}),
                *bind_cluster_role("noder", [fx.rule(["update"], [""], ["nodes"])]),
            ]
        )
        self.assertNotIn("RBAC-015", ids(analysis, RUNNER))


SIGNER = "kubernetes.io/kube-apiserver-client"


class Rbac016CsrApprovalTests(unittest.TestCase):
    def _rules(self, approval=True, signer=True, submit=True):
        rules = []
        if approval:
            rules.append(fx.rule(["update"], [CERTS], ["certificatesigningrequests/approval"]))
        if signer:
            rules.append(fx.rule(["approve"], [CERTS], ["signers"], resource_names=[SIGNER]))
        if submit:
            rules.append(fx.rule(["create"], [CERTS], ["certificatesigningrequests"]))
        return rules

    def test_all_three_permissions_reach_cluster_admin(self):
        analysis = analyse(bind_cluster_role("csr", self._rules()))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-016"), [GOAL])

    def test_approval_without_the_signer_permission_is_a_note(self):
        analysis = analyse(bind_cluster_role("csr", self._rules(signer=False)))
        self.assertNotIn("RBAC-016", ids(analysis, RUNNER))
        note = next(n for n in analysis.notes if n.rule_id == "RBAC-016")
        self.assertIn("approve", note.detail)

    def test_approval_without_submission_is_a_note(self):
        analysis = analyse(bind_cluster_role("csr", self._rules(submit=False)))
        self.assertNotIn("RBAC-016", ids(analysis, RUNNER))
        self.assertIn("RBAC-016", note_ids(analysis))

    def test_a_wildcard_signer_name_also_works(self):
        rules = [
            fx.rule(["update"], [CERTS], ["certificatesigningrequests/approval"]),
            fx.rule(["approve"], [CERTS], ["signers"]),
            fx.rule(["create"], [CERTS], ["certificatesigningrequests"]),
        ]
        analysis = analyse(bind_cluster_role("csr", rules))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-016"), [GOAL])

    def test_a_different_signer_does_not_count(self):
        rules = [
            fx.rule(["update"], [CERTS], ["certificatesigningrequests/approval"]),
            fx.rule(["approve"], [CERTS], ["signers"], resource_names=["example.com/other"]),
            fx.rule(["create"], [CERTS], ["certificatesigningrequests"]),
        ]
        analysis = analyse(bind_cluster_role("csr", rules))
        self.assertNotIn("RBAC-016", ids(analysis, RUNNER))

    def test_submission_alone_is_nothing(self):
        analysis = analyse(bind_cluster_role("csr", self._rules(approval=False, signer=False)))
        self.assertNotIn("RBAC-016", ids(analysis, RUNNER))


class Rbac017OpenBindingTests(unittest.TestCase):
    def _notes(self, group, rules):
        analysis = analyse(
            [
                fx.cluster_role("open", rules),
                fx.cluster_role_binding("open-crb", "open", [fx.group_subject(group)]),
            ]
        )
        return [n for n in analysis.cluster_notes() if n.rule_id == "RBAC-017"]

    def test_system_authenticated_is_flagged(self):
        notes = self._notes("system:authenticated", [fx.rule(["get"], [""], ["pods"])])
        self.assertEqual(len(notes), 1)
        self.assertIn("every identity with a valid credential", notes[0].detail)

    def test_system_unauthenticated_is_flagged(self):
        notes = self._notes("system:unauthenticated", [fx.rule(["get"], [""], ["pods"])])
        self.assertIn("reach the API server port", notes[0].detail)

    def test_all_service_accounts_is_flagged(self):
        notes = self._notes("system:serviceaccounts", [fx.rule(["get"], [""], ["pods"])])
        self.assertIn("every pod in the cluster", notes[0].detail)

    def test_a_namespaced_service_account_group_is_flagged(self):
        notes = self._notes("system:serviceaccounts:ci", [fx.rule(["get"], [""], ["pods"])])
        self.assertIn("every pod in namespace ci", notes[0].detail)

    def test_severity_follows_what_the_role_grants(self):
        read_only = self._notes("system:authenticated", [fx.rule(["get"], [""], ["pods"])])
        wildcard = self._notes("system:authenticated", [fx.rule(["*"], ["*"], ["*"])])
        self.assertEqual(read_only[0].severity, "medium")
        self.assertEqual(wildcard[0].severity, "critical")

    def test_secret_access_raises_the_severity(self):
        notes = self._notes("system:authenticated", [fx.rule(["get"], [""], ["secrets"])])
        self.assertEqual(notes[0].severity, "high")

    def test_a_named_group_is_not_an_open_binding(self):
        self.assertEqual(self._notes("platform-team", [fx.rule(["get"], [""], ["pods"])]), [])


class Rbac018AggregationTests(unittest.TestCase):
    def test_a_matching_contributor_is_reported(self):
        analysis = analyse(
            [
                fx.cluster_role("tenant", [], aggregation=[{"matchLabels": {"agg": "yes"}}]),
                fx.cluster_role("addon", [fx.rule(["get"], [""], ["pods"])], labels={"agg": "yes"}),
            ]
        )
        notes = [n for n in analysis.cluster_notes() if n.rule_id == "RBAC-018"]
        self.assertEqual(len(notes), 1)
        self.assertIn("addon", notes[0].detail)

    def test_an_empty_selector_is_critical(self):
        analysis = analyse(
            [
                fx.cluster_role("tenant", [], aggregation=[{}]),
                fx.cluster_role("addon", [fx.rule(["get"], [""], ["pods"])]),
            ]
        )
        notes = [n for n in analysis.cluster_notes() if n.rule_id == "RBAC-018"]
        self.assertEqual(notes[0].severity, "critical")
        self.assertIn("empty selector", notes[0].detail)

    def test_an_aggregation_rule_with_no_contributors_is_silent(self):
        analysis = analyse(
            [fx.cluster_role("tenant", [], aggregation=[{"matchLabels": {"agg": "yes"}}])]
        )
        self.assertEqual([n for n in analysis.cluster_notes() if n.rule_id == "RBAC-018"], [])

    def test_a_role_without_an_aggregation_rule_is_silent(self):
        analysis = analyse([fx.cluster_role("plain", [fx.rule(["get"], [""], ["pods"])])])
        self.assertEqual([n for n in analysis.cluster_notes() if n.rule_id == "RBAC-018"], [])


class Rbac019NonResourceTests(unittest.TestCase):
    def test_wildcard_non_resource_urls_are_noted(self):
        analysis = analyse(bind_cluster_role("dbg", [fx.rule(["get"], non_resource_urls=["*"])]))
        analysis.edges_from(RUNNER)
        self.assertIn("RBAC-019", note_ids(analysis))

    def test_a_specific_path_is_not_noted(self):
        analysis = analyse(
            bind_cluster_role("dbg", [fx.rule(["get"], non_resource_urls=["/metrics"])])
        )
        analysis.edges_from(RUNNER)
        self.assertNotIn("RBAC-019", note_ids(analysis))

    def test_a_non_resource_rule_grants_no_resource_edges(self):
        analysis = analyse(bind_cluster_role("dbg", [fx.rule(["*"], non_resource_urls=["*"])]))
        self.assertNotIn("RBAC-001", ids(analysis, RUNNER))


class Rbac020And021NodeTests(unittest.TestCase):
    def test_node_control_reaches_the_tokens_of_pods_on_it(self):
        analysis = analyse(
            [
                fx.cluster_role("r", []),
                fx.node("worker-1"),
                fx.pod("app-1", "ci", sa="privileged-app", node_name="worker-1"),
                fx.pod("elsewhere", "ci", sa="other", node_name="worker-2"),
            ]
        )
        self.assertEqual(
            targets(analysis, "node:worker-1", "RBAC-020"), ["sa:ci:privileged-app"]
        )

    def test_a_control_plane_node_reaches_cluster_admin(self):
        analysis = analyse([fx.cluster_role("r", []), fx.node("cp-1", control_plane=True)])
        self.assertEqual(targets(analysis, "node:cp-1", "RBAC-021"), [GOAL])

    def test_a_worker_node_does_not_reach_cluster_admin_directly(self):
        analysis = analyse([fx.cluster_role("r", []), fx.node("worker-1")])
        self.assertNotIn("RBAC-021", ids(analysis, "node:worker-1"))

    def test_an_inferred_control_plane_node_says_so(self):
        analysis = analyse(
            [
                fx.cluster_role("r", []),
                fx.pod(
                    "kube-apiserver-cp",
                    "kube-system",
                    node_name="cp-1",
                    labels={"component": "kube-apiserver"},
                ),
            ]
        )
        edge = next(e for e in analysis.edges_from("node:cp-1") if e.rule_id == "RBAC-021")
        self.assertIn("inferred", edge.detail)


class Rbac022PodWriteTests(unittest.TestCase):
    def _items(self, rules):
        return [
            fx.pod("app-1", "ci", sa="privileged-app"),
            fx.service_account("ci", "privileged-app"),
            *bind_role("writer", "ci", rules),
        ]

    def test_patch_pods_reaches_the_pods_identity(self):
        analysis = analyse(self._items([fx.rule(["patch"], [""], ["pods"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-022"), ["sa:ci:privileged-app"])

    def test_update_pods_too(self):
        analysis = analyse(self._items([fx.rule(["update"], [""], ["pods"])]))
        self.assertEqual(targets(analysis, RUNNER, "RBAC-022"), ["sa:ci:privileged-app"])

    def test_get_pods_is_not_enough(self):
        analysis = analyse(self._items([fx.rule(["get"], [""], ["pods"])]))
        self.assertNotIn("RBAC-022", ids(analysis, RUNNER))

    def test_resource_names_restrict_it_to_the_named_pod(self):
        items = [
            fx.pod("app-1", "ci", sa="privileged-app"),
            fx.pod("app-2", "ci", sa="other-app"),
            fx.service_account("ci", "privileged-app"),
            fx.service_account("ci", "other-app"),
            *bind_role("writer", "ci", [fx.rule(["patch"], [""], ["pods"], resource_names=["app-1"])]),
        ]
        analysis = analyse(items)
        self.assertEqual(targets(analysis, RUNNER, "RBAC-022"), ["sa:ci:privileged-app"])


class Rbac023SecretCreateTests(unittest.TestCase):
    def test_create_secrets_mints_a_token_for_every_account_in_the_namespace(self):
        analysis = analyse(
            [
                fx.service_account("ci", "privileged-app"),
                *bind_role("writer", "ci", [fx.rule(["create"], [""], ["secrets"])]),
            ]
        )
        self.assertIn("sa:ci:privileged-app", targets(analysis, RUNNER, "RBAC-023"))

    def test_the_mechanism_mentions_the_1_24_change(self):
        analysis = analyse(
            [
                fx.service_account("ci", "privileged-app"),
                *bind_role("writer", "ci", [fx.rule(["create"], [""], ["secrets"])]),
            ]
        )
        edge = next(e for e in analysis.edges_from(RUNNER) if e.rule_id == "RBAC-023")
        self.assertIn("1.24", edge.detail)

    def test_reading_secrets_is_not_creating_them(self):
        analysis = analyse(
            [
                fx.service_account("ci", "privileged-app"),
                *bind_role("writer", "ci", [fx.rule(["get"], [""], ["secrets"])]),
            ]
        )
        self.assertNotIn("RBAC-023", ids(analysis, RUNNER))

    def test_resource_names_stop_create_entirely(self):
        analysis = analyse(
            [
                fx.service_account("ci", "privileged-app"),
                *bind_role(
                    "writer", "ci", [fx.rule(["create"], [""], ["secrets"], resource_names=["x"])]
                ),
            ]
        )
        self.assertNotIn("RBAC-023", ids(analysis, RUNNER))


class Rbac024NodeProxyTests(unittest.TestCase):
    def test_get_nodes_proxy_reaches_every_node(self):
        analysis = analyse(
            [
                fx.node("worker-1"),
                fx.node("worker-2"),
                *bind_cluster_role("proxy", [fx.rule(["get"], [""], ["nodes/proxy"])]),
            ]
        )
        self.assertEqual(
            targets(analysis, RUNNER, "RBAC-024"), ["node:worker-1", "node:worker-2"]
        )

    def test_resource_names_restrict_it_to_one_node(self):
        analysis = analyse(
            [
                fx.node("worker-1"),
                fx.node("worker-2"),
                *bind_cluster_role(
                    "proxy",
                    [fx.rule(["get"], [""], ["nodes/proxy"], resource_names=["worker-1"])],
                ),
            ]
        )
        self.assertEqual(targets(analysis, RUNNER, "RBAC-024"), ["node:worker-1"])

    def test_plain_nodes_access_is_not_proxy_access(self):
        analysis = analyse(
            [fx.node("worker-1"), *bind_cluster_role("proxy", [fx.rule(["get"], [""], ["nodes"])])]
        )
        self.assertNotIn("RBAC-024", ids(analysis, RUNNER))

    def test_nodes_metrics_is_not_proxy_access(self):
        analysis = analyse(
            [
                fx.node("worker-1"),
                *bind_cluster_role("proxy", [fx.rule(["get"], [""], ["nodes/metrics"])]),
            ]
        )
        self.assertNotIn("RBAC-024", ids(analysis, RUNNER))


class NamespaceAdminNodeTests(unittest.TestCase):
    def test_namespace_admin_can_create_pods_there(self):
        analysis = analyse(
            [
                fx.service_account("ci", "privileged-app"),
                fx.cluster_role("r", []),
            ]
        )
        self.assertIn("sa:ci:privileged-app", targets(analysis, "nsadmin:ci", "RBAC-007"))

    def test_namespace_admin_in_an_unknown_namespace_reaches_nothing(self):
        analysis = analyse([fx.cluster_role("r", [])])
        self.assertEqual(analysis.edges_from("nsadmin:nowhere"), [])

    def test_a_terminal_node_has_no_outgoing_edges(self):
        analysis = analyse([fx.cluster_role("r", [])])
        self.assertEqual(analysis.edges_from(GOAL), [])

    def test_an_unparseable_node_has_no_outgoing_edges(self):
        analysis = analyse([fx.cluster_role("r", [])])
        self.assertEqual(analysis.edges_from("nonsense"), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
