"""Reading kubectl JSON dumps."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import fixtures as fx
from rbac_paths.loader import (
    LoadError,
    cluster_from_payload,
    discover_files,
    iter_objects,
    load_cluster,
    parse_policy_rule,
)


class ShapeTests(unittest.TestCase):
    def test_list_wrapper(self):
        payload = fx.listing([fx.cluster_role("a", [])])
        self.assertEqual(len(list(iter_objects(payload))), 1)

    def test_bare_array(self):
        payload = [fx.cluster_role("a", []), fx.cluster_role("b", [])]
        self.assertEqual(len(list(iter_objects(payload))), 2)

    def test_single_object(self):
        self.assertEqual(len(list(iter_objects(fx.cluster_role("a", [])))), 1)

    def test_nested_lists(self):
        payload = fx.listing([fx.listing([fx.cluster_role("a", [])])])
        self.assertEqual(len(list(iter_objects(payload))), 1)

    def test_non_object_is_skipped(self):
        self.assertEqual(list(iter_objects(42)), [])


class ParseTests(unittest.TestCase):
    def test_policy_rule_fields(self):
        parsed = parse_policy_rule(
            {
                "verbs": ["get"],
                "apiGroups": [""],
                "resources": ["secrets"],
                "resourceNames": ["a"],
            }
        )
        self.assertEqual(parsed.verbs, ("get",))
        self.assertEqual(parsed.api_groups, ("",))
        self.assertEqual(parsed.resources, ("secrets",))
        self.assertEqual(parsed.resource_names, ("a",))

    def test_missing_fields_become_empty_tuples(self):
        parsed = parse_policy_rule({})
        self.assertEqual(parsed.verbs, ())
        self.assertEqual(parsed.resources, ())

    def test_non_resource_only_flag(self):
        parsed = parse_policy_rule({"verbs": ["get"], "nonResourceURLs": ["/healthz"]})
        self.assertTrue(parsed.is_non_resource_only)

    def test_cluster_role_namespace_is_none(self):
        cluster = fx.build([fx.cluster_role("a", [])])
        role = next(iter(cluster.roles.values()))
        self.assertIsNone(role.namespace)

    def test_role_keeps_its_namespace(self):
        cluster = fx.build([fx.namespaced_role("a", "ci", [])])
        role = next(iter(cluster.roles.values()))
        self.assertEqual(role.namespace, "ci")

    def test_aggregation_rule_is_parsed(self):
        cluster = fx.build(
            [fx.cluster_role("agg", [], aggregation=[{"matchLabels": {"x": "y"}}])]
        )
        role = next(iter(cluster.roles.values()))
        self.assertEqual(len(role.aggregation_selectors), 1)

    def test_pod_defaults_to_the_default_service_account(self):
        cluster = cluster_from_payload(
            fx.listing(
                [
                    fx.cluster_role("a", []),
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "p", "namespace": "ci"},
                        "spec": {"containers": []},
                    },
                ]
            )
        )
        self.assertEqual(cluster.pods[0].service_account, "default")

    def test_pod_host_path_and_privileged(self):
        cluster = cluster_from_payload(
            fx.listing(
                [
                    fx.cluster_role("a", []),
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "p", "namespace": "ci"},
                        "spec": {
                            "hostPID": True,
                            "volumes": [{"name": "root", "hostPath": {"path": "/"}}],
                            "containers": [
                                {"name": "c", "securityContext": {"privileged": True}}
                            ],
                        },
                    },
                ]
            )
        )
        pod = cluster.pods[0]
        self.assertTrue(pod.host_pid)
        self.assertEqual(pod.host_path_volumes, ("/",))
        self.assertTrue(pod.has_privileged_container)

    def test_secret_type_and_annotation(self):
        cluster = fx.build([fx.cluster_role("a", []), fx.token_secret("t", "ci", "runner")])
        secret = cluster.secrets[0]
        self.assertTrue(secret.is_service_account_token)
        self.assertEqual(secret.service_account_name, "runner")

    def test_opaque_secret_is_not_a_token(self):
        cluster = fx.build([fx.cluster_role("a", []), fx.opaque_secret("o", "ci")])
        self.assertFalse(cluster.secrets[0].is_service_account_token)


class ValidationTests(unittest.TestCase):
    def test_cluster_role_binding_to_a_role_is_rejected(self):
        cluster = fx.build(
            [
                fx.cluster_role("a", []),
                fx.cluster_role_binding("b", "ns-role", [fx.user_subject("u")], role_kind="Role"),
            ]
        )
        self.assertEqual(cluster.bindings, [])
        self.assertTrue(any("invalid" in w for w in cluster.warnings))

    def test_binding_without_a_role_ref_is_dropped(self):
        cluster = cluster_from_payload(
            fx.listing(
                [
                    fx.cluster_role("a", []),
                    {
                        "apiVersion": fx.RBAC_API,
                        "kind": "ClusterRoleBinding",
                        "metadata": {"name": "broken"},
                        "subjects": [fx.user_subject("u")],
                    },
                ]
            )
        )
        self.assertEqual(cluster.bindings, [])
        self.assertTrue(any("missing roleRef" in w for w in cluster.warnings))

    def test_service_account_subject_without_a_namespace_takes_the_bindings(self):
        cluster = fx.build(
            [
                fx.namespaced_role("r", "ci", []),
                fx.role_binding(
                    "rb", "ci", "r", "Role", [{"kind": "ServiceAccount", "name": "runner"}]
                ),
            ]
        )
        self.assertEqual(cluster.bindings[0].subjects[0].namespace, "ci")

    def test_unknown_subject_kind_is_dropped(self):
        cluster = fx.build(
            [
                fx.cluster_role("a", []),
                fx.cluster_role_binding("b", "a", [{"kind": "Robot", "name": "r2"}]),
            ]
        )
        self.assertEqual(cluster.bindings[0].subjects, ())

    def test_unmodelled_kinds_are_counted_not_dropped_silently(self):
        cluster = fx.build(
            [
                fx.cluster_role("a", []),
                {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c"}},
            ]
        )
        self.assertEqual(cluster.skipped_kinds.get("ConfigMap"), 1)

    def test_duplicate_role_warns(self):
        cluster = fx.build([fx.cluster_role("a", []), fx.cluster_role("a", [])])
        self.assertTrue(any("twice" in w for w in cluster.warnings))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name: str, payload) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload if isinstance(payload, str) else json.dumps(payload))
        return path

    def test_load_one_file(self):
        path = self._write("c.json", fx.listing([fx.cluster_role("a", [])]))
        self.assertEqual(len(load_cluster([path]).roles), 1)

    def test_load_a_directory(self):
        self._write("one.json", fx.listing([fx.cluster_role("a", [])]))
        self._write("two.json", fx.listing([fx.cluster_role("b", [])]))
        self.assertEqual(len(load_cluster([self.tmp.name]).roles), 2)

    def test_directory_without_json_is_an_error(self):
        empty = tempfile.mkdtemp(dir=self.tmp.name)
        with self.assertRaises(LoadError):
            discover_files(empty)

    def test_missing_path_is_an_error(self):
        with self.assertRaises(LoadError):
            discover_files(os.path.join(self.tmp.name, "nope.json"))

    def test_concatenated_objects(self):
        text = json.dumps(fx.cluster_role("a", [])) + "\n" + json.dumps(fx.cluster_role("b", []))
        path = self._write("stream.json", text)
        self.assertEqual(len(load_cluster([path]).roles), 2)

    def test_invalid_json_is_an_input_error(self):
        path = self._write("bad.json", "{not json")
        with self.assertRaises(LoadError):
            load_cluster([path])

    def test_empty_file_is_an_input_error(self):
        path = self._write("empty.json", "   ")
        with self.assertRaises(LoadError):
            load_cluster([path])

    def test_a_dump_without_rbac_is_rejected(self):
        path = self._write("pods.json", fx.listing([fx.pod("p", "ci")]))
        with self.assertRaises(LoadError) as ctx:
            load_cluster([path])
        self.assertIn("no RBAC objects", str(ctx.exception))

    def test_stdin(self):
        text = json.dumps(fx.listing([fx.cluster_role("a", [])]))
        self.assertEqual(len(load_cluster(["-"], stdin_text=text).roles), 1)

    def test_sources_record_basenames_only(self):
        path = self._write("c.json", fx.listing([fx.cluster_role("a", [])]))
        self.assertEqual(load_cluster([path]).sources, ["c.json"])


class ClusterHelperTests(unittest.TestCase):
    def test_known_namespaces_gathers_from_everywhere(self):
        cluster = fx.build(
            [
                fx.namespaced_role("r", "ci", []),
                fx.service_account("platform", "sa"),
                fx.pod("p", "legacy"),
                fx.opaque_secret("s", "observability"),
            ]
        )
        self.assertEqual(
            cluster.known_namespaces(), ["ci", "legacy", "observability", "platform"]
        )

    def test_control_plane_from_a_node_label(self):
        cluster = fx.build([fx.cluster_role("a", []), fx.node("cp", control_plane=True)])
        self.assertEqual(cluster.control_plane_nodes(), ["cp"])

    def test_control_plane_inferred_from_an_apiserver_pod(self):
        cluster = fx.build(
            [
                fx.cluster_role("a", []),
                fx.pod(
                    "kube-apiserver-cp",
                    "kube-system",
                    node_name="cp",
                    labels={"component": "kube-apiserver"},
                ),
            ]
        )
        self.assertEqual(cluster.control_plane_nodes(), ["cp"])

    def test_a_plain_worker_is_not_control_plane(self):
        cluster = fx.build([fx.cluster_role("a", []), fx.node("w1")])
        self.assertEqual(cluster.control_plane_nodes(), [])

    def test_node_names_include_nodes_only_seen_through_pods(self):
        cluster = fx.build(
            [fx.cluster_role("a", []), fx.node("w1"), fx.pod("p", "ci", node_name="w2")]
        )
        self.assertEqual(cluster.node_names(), ["w1", "w2"])

    def test_psa_label_is_read(self):
        cluster = fx.build([fx.cluster_role("a", []), fx.namespace("ci", psa="restricted")])
        self.assertEqual(cluster.namespace("ci").psa_enforce, "restricted")

    def test_unknown_psa_value_is_ignored(self):
        cluster = fx.build([fx.cluster_role("a", []), fx.namespace("ci", psa="silly")])
        self.assertIsNone(cluster.namespace("ci").psa_enforce)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
