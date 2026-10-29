"""The command line: output formats and exit codes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

import fixtures as fx
from rbac_paths.cli import (
    EXIT_FINDINGS,
    EXIT_INPUT,
    EXIT_OK,
    EXIT_USAGE,
    main,
)

RUNNER = "sa:ci:pipeline-runner"


def run(*argv: str) -> tuple[int, str]:
    """Invoke the CLI in process.

    argparse writes --help, --version and its own usage errors straight to the
    real streams, so they are captured here as well to keep the test output
    clean.
    """
    out = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(argv), out=out)
    return code, out.getvalue()


class ExitCodeTests(unittest.TestCase):
    def test_findings_exit_one(self):
        code, _ = run("escalate", "--dump", fx.VULNERABLE, "--from", RUNNER)
        self.assertEqual(code, EXIT_FINDINGS)

    def test_no_findings_exit_zero(self):
        code, _ = run("escalate", "--dump", fx.HARDENED, "--from", RUNNER)
        self.assertEqual(code, EXIT_OK)

    def test_exit_zero_flag_overrides(self):
        code, _ = run("escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--exit-zero")
        self.assertEqual(code, EXIT_OK)

    def test_audit_with_findings_exits_one(self):
        code, _ = run("audit", "--dump", fx.VULNERABLE)
        self.assertEqual(code, EXIT_FINDINGS)

    def test_who_can_always_exits_zero(self):
        code, _ = run("who-can", "--dump", fx.VULNERABLE, "get", "secrets")
        self.assertEqual(code, EXIT_OK)

    def test_who_can_with_no_answer_also_exits_zero(self):
        code, _ = run("who-can", "--dump", fx.HARDENED, "delete", "nodes")
        self.assertEqual(code, EXIT_OK)

    def test_a_bad_subject_is_a_usage_error(self):
        code, _ = run("escalate", "--dump", fx.VULNERABLE, "--from", "runner")
        self.assertEqual(code, EXIT_USAGE)

    def test_a_bad_target_is_a_usage_error(self):
        code, _ = run(
            "escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--to", "secrets"
        )
        self.assertEqual(code, EXIT_USAGE)

    def test_a_zero_max_depth_is_a_usage_error(self):
        code, _ = run(
            "escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--max-depth", "0"
        )
        self.assertEqual(code, EXIT_USAGE)

    def test_a_missing_dump_is_an_input_error(self):
        code, _ = run("audit", "--dump", os.path.join(tempfile.gettempdir(), "nope-xyz.json"))
        self.assertEqual(code, EXIT_INPUT)

    def test_an_unknown_rule_id_is_a_usage_error(self):
        code, _ = run("--explain", "RBAC-999")
        self.assertEqual(code, EXIT_USAGE)

    def test_no_command_prints_help_and_exits_two(self):
        code, text = run()
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("usage: rbac-paths", text)

    def test_an_unknown_format_is_rejected_by_argparse(self):
        code, _ = run("who-can", "--dump", fx.VULNERABLE, "--format", "dot", "get", "secrets")
        self.assertEqual(code, EXIT_USAGE)


class TextOutputTests(unittest.TestCase):
    def test_escalate_names_the_source_and_the_target(self):
        _, text = run("escalate", "--dump", fx.VULNERABLE, "--from", RUNNER)
        self.assertIn("ServiceAccount ci/pipeline-runner", text)
        self.assertIn("cluster-admin", text)

    def test_escalate_shows_the_rule_and_the_action(self):
        _, text = run("escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--max-paths", "1")
        self.assertIn("rule: verbs=", text)
        self.assertIn("do:   ", text)
        self.assertIn("from: ", text)

    def test_escalate_with_no_path_says_what_that_means(self):
        _, text = run("escalate", "--dump", fx.HARDENED, "--from", RUNNER)
        self.assertIn("No escalation path found", text)
        self.assertIn("not about the cluster", text)

    def test_audit_lists_the_input_and_the_counts(self):
        _, text = run("audit", "--dump", fx.VULNERABLE)
        self.assertIn("cluster-vulnerable.json", text)
        self.assertIn("clusterRoles=", text)

    def test_audit_surfaces_the_input_warning(self):
        _, text = run("audit", "--dump", fx.VULNERABLE)
        self.assertIn("broken-legacy-binding", text)

    def test_audit_ranks_critical_first(self):
        _, text = run("audit", "--dump", fx.VULNERABLE)
        first = next(line for line in text.splitlines() if line.startswith("[RBAC-"))
        self.assertIn("critical", first)

    def test_who_can_text(self):
        _, text = run("who-can", "--dump", fx.VULNERABLE, "create", "pods/exec")
        self.assertIn("who can `create pods/exec`", text)
        self.assertIn("ServiceAccount ci/pipeline-runner", text)

    def test_who_can_explains_subresource_matching(self):
        _, text = run("who-can", "--dump", fx.VULNERABLE, "create", "pods/exec")
        self.assertIn("*/exec", text)

    def test_explain_prints_mechanism_and_remediation(self):
        code, text = run("--explain", "RBAC-011")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("mechanism", text)
        self.assertIn("remediation", text)
        self.assertIn("https://kubernetes.io/", text)

    def test_explain_is_case_insensitive(self):
        code, text = run("--explain", "rbac-011")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("RBAC-011", text)

    def test_explain_subcommand_works_too(self):
        code, text = run("explain", "RBAC-013")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("1.24", text)

    def test_list_rules(self):
        code, text = run("--list-rules")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("RBAC-001", text)
        self.assertIn("RBAC-024", text)

    def test_rules_subcommand(self):
        code, text = run("rules")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("RBAC-001", text)


class JsonOutputTests(unittest.TestCase):
    def test_escalate_json_is_valid(self):
        _, text = run(
            "escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--format", "json"
        )
        payload = json.loads(text)
        self.assertEqual(payload["source"], RUNNER)
        self.assertGreater(payload["pathCount"], 0)

    def test_escalate_json_edges_carry_everything_needed(self):
        _, text = run(
            "escalate",
            "--dump",
            fx.VULNERABLE,
            "--from",
            RUNNER,
            "--format",
            "json",
            "--max-paths",
            "1",
        )
        edge = json.loads(text)["paths"][0]["edges"][0]
        for key in ("ruleId", "severity", "source", "target", "detail", "action", "grantSource"):
            self.assertIn(key, edge)

    def test_escalate_json_with_no_paths(self):
        _, text = run(
            "escalate", "--dump", fx.HARDENED, "--from", RUNNER, "--format", "json"
        )
        self.assertEqual(json.loads(text)["pathCount"], 0)

    def test_audit_json_is_valid(self):
        _, text = run("audit", "--dump", fx.VULNERABLE, "--format", "json")
        payload = json.loads(text)
        self.assertIn("primitives", payload)
        self.assertIn("subjectsReachingClusterAdmin", payload)
        self.assertEqual(payload["input"]["sources"], ["cluster-vulnerable.json"])

    def test_audit_json_primitives_are_sorted_by_severity(self):
        _, text = run("audit", "--dump", fx.VULNERABLE, "--format", "json")
        severities = [p["severity"] for p in json.loads(text)["primitives"]]
        self.assertEqual(severities[0], "critical")

    def test_who_can_json_is_valid(self):
        _, text = run(
            "who-can", "--dump", fx.VULNERABLE, "get", "secrets", "--format", "json"
        )
        payload = json.loads(text)
        self.assertGreater(payload["subjectCount"], 0)
        self.assertEqual(payload["verb"], "get")

    def test_rules_json_is_valid(self):
        _, text = run("rules", "--format", "json")
        payload = json.loads(text)
        self.assertEqual(len(payload["rules"]), 24)


class DotOutputTests(unittest.TestCase):
    def test_escalate_dot_is_a_digraph(self):
        _, text = run(
            "escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--format", "dot"
        )
        self.assertTrue(text.startswith("digraph escalation {"))
        self.assertTrue(text.rstrip().endswith("}"))

    def test_escalate_dot_quotes_every_node_id(self):
        _, text = run(
            "escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--format", "dot"
        )
        self.assertIn('"sa:ci:pipeline-runner"', text)

    def test_escalate_dot_marks_the_goal(self):
        _, text = run(
            "escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--format", "dot"
        )
        self.assertIn("doubleoctagon", text)

    def test_dot_uses_a_single_backslash_n_for_a_line_break(self):
        _, text = run(
            "escalate", "--dump", fx.VULNERABLE, "--from", RUNNER, "--format", "dot"
        )
        self.assertIn("\\nns=", text)
        self.assertNotIn("\\\\nns=", text)

    def test_dot_is_balanced_and_every_statement_is_terminated(self):
        _, text = run("audit", "--dump", fx.VULNERABLE, "--format", "dot")
        body = [
            line.strip()
            for line in text.splitlines()[1:-1]
            if line.strip() and not line.strip().startswith("//")
        ]
        self.assertTrue(body)
        for line in body:
            self.assertTrue(line.endswith(";"), line)
        self.assertEqual(text.count("{"), 1)
        self.assertEqual(text.count("}"), 1)

    def test_dot_for_an_empty_result_is_still_valid(self):
        _, text = run("escalate", "--dump", fx.HARDENED, "--from", RUNNER, "--format", "dot")
        self.assertTrue(text.startswith("digraph escalation {"))
        self.assertTrue(text.rstrip().endswith("}"))


class InputHandlingTests(unittest.TestCase):
    def test_both_dumps_can_be_loaded_together(self):
        code, text = run("audit", "--dump", fx.VULNERABLE, "--dump", fx.HARDENED, "--format", "json")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(
            json.loads(text)["input"]["sources"],
            ["cluster-vulnerable.json", "cluster-hardened.json"],
        )

    def test_a_directory_of_dumps_works(self):
        code, _ = run("audit", "--dump", fx.EXAMPLES_DIR)
        self.assertEqual(code, EXIT_FINDINGS)

    def test_an_extra_group_changes_the_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    fx.listing(
                        [
                            fx.cluster_role("wh", [fx.rule(["*"], ["*"], ["*"])]),
                            fx.cluster_role_binding(
                                "wh", "wh", [fx.group_subject("platform-admins")]
                            ),
                        ]
                    ),
                    handle,
                )
            without, _ = run("escalate", "--dump", path, "--from", "user:alice")
            with_group, _ = run(
                "escalate", "--dump", path, "--from", "user:alice", "--group", "platform-admins"
            )
        self.assertEqual(without, EXIT_OK)
        self.assertEqual(with_group, EXIT_FINDINGS)

    def test_assume_psa_restricted_removes_the_host_paths(self):
        _, text = run(
            "escalate",
            "--dump",
            fx.VULNERABLE,
            "--from",
            RUNNER,
            "--assume-psa",
            "restricted",
            "--format",
            "json",
            "--max-paths",
            "50",
        )
        chains = [
            [e["ruleId"] for e in p["edges"]] for p in json.loads(text)["paths"]
        ]
        self.assertNotIn(["RBAC-008", "RBAC-021"], chains)

    def test_the_namespace_label_still_wins_over_assume_psa(self):
        # ci carries no enforce label in the vulnerable dump, so --assume-psa
        # privileged and the default agree; platform is labelled restricted and
        # must stay restricted either way.
        _, text = run(
            "audit", "--dump", fx.VULNERABLE, "--assume-psa", "privileged", "--format", "json"
        )
        payload = json.loads(text)
        notes = [
            n
            for p in payload["primitives"]
            if p["ruleId"] == "RBAC-008"
            for n in p["notes"]
        ]
        self.assertTrue(any("restricted" in n["detail"] for n in notes))

    def test_version_exits_zero(self):
        self.assertEqual(run("--version")[0], 0)

    def test_help_exits_zero(self):
        self.assertEqual(run("--help")[0], 0)

    def test_subcommand_help_exits_zero(self):
        self.assertEqual(run("escalate", "--help")[0], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
