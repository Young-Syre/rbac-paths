"""Command line interface.

Exit codes are part of the contract, because the point of a tool like this is
that CI can gate on it:

==  =========================================================================
0   ran successfully and found nothing (``escalate``: no path; ``audit``: no
    primitive).  ``who-can`` always exits 0 on success: a query having an
    answer is not a finding.
1   ran successfully and found something.
2   usage error - a bad flag, an unparseable subject, or a format the
    subcommand does not produce.
3   input error - a dump that is missing, unreadable, or not the JSON shape
    ``kubectl -o json`` produces.
4   an unexpected internal error, which is a bug; the traceback is suppressed
    unless ``--traceback`` is given.
==  =========================================================================

``--exit-zero`` forces 0 on a successful run, for a report you want to read
without failing the pipeline.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .graph import (
    GOAL,
    Analysis,
    collect_all_edges,
    find_paths,
    known_cluster_summary,
    parse_subject,
    parse_target,
    reachable_subjects,
)
from .loader import LoadError, load_cluster
from .model import PSA_LEVELS
from .query import parse_resource, query_warnings, who_can
from .render import (
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
from .resolver import Resolver
from .rules import get_rule

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_INTERNAL = 4

EPILOG = """\
input
  Local JSON only. Produce it with:

    kubectl get clusterroles,clusterrolebindings,roles,rolebindings,\\
      serviceaccounts,pods -A -o json > cluster.json

  Adding `kubectl get nodes,namespaces -o json` to the same file lets the tool
  name control-plane nodes and read the enforced Pod Security Standard instead
  of assuming one. Pass a directory to read every .json file in it, or `-` for
  stdin. This tool never contacts an API server.

examples
  rbac-paths escalate --dump cluster.json --from sa:ci:pipeline-runner
  rbac-paths escalate --dump cluster.json --from sa:ci:pipeline-runner --format dot
  rbac-paths who-can --dump cluster.json create pods/exec
  rbac-paths audit --dump cluster.json
  rbac-paths --explain RBAC-011
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbac-paths",
        description=(
            "Find Kubernetes RBAC privilege-escalation paths in a local kubectl JSON "
            "dump. Offline, read-only, standard library only."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"rbac-paths {__version__}")
    parser.add_argument(
        "--explain",
        metavar="RULE-ID",
        help="print the mechanism and remediation for one edge rule and exit",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="list every edge rule with its severity and exit",
    )
    parser.add_argument(
        "--traceback",
        action="store_true",
        help="show the traceback on an internal error instead of a one-line message",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add_common(sub: argparse.ArgumentParser, formats: Sequence[str]) -> None:
        sub.add_argument(
            "--dump",
            metavar="PATH",
            action="append",
            required=True,
            help="a kubectl JSON dump, a directory of them, or - for stdin (repeatable)",
        )
        sub.add_argument(
            "--format",
            choices=list(formats),
            default="text",
            help="output format (default: text)",
        )
        sub.add_argument(
            "--group",
            metavar="GROUP",
            action="append",
            default=[],
            help=(
                "an extra group the subject is in, for membership that comes from the "
                "authenticator and is not in the dump (repeatable)"
            ),
        )
        sub.add_argument(
            "--exit-zero",
            action="store_true",
            help="exit 0 even when something is found",
        )

    escalate = subparsers.add_parser(
        "escalate",
        help="find paths from a subject to cluster-admin or to a named permission",
        description=(
            "Find every path from one subject to cluster-admin, shortest first. Each "
            "hop names the rule that permits it and the action a tester would take."
        ),
    )
    add_common(escalate, ("text", "json", "dot"))
    escalate.add_argument(
        "--from",
        dest="subject",
        required=True,
        metavar="SUBJECT",
        help="sa:<namespace>:<name>, user:<name> or group:<name>",
    )
    escalate.add_argument(
        "--to",
        dest="target",
        default=GOAL,
        metavar="TARGET",
        help="cluster-admin (default) or <verb>:<resource>, e.g. get:secrets",
    )
    escalate.add_argument(
        "--assume-psa",
        choices=list(PSA_LEVELS),
        default="privileged",
        help=(
            "Pod Security Standard to assume for namespaces whose "
            "pod-security.kubernetes.io/enforce label is not in the dump "
            "(default: privileged, the API server's own default)"
        ),
    )
    escalate.add_argument("--max-depth", type=int, default=6, help="maximum hops (default: 6)")
    escalate.add_argument(
        "--max-paths", type=int, default=50, help="maximum paths to report (default: 50)"
    )

    whocan = subparsers.add_parser(
        "who-can",
        help="list every subject that may perform a verb on a resource",
        description=(
            "List every subject that may perform a verb on a resource, expanded over "
            "wildcards, ClusterRole aggregation and synthesised group membership."
        ),
    )
    add_common(whocan, ("text", "json"))
    whocan.add_argument("verb", help="get, list, create, patch, escalate, impersonate, ...")
    whocan.add_argument(
        "resource",
        help="secrets, pods/exec, deployments.apps - group as a suffix or via --api-group",
    )
    whocan.add_argument(
        "--api-group",
        default=None,
        help='API group; "" for the core group. Overrides a dotted suffix.',
    )
    whocan.add_argument("--namespace", default=None, help="restrict the answer to one namespace")
    whocan.add_argument(
        "--name",
        default=None,
        help="one object name, so rules carrying resourceNames can match",
    )

    audit = subparsers.add_parser(
        "audit",
        help="rank every escalation primitive present in the dump",
        description=(
            "Rank every escalation primitive present in the dump, and list the "
            "subjects that reach cluster-admin."
        ),
    )
    add_common(audit, ("text", "json", "dot"))
    audit.add_argument(
        "--assume-psa",
        choices=list(PSA_LEVELS),
        default="privileged",
        help="as for escalate (default: privileged)",
    )

    rules = subparsers.add_parser("rules", help="list every edge rule")
    rules.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )

    explain = subparsers.add_parser("explain", help="explain one edge rule")
    explain.add_argument("rule_id", metavar="RULE-ID")

    return parser


def _load(args: argparse.Namespace) -> tuple[Analysis, Resolver]:
    stdin_text = sys.stdin.read() if "-" in args.dump else None
    cluster = load_cluster(args.dump, stdin_text)
    resolver = Resolver(cluster)
    analysis = Analysis(
        cluster=cluster,
        resolver=resolver,
        assume_psa=getattr(args, "assume_psa", "privileged"),
        extra_groups=tuple(args.group),
    )
    return analysis, resolver


def _cmd_escalate(args: argparse.Namespace, out) -> int:
    try:
        subject = parse_subject(args.subject)
        target = parse_target(args.target)
    except ValueError as exc:
        print(f"rbac-paths: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.max_depth < 1 or args.max_paths < 1:
        print("rbac-paths: --max-depth and --max-paths must be at least 1", file=sys.stderr)
        return EXIT_USAGE
    analysis, _ = _load(args)
    paths = find_paths(
        analysis, subject.id, target, max_depth=args.max_depth, max_paths=args.max_paths
    )
    truncated = len(paths) >= args.max_paths
    if args.format == "json":
        out.write(dumps(paths_to_json(subject.id, target, paths, analysis.notes)))
    elif args.format == "dot":
        edges = [edge for path in paths for edge in path.edges]
        out.write(render_dot(edges, name="escalation"))
    else:
        out.write(render_paths_text(subject.id, target, paths, analysis.notes, truncated))
    return EXIT_FINDINGS if paths else EXIT_OK


def _cmd_who_can(args: argparse.Namespace, out) -> int:
    try:
        spec = parse_resource(args.resource, args.api_group)
    except ValueError as exc:
        print(f"rbac-paths: {exc}", file=sys.stderr)
        return EXIT_USAGE
    _, resolver = _load(args)
    rows = who_can(
        resolver,
        args.verb,
        spec,
        namespace=args.namespace,
        name=args.name,
        extra_groups=tuple(args.group),
    )
    warnings = query_warnings(args.verb, spec, args.name)
    if args.format == "json":
        out.write(dumps(who_can_to_json(args.verb, spec, rows, warnings)))
    else:
        out.write(render_who_can_text(args.verb, spec, rows, warnings))
    return EXIT_OK


def _cmd_audit(args: argparse.Namespace, out) -> int:
    analysis, resolver = _load(args)
    subjects = resolver.all_subjects()
    edges = collect_all_edges(analysis, subjects)
    reachable = reachable_subjects(analysis, subjects)
    notes = analysis.cluster_notes() + list(analysis.notes)
    summary = known_cluster_summary(analysis.cluster)
    if args.format == "json":
        out.write(dumps(audit_to_json(analysis.cluster, summary, edges, notes, reachable)))
    elif args.format == "dot":
        out.write(render_dot(edges, name="cluster"))
    else:
        out.write(render_audit_text(analysis.cluster, summary, edges, notes, reachable))
    return EXIT_FINDINGS if (edges or notes) else EXIT_OK


def main(argv: Sequence[str] | None = None, out=None) -> int:
    parser = build_parser()
    out = out or sys.stdout
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        # argparse exits 2 for a usage error and 0 for --help/--version, which
        # already matches the documented codes.
        return int(exc.code or 0)

    if args.explain or args.command == "explain":
        rule_id = args.explain or args.rule_id
        rule = get_rule(rule_id)
        if rule is None:
            print(
                f"rbac-paths: no such rule {rule_id!r}; try --list-rules",
                file=sys.stderr,
            )
            return EXIT_USAGE
        out.write(render_rule_explanation(rule))
        return EXIT_OK

    if args.list_rules or args.command == "rules":
        if getattr(args, "format", "text") == "json":
            out.write(dumps(rules_to_json()))
        else:
            out.write(render_rule_list())
        return EXIT_OK

    if args.command is None:
        parser.print_help(out)
        return EXIT_USAGE

    handlers = {
        "escalate": _cmd_escalate,
        "who-can": _cmd_who_can,
        "audit": _cmd_audit,
    }
    handler = handlers[args.command]
    try:
        code = handler(args, out)
    except LoadError as exc:
        print(f"rbac-paths: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        return EXIT_INTERNAL
    except Exception as exc:  # the top-level guard: report, do not traceback
        if args.traceback:
            raise
        print(f"rbac-paths: internal error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        print("rbac-paths: re-run with --traceback and please report it", file=sys.stderr)
        return EXIT_INTERNAL
    if code == EXIT_FINDINGS and getattr(args, "exit_zero", False):
        return EXIT_OK
    return code


def entrypoint() -> None:  # pragma: no cover - console_scripts shim
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
