"""Output formatting: plain text, JSON and DOT.

The text format is written to be read in a terminal by someone who has to act
on it, so every hop carries three things: the rule that permits it, the
identity it reaches, and the command a tester would run next.  The JSON format
is the same information with nothing elided, for piping into something else.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from .graph import Edge, Note, Path, node_label
from .model import Cluster
from .query import ResourceSpec, WhoCanRow
from .rules import EdgeRule, all_rules, get_rule, severity_rank

INDENT = "  "


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


# -- escalate ---------------------------------------------------------------


def render_paths_text(
    source: str,
    target: str,
    paths: Sequence[Path],
    notes: Sequence[Note] = (),
    truncated: bool = False,
) -> str:
    lines: list[str] = []
    lines.append(f"from: {node_label(source)}  ({source})")
    lines.append(f"to:   {node_label(target)}")
    lines.append("")
    if not paths:
        lines.append("No escalation path found.")
        lines.append("")
        lines.append(
            "This is a statement about the rules in the dump, not about the cluster: "
            "a path through a CustomResourceDefinition, an admission controller or a "
            "workload's own API is not visible here. See 'what this tool does not do' "
            "in the README."
        )
    else:
        plural = "path" if len(paths) == 1 else "paths"
        lines.append(f"{len(paths)} {plural} found, shortest first.")
        if truncated:
            lines.append("(result limit reached; raise --max-paths to see more)")
        for index, path in enumerate(paths, start=1):
            lines.append("")
            hops = "hop" if path.length == 1 else "hops"
            lines.append(
                f"path {index}: {path.length} {hops}, worst severity {path.worst_severity}"
            )
            for hop, edge in enumerate(path.edges, start=1):
                lines.append(f"{INDENT}{hop}. [{edge.rule_id} {edge.severity}] {edge.detail}")
                lines.append(f"{INDENT}   -> {node_label(edge.target)}")
                if edge.grant_rule:
                    lines.append(f"{INDENT}   rule: {edge.grant_rule}")
                lines.append(f"{INDENT}   from: {edge.grant_source}")
                lines.append(f"{INDENT}   do:   {edge.action}")
    if notes:
        lines.append("")
        lines.append(f"{len(notes)} related observation(s) that are not themselves a hop:")
        for note in notes:
            scope = f" [{note.namespace}]" if note.namespace else ""
            lines.append(f"{INDENT}[{note.rule_id} {note.severity}]{scope} {note.detail}")
    return "\n".join(lines) + "\n"


def paths_to_json(source: str, target: str, paths: Sequence[Path], notes: Sequence[Note]) -> dict:
    return {
        "source": source,
        "sourceLabel": node_label(source),
        "target": target,
        "pathCount": len(paths),
        "paths": [
            {
                "length": path.length,
                "worstSeverity": path.worst_severity,
                "nodes": [{"id": n, "label": node_label(n)} for n in path.nodes()],
                "edges": [_edge_to_json(edge) for edge in path.edges],
            }
            for path in paths
        ],
        "notes": [_note_to_json(note) for note in notes],
    }


def _edge_to_json(edge: Edge) -> dict:
    return {
        "ruleId": edge.rule_id,
        "severity": edge.severity,
        "source": edge.source,
        "target": edge.target,
        "targetLabel": node_label(edge.target),
        "namespace": edge.namespace,
        "detail": edge.detail,
        "action": edge.action,
        "grantSource": edge.grant_source,
        "grantRule": edge.grant_rule,
    }


def _note_to_json(note: Note) -> dict:
    return {
        "ruleId": note.rule_id,
        "severity": note.severity,
        "subject": note.subject,
        "namespace": note.namespace,
        "detail": note.detail,
        "grantSource": note.grant_source,
        "grantRule": note.grant_rule,
    }


SEVERITY_COLOURS = {
    "critical": "#b00020",
    "high": "#d2691e",
    "medium": "#b8860b",
    "low": "#4f6d7a",
}


def render_dot(edges: Sequence[Edge], name: str = "rbac") -> str:
    """Emit a DOT digraph.

    Node identifiers are quoted strings, so no mangling of ``:`` is needed.
    """
    lines = [f"digraph {name} {{", '  rankdir="LR";', '  node [shape=box, fontname="monospace"];']
    nodes: dict[str, None] = {}
    for edge in edges:
        nodes.setdefault(edge.source, None)
        nodes.setdefault(edge.target, None)
    for node in nodes:
        shape = "doubleoctagon" if node == "cluster-admin" else "box"
        lines.append(
            f'  "{_dot_escape(node)}" [label="{_dot_escape(node_label(node))}", shape={shape}];'
        )
    for edge in edges:
        label = f"{edge.rule_id}"
        if edge.namespace:
            # A real newline; _dot_escape turns it into the \n that DOT wants.
            label += f"\nns={edge.namespace}"
        colour = SEVERITY_COLOURS.get(edge.severity, "#333333")
        lines.append(
            f'  "{_dot_escape(edge.source)}" -> "{_dot_escape(edge.target)}" '
            f'[label="{_dot_escape(label)}", color="{colour}", fontsize=10];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


# -- who-can ----------------------------------------------------------------


def render_who_can_text(
    verb: str,
    spec: ResourceSpec,
    rows: Sequence[WhoCanRow],
    warnings: Sequence[str] = (),
) -> str:
    lines = [f"who can `{verb} {spec}`:", ""]
    if not rows:
        lines.append("Nobody, according to this dump.")
    else:
        for row in rows:
            lines.append(f"{row.subject}")
            lines.append(f"{INDENT}scope: {row.scope_text}")
            if row.via_groups:
                lines.append(f"{INDENT}via group: {', '.join(row.via_groups)}")
            if row.aggregated_from:
                lines.append(f"{INDENT}aggregated from: {', '.join(row.aggregated_from)}")
            for grant in row.grants[:4]:
                lines.append(f"{INDENT}rule: {grant.rule_text()}")
                lines.append(f"{INDENT}      {grant.source_text()} ({grant.scope_text})")
            if len(row.grants) > 4:
                lines.append(f"{INDENT}... and {len(row.grants) - 4} further matching rule(s)")
            lines.append("")
    if warnings:
        lines.append("notes on this query:")
        for warning in warnings:
            lines.append(f"{INDENT}- {warning}")
    return "\n".join(lines).rstrip() + "\n"


def who_can_to_json(
    verb: str, spec: ResourceSpec, rows: Sequence[WhoCanRow], warnings: Sequence[str]
) -> dict:
    return {
        "verb": verb,
        "resource": str(spec),
        "apiGroup": spec.api_group,
        "subresource": spec.subresource,
        "subjectCount": len(rows),
        "subjects": [
            {
                "id": row.subject.id,
                "kind": row.subject.kind,
                "name": row.subject.name,
                "namespace": row.subject.namespace,
                "clusterWide": row.cluster_wide,
                "namespaces": row.namespaces,
                "viaGroups": row.via_groups,
                "aggregatedFrom": row.aggregated_from,
                "grants": [
                    {
                        "rule": grant.rule_text(),
                        "source": grant.source_text(),
                        "scope": grant.scope_text,
                    }
                    for grant in row.grants
                ],
            }
            for row in rows
        ],
        "notes": list(warnings),
    }


# -- audit ------------------------------------------------------------------


def render_audit_text(
    cluster: Cluster,
    summary: dict[str, int],
    edges: Sequence[Edge],
    notes: Sequence[Note],
    reachable: dict[str, Sequence[Path]],
) -> str:
    lines = ["rbac-paths audit", ""]
    lines.append("input: " + ", ".join(cluster.sources))
    lines.append(
        INDENT
        + ", ".join(f"{key}={value}" for key, value in summary.items() if value)
    )
    if cluster.skipped_kinds:
        skipped = ", ".join(
            f"{kind}={count}" for kind, count in sorted(cluster.skipped_kinds.items())
        )
        lines.append(f"{INDENT}not modelled, ignored: {skipped}")
    if cluster.warnings:
        lines.append("")
        lines.append("input warnings:")
        for warning in cluster.warnings:
            lines.append(f"{INDENT}- {warning}")
    lines.append("")
    if reachable:
        lines.append(
            f"{len(reachable)} subject(s) reach cluster-admin, shortest path first:"
        )
        ordered = sorted(reachable.items(), key=lambda kv: (kv[1][0].length, kv[0]))
        for subject_id, paths in ordered:
            best = paths[0]
            chain = " -> ".join(edge.rule_id for edge in best.edges)
            lines.append(
                f"{INDENT}{node_label(subject_id)}: {best.length} hop(s) via {chain}"
            )
    else:
        lines.append("No subject in this dump reaches cluster-admin.")
    lines.append("")
    by_rule: dict[str, list[Edge]] = {}
    for edge in edges:
        by_rule.setdefault(edge.rule_id, []).append(edge)
    note_by_rule: dict[str, list[Note]] = {}
    for note in notes:
        note_by_rule.setdefault(note.rule_id, []).append(note)
    rule_ids = sorted(
        set(by_rule) | set(note_by_rule),
        key=lambda rid: (
            severity_rank(_worst(by_rule.get(rid, []), note_by_rule.get(rid, []))),
            rid,
        ),
    )
    lines.append("escalation primitives present, worst first:")
    for rule_id in rule_ids:
        rule = get_rule(rule_id)
        title = rule.title if rule else rule_id
        rule_edges = by_rule.get(rule_id, [])
        rule_notes = note_by_rule.get(rule_id, [])
        worst = _worst(rule_edges, rule_notes)
        lines.append("")
        lines.append(f"[{rule_id} {worst}] {title}")
        lines.append(f"{INDENT}{len(rule_edges)} escalation edge(s), {len(rule_notes)} note(s)")
        for edge in rule_edges[:6]:
            scope = f" [{edge.namespace}]" if edge.namespace else ""
            lines.append(
                f"{INDENT}- {node_label(edge.source)}{scope} -> "
                f"{node_label(edge.target)}"
            )
            lines.append(f"{INDENT}  {edge.detail}")
            if edge.grant_source:
                lines.append(f"{INDENT}  from: {edge.grant_source}")
        if len(rule_edges) > 6:
            lines.append(f"{INDENT}- ... and {len(rule_edges) - 6} further edge(s)")
        for note in rule_notes[:6]:
            scope = f" [{note.namespace}]" if note.namespace else ""
            lines.append(f"{INDENT}- note: {note.subject}{scope} {note.detail}")
        if len(rule_notes) > 6:
            lines.append(f"{INDENT}- ... and {len(rule_notes) - 6} further note(s)")
    lines.append("")
    lines.append("Run `rbac-paths --explain <rule-id>` for the mechanism and remediation.")
    return "\n".join(lines) + "\n"


def _worst(edges: Sequence[Edge], notes: Sequence[Note]) -> str:
    severities = [e.severity for e in edges] + [n.severity for n in notes]
    if not severities:
        return "low"
    return min(severities, key=severity_rank)


def audit_to_json(
    cluster: Cluster,
    summary: dict[str, int],
    edges: Sequence[Edge],
    notes: Sequence[Note],
    reachable: dict[str, Sequence[Path]],
) -> dict:
    by_rule: dict[str, dict] = {}
    for edge in edges:
        entry = by_rule.setdefault(
            edge.rule_id, {"ruleId": edge.rule_id, "edges": [], "notes": []}
        )
        entry["edges"].append(_edge_to_json(edge))
    for note in notes:
        entry = by_rule.setdefault(
            note.rule_id, {"ruleId": note.rule_id, "edges": [], "notes": []}
        )
        entry["notes"].append(_note_to_json(note))
    for rule_id, entry in by_rule.items():
        rule = get_rule(rule_id)
        entry["title"] = rule.title if rule else rule_id
    # Severity comes from the worst edge or note carrying the rule, which is
    # taken from the objects rather than from the dicts built above.
    severity_by_rule: dict[str, str] = {}
    for edge in edges:
        current = severity_by_rule.get(edge.rule_id)
        if current is None or severity_rank(edge.severity) < severity_rank(current):
            severity_by_rule[edge.rule_id] = edge.severity
    for note in notes:
        current = severity_by_rule.get(note.rule_id)
        if current is None or severity_rank(note.severity) < severity_rank(current):
            severity_by_rule[note.rule_id] = note.severity
    for rule_id, entry in by_rule.items():
        entry["severity"] = severity_by_rule.get(rule_id, "low")
    return {
        "input": {
            "sources": list(cluster.sources),
            "counts": summary,
            "ignoredKinds": dict(sorted(cluster.skipped_kinds.items())),
            "warnings": list(cluster.warnings),
        },
        "subjectsReachingClusterAdmin": [
            {
                "subject": subject_id,
                "shortestPathLength": paths[0].length,
                "ruleChain": [edge.rule_id for edge in paths[0].edges],
            }
            for subject_id, paths in sorted(
                reachable.items(), key=lambda kv: (kv[1][0].length, kv[0])
            )
        ],
        "primitives": [
            by_rule[rule_id]
            for rule_id in sorted(
                by_rule, key=lambda rid: (severity_rank(by_rule[rid]["severity"]), rid)
            )
        ],
    }


# -- rules ------------------------------------------------------------------


def render_rule_explanation(rule: EdgeRule) -> str:
    lines = [
        f"{rule.id}  [{rule.severity}]  {rule.title}",
        "",
        "mechanism",
        _wrap(rule.mechanism),
        "",
        "remediation",
        _wrap(rule.remediation),
    ]
    if rule.references:
        lines.append("")
        lines.append("references")
        for reference in rule.references:
            lines.append(f"{INDENT}{reference}")
    return "\n".join(lines) + "\n"


def render_rule_list() -> str:
    lines = ["escalation edge rules:", ""]
    for rule in sorted(all_rules(), key=lambda r: (severity_rank(r.severity), r.id)):
        lines.append(f"{rule.id}  {rule.severity:<9}{rule.title}")
    lines.append("")
    lines.append("Run `rbac-paths --explain <rule-id>` for the mechanism and remediation.")
    return "\n".join(lines) + "\n"


def rules_to_json() -> dict:
    return {
        "rules": [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "mechanism": rule.mechanism,
                "remediation": rule.remediation,
                "references": list(rule.references),
            }
            for rule in all_rules()
        ]
    }


def _wrap(text: str, width: int = 78) -> str:
    words = text.split()
    lines: list[str] = []
    current = INDENT
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = INDENT
        current += word + " "
    if current.strip():
        lines.append(current.rstrip())
    return "\n".join(lines)


def dumps(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"
