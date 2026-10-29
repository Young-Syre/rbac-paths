"""Label selectors, as the aggregation controller evaluates them.

ClusterRole aggregation is driven by ``aggregationRule.clusterRoleSelectors``,
a list of ``metav1.LabelSelector``.  The semantics that matter here and are
easy to get wrong:

* An entry with neither ``matchLabels`` nor ``matchExpressions`` matches every
  ClusterRole.  A single empty selector in an ``aggregationRule`` therefore
  aggregates the whole cluster's RBAC into one role.
* Within one selector every term must match (AND).
* Across selectors any one matching is enough (OR).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

VALID_OPERATORS = ("In", "NotIn", "Exists", "DoesNotExist")


@dataclass(frozen=True)
class MatchExpression:
    key: str
    operator: str
    values: tuple[str, ...] = ()

    def matches(self, labels: Mapping[str, str]) -> bool:
        if self.operator == "Exists":
            return self.key in labels
        if self.operator == "DoesNotExist":
            return self.key not in labels
        if self.operator == "In":
            return self.key in labels and labels[self.key] in self.values
        if self.operator == "NotIn":
            # NotIn is satisfied when the key is absent, matching
            # metav1.LabelSelectorAsSelector.
            return self.key not in labels or labels[self.key] not in self.values
        # An unknown operator cannot be satisfied; the API server would have
        # rejected the object, so treat it as matching nothing rather than
        # everything.
        return False

    def __str__(self) -> str:
        if self.operator in ("Exists", "DoesNotExist"):
            return f"{self.key} {self.operator}"
        return f"{self.key} {self.operator} ({','.join(self.values)})"


@dataclass(frozen=True)
class LabelSelector:
    match_labels: tuple[tuple[str, str], ...] = ()
    match_expressions: tuple[MatchExpression, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.match_labels and not self.match_expressions

    def matches(self, labels: Mapping[str, str]) -> bool:
        if self.is_empty:
            return True
        for key, value in self.match_labels:
            if labels.get(key) != value:
                return False
        return all(expr.matches(labels) for expr in self.match_expressions)

    def __str__(self) -> str:
        if self.is_empty:
            return "<empty: matches every ClusterRole>"
        parts = [f"{k}={v}" for k, v in self.match_labels]
        parts += [str(e) for e in self.match_expressions]
        return ",".join(parts)


def parse_label_selector(raw: object) -> LabelSelector:
    if not isinstance(raw, dict):
        return LabelSelector()
    match_labels = raw.get("matchLabels") or {}
    labels: tuple[tuple[str, str], ...] = ()
    if isinstance(match_labels, dict):
        labels = tuple(sorted((str(k), str(v)) for k, v in match_labels.items()))
    expressions: list[MatchExpression] = []
    raw_expressions = raw.get("matchExpressions") or []
    if isinstance(raw_expressions, list):
        for entry in raw_expressions:
            if not isinstance(entry, dict):
                continue
            values = entry.get("values") or []
            expressions.append(
                MatchExpression(
                    key=str(entry.get("key", "")),
                    operator=str(entry.get("operator", "")),
                    values=tuple(str(v) for v in values) if isinstance(values, list) else (),
                )
            )
    return LabelSelector(match_labels=labels, match_expressions=tuple(expressions))
