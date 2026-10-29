"""Label selector semantics, as ClusterRole aggregation uses them."""

from __future__ import annotations

import unittest

from rbac_paths.selectors import LabelSelector, MatchExpression, parse_label_selector


class EmptySelectorTests(unittest.TestCase):
    def test_empty_selector_matches_everything(self):
        self.assertTrue(LabelSelector().matches({}))

    def test_empty_selector_matches_a_labelled_object(self):
        self.assertTrue(LabelSelector().matches({"a": "b"}))

    def test_is_empty_flag(self):
        self.assertTrue(LabelSelector().is_empty)
        self.assertFalse(LabelSelector(match_labels=(("a", "b"),)).is_empty)

    def test_empty_selector_renders_a_warning(self):
        self.assertIn("matches every ClusterRole", str(LabelSelector()))


class MatchLabelsTests(unittest.TestCase):
    def test_single_label(self):
        selector = LabelSelector(match_labels=(("tier", "edge"),))
        self.assertTrue(selector.matches({"tier": "edge"}))

    def test_wrong_value(self):
        selector = LabelSelector(match_labels=(("tier", "edge"),))
        self.assertFalse(selector.matches({"tier": "core"}))

    def test_missing_key(self):
        selector = LabelSelector(match_labels=(("tier", "edge"),))
        self.assertFalse(selector.matches({}))

    def test_all_terms_must_match(self):
        selector = LabelSelector(match_labels=(("a", "1"), ("b", "2")))
        self.assertTrue(selector.matches({"a": "1", "b": "2", "c": "3"}))
        self.assertFalse(selector.matches({"a": "1"}))


class MatchExpressionTests(unittest.TestCase):
    def test_exists(self):
        expr = MatchExpression("k", "Exists")
        self.assertTrue(expr.matches({"k": ""}))
        self.assertFalse(expr.matches({}))

    def test_does_not_exist(self):
        expr = MatchExpression("k", "DoesNotExist")
        self.assertTrue(expr.matches({}))
        self.assertFalse(expr.matches({"k": "v"}))

    def test_in(self):
        expr = MatchExpression("k", "In", ("a", "b"))
        self.assertTrue(expr.matches({"k": "b"}))
        self.assertFalse(expr.matches({"k": "c"}))
        self.assertFalse(expr.matches({}))

    def test_not_in_is_satisfied_by_an_absent_key(self):
        expr = MatchExpression("k", "NotIn", ("a",))
        self.assertTrue(expr.matches({}))
        self.assertTrue(expr.matches({"k": "b"}))
        self.assertFalse(expr.matches({"k": "a"}))

    def test_unknown_operator_matches_nothing(self):
        expr = MatchExpression("k", "Sideways", ("a",))
        self.assertFalse(expr.matches({"k": "a"}))
        self.assertFalse(expr.matches({}))

    def test_rendering(self):
        self.assertEqual(str(MatchExpression("k", "Exists")), "k Exists")
        self.assertEqual(str(MatchExpression("k", "In", ("a", "b"))), "k In (a,b)")


class ParseTests(unittest.TestCase):
    def test_parse_match_labels(self):
        selector = parse_label_selector({"matchLabels": {"a": "b"}})
        self.assertEqual(selector.match_labels, (("a", "b"),))

    def test_parse_match_expressions(self):
        selector = parse_label_selector(
            {"matchExpressions": [{"key": "k", "operator": "In", "values": ["x"]}]}
        )
        self.assertEqual(len(selector.match_expressions), 1)
        self.assertEqual(selector.match_expressions[0].operator, "In")

    def test_parse_rubbish_is_an_empty_selector(self):
        self.assertTrue(parse_label_selector("not a dict").is_empty)
        self.assertTrue(parse_label_selector(None).is_empty)

    def test_parse_combined(self):
        selector = parse_label_selector(
            {
                "matchLabels": {"a": "b"},
                "matchExpressions": [{"key": "k", "operator": "Exists"}],
            }
        )
        self.assertTrue(selector.matches({"a": "b", "k": ""}))
        self.assertFalse(selector.matches({"a": "b"}))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
