"""Advisory policy parsing.

Two invariants drive these tests:

1. The payload is untrusted remote data from a repository that evolves
   independently, so no input may raise.
2. Failing to parse a warning must not block a job the backend already allowed —
   the failure mode is an empty tuple, never an exception.
"""

import dataclasses

import pytest

from vardrrunner import policy


class TestParseWarnings:
    def test_parses_the_documented_shape(self):
        w = policy.parse_warnings(
            {"warnings": [{"reason": "target_out_of_scope", "message": "a.com not in scope"}]}
        )
        assert len(w) == 1
        assert w[0].reason == "target_out_of_scope"
        assert w[0].message == "a.com not in scope"

    def test_accepts_a_bare_list(self):
        assert len(policy.parse_warnings([{"reason": "scope_ambiguous"}])) == 1

    def test_absent_warnings_key_yields_nothing(self):
        assert policy.parse_warnings({"id": "job-1", "status": "running"}) == ()

    def test_preserves_order_and_multiplicity(self):
        w = policy.parse_warnings({"warnings": [{"reason": "a"}, {"reason": "b"}, {"reason": "a"}]})
        assert [x.reason for x in w] == ["a", "b", "a"]

    def test_skips_entries_with_neither_reason_nor_message(self):
        w = policy.parse_warnings({"warnings": [{}, {"reason": "real"}, {"other": 1}]})
        assert [x.reason for x in w] == ["real"]

    def test_message_only_entry_is_kept(self):
        """A finding the runner cannot label is still a finding to show."""
        w = policy.parse_warnings({"warnings": [{"message": "something happened"}]})
        assert len(w) == 1 and w[0].message == "something happened"

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            "string",
            42,
            0,
            [],
            {},
            {"warnings": None},
            {"warnings": "no"},
            {"warnings": 5},
            {"warnings": [1, "a", None]},
            {"warnings": [{"reason": 5, "message": []}]},
            {"warnings": [{"reason": None, "message": None}]},
        ],
    )
    def test_hostile_payloads_never_raise(self, payload):
        assert policy.parse_warnings(payload) == () or isinstance(
            policy.parse_warnings(payload), tuple
        )

    def test_non_string_fields_are_coerced_away_not_crashed_on(self):
        w = policy.parse_warnings({"warnings": [{"reason": "ok", "message": {"nested": 1}}]})
        assert w[0].reason == "ok" and w[0].message == ""

    def test_result_is_immutable(self):
        w = policy.parse_warnings({"warnings": [{"reason": "x"}]})
        with pytest.raises(dataclasses.FrozenInstanceError):
            w[0].reason = "changed"  # type: ignore[misc]


class TestPresentation:
    def test_known_reason_gets_a_human_label(self):
        w = policy.parse_warnings({"warnings": [{"reason": "outside_testing_window"}]})
        assert "Outside the agreed testing window" in w[0].describe()

    def test_unknown_reason_is_shown_verbatim_not_dropped(self):
        w = policy.parse_warnings({"warnings": [{"reason": "brand_new_code"}]})
        assert "brand_new_code" in w[0].describe()

    def test_format_warnings_one_line_each(self):
        w = policy.parse_warnings({"warnings": [{"reason": "a"}, {"reason": "b"}]})
        assert len(policy.format_warnings(w)) == 2

    def test_summarize_lists_codes_and_count(self):
        w = policy.parse_warnings({"warnings": [{"reason": "a"}, {"reason": "b"}]})
        s = policy.summarize(w)
        assert "2 policy warning(s)" in s and "a" in s and "b" in s

    def test_summarize_empty_is_empty_string(self):
        assert policy.summarize(()) == ""


class TestStopWorkDetection:
    def test_detects_stop_work_reported_as_a_warning(self):
        w = policy.parse_warnings({"warnings": [{"reason": "stop_work_active"}]})
        assert policy.has_stop_work(w) is True

    def test_ordinary_warnings_are_not_stop_work(self):
        w = policy.parse_warnings({"warnings": [{"reason": "target_out_of_scope"}]})
        assert policy.has_stop_work(w) is False
