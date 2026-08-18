"""Failure classification: the taxonomy every reported failure maps onto.

Category *values* are asserted literally because they are written to durable
records from the execution journal onward — renaming one is a breaking change,
and these tests are the tripwire.
"""

import pytest

from vardrrunner import errors


class TestFailureCategoryValues:
    @pytest.mark.parametrize(
        "member,value",
        [
            (errors.FailureCategory.STOP_WORK, "stop_work"),
            (errors.FailureCategory.CLAIM_RACE, "claim_race"),
            (errors.FailureCategory.AUTH, "auth"),
            (errors.FailureCategory.NOT_FOUND, "not_found"),
            (errors.FailureCategory.RATE_LIMITED, "rate_limited"),
            (errors.FailureCategory.BACKEND_UNAVAILABLE, "backend_unavailable"),
            (errors.FailureCategory.UNKNOWN, "unknown"),
        ],
    )
    def test_stable_wire_values(self, member, value):
        assert member.value == value


class TestClassifyStatus:
    @pytest.mark.parametrize(
        "status,expected",
        [
            (401, errors.AuthError),
            (403, errors.StopWorkError),
            (404, errors.NotFoundError),
            (409, errors.ClaimRace),
            (422, errors.InvalidRequestError),
            (429, errors.RateLimited),
            (500, errors.BackendUnavailable),
            (502, errors.BackendUnavailable),
            (503, errors.BackendUnavailable),
            (418, errors.InvalidRequestError),
        ],
    )
    def test_status_maps_to_domain_error(self, status, expected):
        assert isinstance(errors.classify_status(status), expected)

    def test_every_classified_error_is_a_runner_error(self):
        for status in (401, 403, 404, 409, 422, 429, 500, 418):
            assert isinstance(errors.classify_status(status), errors.RunnerError)

    def test_403_is_stop_work_not_generic_forbidden(self):
        """VardrMap reserves 403 for the halt switch and answers other denials
        with 404, so 403 must never be reported as a plain permission error."""
        e = errors.classify_status(403)
        assert e.category is errors.FailureCategory.STOP_WORK

    def test_extracts_backend_reason_and_message(self):
        e = errors.classify_status(
            403,
            {
                "detail": {
                    "error": "stop_work_active",
                    "reason": "stop_work_active",
                    "message": "Halted by the engagement lead",
                }
            },
        )
        assert e.reason == "stop_work_active"
        assert "Halted by the engagement lead" in str(e)

    def test_falls_back_to_default_message_without_a_body(self):
        assert str(errors.classify_status(409))

    def test_string_detail_becomes_the_message(self):
        assert "nope" in str(errors.classify_status(422, {"detail": "nope"}))

    @pytest.mark.parametrize(
        "body",
        [
            None,
            "",
            0,
            [],
            ["x"],
            {"detail": None},
            {"detail": []},
            {"detail": {"reason": 5, "message": {}}},
            {"unexpected": True},
        ],
    )
    def test_malformed_bodies_never_raise(self, body):
        """Error bodies are untrusted remote data; parsing one must not add a
        second failure on top of the one being reported."""
        e = errors.classify_status(500, body)
        assert isinstance(e, errors.RunnerError)
        assert isinstance(e.reason, str)


class TestExceptionShape:
    def test_category_defaults_to_unknown(self):
        assert errors.RunnerError("x").category is errors.FailureCategory.UNKNOWN

    def test_message_and_reason_are_preserved(self):
        e = errors.StopWorkError("halted", reason="stop_work_active")
        assert e.message == "halted" and e.reason == "stop_work_active"

    def test_chaining_preserves_the_cause(self):
        try:
            try:
                raise ValueError("underlying")
            except ValueError as cause:
                raise errors.classify_status(500) from cause
        except errors.RunnerError as e:
            assert isinstance(e.__cause__, ValueError)
