"""Target classification, advisory findings, and local deny rules.

The invariant under test is the one that is easiest to break by accident:
classification produces **warnings**, and warnings never stop a job. Only a deny
rule the operator configured blocks, and only until they override it.
"""

import os
from unittest.mock import patch

import pytest
import typer
from rich.console import Console

from vardrrunner import target_safety as ts
from vardrrunner import targets as targets_module


class TestClassification:
    @pytest.mark.parametrize(
        "target",
        [
            "169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254:80/",
            "169.254.169.253",
            "169.254.170.2",
            "100.100.100.200",
            "192.0.0.192",
            "fd00:ec2::254",
            "[fd00:ec2::254]",
            "metadata.google.internal",
            "metadata",
            "instance-data",
        ],
    )
    def test_cloud_metadata_is_detected(self, target):
        """The case this module exists for: instance metadata answers from inside
        almost every cloud network, with credentials attached."""
        assert ts.classify(target) is ts.TargetClass.CLOUD_METADATA

    @pytest.mark.parametrize(
        "target", ["127.0.0.1", "127.1.2.3", "::1", "localhost", "http://localhost:8080"]
    )
    def test_loopback(self, target):
        assert ts.classify(target) is ts.TargetClass.LOOPBACK

    @pytest.mark.parametrize("target", ["169.254.10.5", "fe80::1"])
    def test_link_local(self, target):
        assert ts.classify(target) is ts.TargetClass.LINK_LOCAL

    @pytest.mark.parametrize("target", ["10.0.0.5", "192.168.1.1", "172.16.0.1"])
    def test_private(self, target):
        assert ts.classify(target) is ts.TargetClass.PRIVATE

    @pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1"])
    def test_public(self, target):
        assert ts.classify(target) is ts.TargetClass.PUBLIC

    @pytest.mark.parametrize("target", ["example.com", "app.test.co.uk", "https://a.example.com/x"])
    def test_hostname_is_not_guessed_at(self, target):
        """Classification is lexical — a name is never resolved, so it stays a name."""
        assert ts.classify(target) is ts.TargetClass.HOSTNAME

    def test_metadata_beats_the_generic_link_local_rule(self):
        """169.254.169.254 is link-local too; the more specific finding must win."""
        assert ts.classify("169.254.169.254") is ts.TargetClass.CLOUD_METADATA

    @pytest.mark.parametrize("target", ["", "   ", "://", "not a url", "]["])
    def test_malformed_input_never_raises(self, target):
        assert isinstance(ts.classify(target), ts.TargetClass)


class TestAssessIsAdvisory:
    def test_flags_metadata_loopback_and_link_local(self):
        findings = ts.assess(["169.254.169.254", "127.0.0.1", "169.254.10.5"])
        assert {f.target_class for f in findings} == {
            ts.TargetClass.CLOUD_METADATA,
            ts.TargetClass.LOOPBACK,
            ts.TargetClass.LINK_LOCAL,
        }

    def test_private_is_classified_but_not_warned(self):
        """Internal ranges are routine on an internal engagement; warning on them
        would train operators to ignore the output."""
        assert ts.assess(["10.0.0.5", "192.168.1.1"]) == ()

    def test_public_and_hostnames_are_quiet(self):
        assert ts.assess(["8.8.8.8", "example.com"]) == ()

    def test_assess_returns_findings_not_a_verdict(self):
        """There is no 'blocked' outcome here at all — by design."""
        findings = ts.assess(["169.254.169.254"])
        assert all(hasattr(f, "message") for f in findings)
        assert not any(hasattr(f, "blocked") for f in findings)


class TestDenyRules:
    def test_nothing_is_denied_by_default(self):
        """The critical default: an operator who configured nothing is blocked by nothing."""
        allowed, denied = ts.apply_deny_rules(["169.254.169.254", "127.0.0.1"], ())
        assert denied == () and len(allowed) == 2

    def test_class_rule_blocks_that_class_only(self):
        allowed, denied = ts.apply_deny_rules(
            ["169.254.169.254", "example.com"], ("cloud_metadata",)
        )
        assert allowed == ["example.com"]
        assert [f.target for f in denied] == ["169.254.169.254"]

    def test_literal_host_rule(self):
        allowed, denied = ts.apply_deny_rules(
            ["a.example.com", "b.example.com"], ("a.example.com",)
        )
        assert allowed == ["b.example.com"]

    def test_cidr_rule(self):
        allowed, denied = ts.apply_deny_rules(["10.0.0.5", "8.8.8.8"], ("10.0.0.0/8",))
        assert allowed == ["8.8.8.8"]
        assert len(denied) == 1

    def test_rule_matches_host_inside_a_url(self):
        _, denied = ts.apply_deny_rules(["https://169.254.169.254/x"], ("cloud_metadata",))
        assert len(denied) == 1

    @pytest.mark.parametrize("rule", ["", "   ", "not-a-cidr/99", "999.999.999.999/8"])
    def test_unparseable_rules_match_nothing_rather_than_everything(self, rule):
        """Fail open on a malformed rule: silently blocking all work because of a
        typo in config is worse than the rule not applying."""
        allowed, denied = ts.apply_deny_rules(["8.8.8.8"], (rule,))
        assert allowed == ["8.8.8.8"] and denied == ()

    def test_denied_finding_names_the_rule(self):
        _, denied = ts.apply_deny_rules(["127.0.0.1"], ("loopback",))
        assert "loopback" in denied[0].message


class TestDenyRuleLoading:
    def test_empty_by_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ts.ENV_DENY, None)
            with patch("vardrrunner.target_safety.config.load", return_value={}):
                assert ts.load_deny_rules() == ()

    def test_env_var_is_comma_separated(self):
        with patch.dict(os.environ, {ts.ENV_DENY: "cloud_metadata, loopback"}):
            assert ts.load_deny_rules() == ("cloud_metadata", "loopback")

    def test_config_list(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ts.ENV_DENY, None)
            with patch(
                "vardrrunner.target_safety.config.load",
                return_value={ts.CONFIG_DENY_KEY: ["loopback", "10.0.0.0/8"]},
            ):
                assert ts.load_deny_rules() == ("loopback", "10.0.0.0/8")

    def test_corrupt_config_yields_no_rules_rather_than_raising(self):
        from vardrrunner import config as config_mod

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ts.ENV_DENY, None)
            with patch(
                "vardrrunner.target_safety.config.load",
                side_effect=config_mod.InvalidConfigFile("bad"),
            ):
                assert ts.load_deny_rules() == ()

    @pytest.mark.parametrize(
        "value,expected",
        [("1", True), ("true", True), ("yes", True), ("0", False), ("", False), ("maybe", False)],
    )
    def test_override_flag_parsing(self, value, expected):
        with patch.dict(os.environ, {ts.ENV_ALLOW_DENIED: value}):
            assert ts.override_enabled() is expected


class TestStats:
    def test_counts_duplicates_and_blanks(self):
        s = ts.summarize(["a.com", "a.com", "", "b.com"], ["a.com", "b.com"])
        assert s.received == 4 and s.accepted == 2
        assert s.duplicates_removed == 1 and s.blank_skipped == 1

    def test_class_breakdown(self):
        s = ts.summarize(["8.8.8.8", "10.0.0.1"], ["8.8.8.8", "10.0.0.1"])
        assert s.by_class == {"public": 1, "private": 1}

    def test_summary_contains_no_target_values(self):
        """Stats go into the audit trail, so they must be safe to record."""
        s = ts.summarize(["secret.internal.example"], ["secret.internal.example"])
        assert "secret.internal.example" not in s.summary()


class TestScreeningIntegration:
    """`screen_targets` is the chokepoint every `run`/`pipeline` path goes through."""

    def _screen(self, targets, env=None):
        con = Console(record=True, width=200)
        with patch.dict(os.environ, env or {}, clear=False):
            if not env or ts.ENV_DENY not in env:
                os.environ.pop(ts.ENV_DENY, None)
            if not env or ts.ENV_ALLOW_DENIED not in env:
                os.environ.pop(ts.ENV_ALLOW_DENIED, None)
            with patch("vardrrunner.targets.console", con):
                result = targets_module.screen_targets(targets)
        return result, con.export_text()

    def test_warning_does_not_block(self):
        """The whole invariant in one test: a flagged target still runs."""
        result, out = self._screen(["169.254.169.254"])
        assert result == ["169.254.169.254"]
        assert "metadata" in out

    def test_clean_targets_produce_no_noise(self):
        result, out = self._screen(["example.com"])
        assert result == ["example.com"] and "⚠" not in out

    def test_configured_deny_rule_blocks(self):
        result, out = self._screen(
            ["169.254.169.254", "example.com"], {ts.ENV_DENY: "cloud_metadata"}
        )
        assert result == ["example.com"]
        assert "blocked" in out

    def test_override_restores_denied_targets(self):
        result, out = self._screen(
            ["169.254.169.254"],
            {ts.ENV_DENY: "cloud_metadata", ts.ENV_ALLOW_DENIED: "1"},
        )
        assert result == ["169.254.169.254"]
        assert "override" in out

    def test_all_targets_denied_exits_rather_than_running_nothing(self):
        with pytest.raises(typer.Exit):
            self._screen(["169.254.169.254"], {ts.ENV_DENY: "cloud_metadata"})

    def test_block_message_names_the_override(self):
        _, out = self._screen(["169.254.169.254", "example.com"], {ts.ENV_DENY: "cloud_metadata"})
        assert ts.ENV_ALLOW_DENIED in out


class TestJobPathIntegration:
    """The unattended path — where deny rules matter most, because there is no
    operator watching and no command line to put a flag on."""

    JOB = {
        "id": "job-1",
        "engagement_id": "eng-1",
        "tool_type": "httpx",
        "target_source": "scope",
        "config": {},
    }

    def _run(self, tmp_path, resolved, env=None):
        from unittest.mock import MagicMock

        from vardrrunner.commands import jobs as jobs_cmd

        client = MagicMock()
        client.pending_jobs.return_value = [dict(self.JOB)]
        client.claim_job.return_value = {}
        con = Console(record=True, width=220)

        env = env or {}
        with patch.dict(os.environ, env, clear=False):
            for var in (ts.ENV_DENY, ts.ENV_ALLOW_DENIED):
                if var not in env:
                    os.environ.pop(var, None)
            with (
                patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
                patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
                patch("vardrrunner.commands.jobs.handlers.REGISTRY") as reg,
            ):
                handler = reg.get.return_value
                handler.tool = "httpx"
                handler.resolve_targets.return_value = resolved
                handler.execute.return_value = None
                jobs_cmd.execute_pending_jobs(client, con, yes=True)
        events = [c.args[1] for c in client.post_event.call_args_list]
        return con.export_text(), events, client, reg.get.return_value

    def _run_real_scope(self, tmp_path, resolved, env=None):
        """Exercise the real handler/resolver boundary, not a mocked handler."""
        from unittest.mock import MagicMock

        from vardrrunner.commands import jobs as jobs_cmd

        client = MagicMock()
        client.pending_jobs.return_value = [dict(self.JOB)]
        client.scope.return_value = {
            "in": [{"value": target, "kind": "url"} for target in resolved],
            "out": [],
        }
        client.claim_job.return_value = {}
        con = Console(record=True, width=220)
        env = env or {}
        with patch.dict(os.environ, env, clear=False):
            for var in (ts.ENV_DENY, ts.ENV_ALLOW_DENIED):
                if var not in env:
                    os.environ.pop(var, None)
            with (
                patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
                patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
                patch("vardrrunner.runner.run_httpx") as run_httpx,
            ):
                jobs_cmd.execute_pending_jobs(client, con, yes=True)
        events = [(call.args[1], call.args[2]) for call in client.post_event.call_args_list]
        return con.export_text(), events, client, run_httpx

    def test_metadata_target_warns_but_still_runs(self, tmp_path):
        """A warning is not a veto — the tool must still execute."""
        out, events, client, handler = self._run(tmp_path, ["http://169.254.169.254/"])
        assert "target_warning" in events
        handler.execute.assert_called_once()
        client.complete_job.assert_called_with("job-1", "done")

    def test_stats_are_emitted_for_the_audit_trail(self, tmp_path):
        _, events, _, _ = self._run(tmp_path, ["https://a.example.com"])
        assert "target_stats" in events

    def test_configured_deny_rule_blocks_the_job(self, tmp_path):
        out, events, client, handler = self._run(
            tmp_path, ["http://169.254.169.254/"], {ts.ENV_DENY: "cloud_metadata"}
        )
        assert "target_blocked" in events
        handler.execute.assert_not_called()
        assert client.complete_job.call_args[0][1] == "failed"

    def test_partial_deny_continues_with_the_survivors(self, tmp_path):
        out, events, _, handler = self._run(
            tmp_path,
            ["http://169.254.169.254/", "https://a.example.com"],
            {ts.ENV_DENY: "cloud_metadata"},
        )
        handler.execute.assert_called_once()
        assert handler.execute.call_args[0][0] == ["https://a.example.com"]

    def test_override_is_audited_as_an_event(self, tmp_path):
        """An override that leaves no trace is not auditable."""
        _, events, _, handler = self._run(
            tmp_path,
            ["http://169.254.169.254/"],
            {ts.ENV_DENY: "cloud_metadata", ts.ENV_ALLOW_DENIED: "1"},
        )
        assert "deny_override" in events
        handler.execute.assert_called_once()

    def test_no_rules_means_no_blocking_events(self, tmp_path):
        _, events, _, handler = self._run(tmp_path, ["https://a.example.com"])
        assert "target_blocked" not in events and "deny_override" not in events
        handler.execute.assert_called_once()

    def test_real_resolver_screens_warning_once_and_escapes_markup(self, tmp_path):
        target = "http://169.254.169.254/[red]hidden[/red]"
        output, events, _, run_httpx = self._run_real_scope(tmp_path, [target])
        assert output.count("cloud instance-metadata endpoint") == 1
        assert "[red]hidden[/red]" in output
        assert [kind for kind, _ in events].count("target_warning") == 1
        run_httpx.assert_called_once()

    def test_real_resolver_preserves_block_and_input_statistics(self, tmp_path):
        output, events, _, run_httpx = self._run_real_scope(
            tmp_path,
            ["http://169.254.169.254/", "https://a.example.com", "https://a.example.com", ""],
            {ts.ENV_DENY: "cloud_metadata"},
        )
        event_map = {kind: text for kind, text in events}
        assert "target_blocked" in event_map
        assert "1 duplicate(s) removed" in event_map["target_stats"]
        assert "1 blank line(s) skipped" in event_map["target_stats"]
        assert "blocked" in output
        assert run_httpx.call_args.args[0] == ["https://a.example.com"]
