"""Tests for typed job configs — parsing, defaults, and validation."""

import pytest

from vardrrunner import configs
from vardrrunner.configs import ConfigError


def test_httpx_defaults():
    c = configs.HttpxConfig.from_dict({})
    assert (c.limit, c.status_code, c.timeout) == (100, None, None)


def test_httpx_parses_values():
    c = configs.HttpxConfig.from_dict({"limit": "50", "status_code": 200, "timeout": 60})
    assert (c.limit, c.status_code, c.timeout) == (50, 200, 60)


def test_limit_must_be_positive():
    with pytest.raises(ConfigError):
        configs.HttpxConfig.from_dict({"limit": 0})


def test_non_integer_rejected():
    with pytest.raises(ConfigError):
        configs.HttpxConfig.from_dict({"limit": "abc"})


def test_empty_string_treated_as_absent():
    c = configs.HttpxConfig.from_dict({"status_code": "", "timeout": ""})
    assert c.status_code is None and c.timeout is None


def test_timeout_must_be_positive():
    with pytest.raises(ConfigError):
        configs.HttpxConfig.from_dict({"timeout": 0})


# --- nuclei -------------------------------------------------------------------


def test_nuclei_severity_string_passthrough():
    assert configs.NucleiConfig.from_dict({"severity": "high,critical"}).severity == "high,critical"


def test_nuclei_severity_list_normalized():
    assert configs.NucleiConfig.from_dict({"severity": ["high", "low"]}).severity == "high,low"


def test_nuclei_invalid_severity_rejected():
    with pytest.raises(ConfigError):
        configs.NucleiConfig.from_dict({"severity": "bogus"})


def test_nuclei_templates_list_joined():
    assert (
        configs.NucleiConfig.from_dict({"templates": ["cves", "exposures"]}).templates
        == "cves,exposures"
    )


# --- nmap ---------------------------------------------------------------------


def test_nmap_defaults():
    c = configs.NmapConfig.from_dict({})
    assert (c.top_ports, c.timing, c.limit) == (100, 3, 500)


@pytest.mark.parametrize("timing", [-1, 5, 9])
def test_nmap_timing_range_enforced(timing):
    with pytest.raises(ConfigError):
        configs.NmapConfig.from_dict({"timing": timing})


@pytest.mark.parametrize("top_ports", [0, 70000])
def test_nmap_top_ports_bounds(top_ports):
    with pytest.raises(ConfigError):
        configs.NmapConfig.from_dict({"top_ports": top_ports})


# --- subfinder ----------------------------------------------------------------


def test_subfinder_timeout():
    assert configs.SubfinderConfig.from_dict({"timeout": 30}).timeout == 30
    assert configs.SubfinderConfig.from_dict({}).timeout is None


# --- dnsx / naabu -------------------------------------------------------------


def test_dnsx_defaults_and_validation():
    assert configs.DnsxConfig.from_dict({}).limit == 500
    with pytest.raises(ConfigError):
        configs.DnsxConfig.from_dict({"limit": 0})


def test_naabu_defaults():
    c = configs.NaabuConfig.from_dict({})
    assert (c.top_ports, c.limit) == (100, 500)


@pytest.mark.parametrize("top_ports", [0, 70000])
def test_naabu_top_ports_bounds(top_ports):
    with pytest.raises(ConfigError):
        configs.NaabuConfig.from_dict({"top_ports": top_ports})


# --- job envelope -------------------------------------------------------------


def test_job_envelope_valid():
    env = configs.JobEnvelope.from_dict(
        {
            "id": "job-1",
            "tool_type": "httpx",
            "target_source": "scope",
            "program_id": "prog-1",
            "config": {"limit": 5},
        }
    )
    assert env.id == "job-1" and env.tool_type == "httpx" and env.config == {"limit": 5}


def test_job_envelope_defaults_config_to_empty():
    env = configs.JobEnvelope.from_dict(
        {"id": "1", "tool_type": "httpx", "target_source": "scope", "program_id": "p"}
    )
    assert env.config == {}


@pytest.mark.parametrize(
    "job",
    [
        {"tool_type": "httpx", "target_source": "scope", "program_id": "p"},  # no id
        {"id": "1", "target_source": "scope", "program_id": "p"},  # no tool_type
        {"id": "1", "tool_type": "httpx", "program_id": "p"},  # no target_source
        {"id": "1", "tool_type": "httpx", "target_source": "scope"},  # no program_id
    ],
)
def test_job_envelope_missing_field_rejected(job):
    with pytest.raises(configs.ConfigError):
        configs.JobEnvelope.from_dict(job)


def test_vardrgate_config_parses():
    c = configs.VardrGateConfig.from_dict(
        {
            "test_case": {"id": "x", "request": {"url": "https://a/"}},
            "execution": {"timeout_seconds": 5},
            "policy_id": "pol_1",
        }
    )
    assert c.test_case["id"] == "x"
    assert c.execution == {"timeout_seconds": 5}
    assert c.policy_id == "pol_1"


def test_vardrgate_config_defaults_execution():
    c = configs.VardrGateConfig.from_dict({"test_case": {"id": "x"}})
    assert c.execution == {}
    assert c.policy_id is None


def test_vardrgate_config_requires_test_case():
    with pytest.raises(ConfigError):
        configs.VardrGateConfig.from_dict({"execution": {}})


def test_vardrgate_config_rejects_non_object_execution():
    with pytest.raises(ConfigError):
        configs.VardrGateConfig.from_dict({"test_case": {"id": "x"}, "execution": "nope"})
