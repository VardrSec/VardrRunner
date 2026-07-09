"""
Tool handlers — one per job type.

Each handler knows four things about its tool: how to validate its config, how to
resolve its targets, how to execute it, and how to upload the result. The uniform
job lifecycle (availability check → claim → events → done/fail) lives in
``commands/jobs.py`` and drives these handlers, so every tool gets identical
claim/event/failure handling and the executor stays small.

Adding a tool is a one-file change: write a handler and register it below.
"""

import copy
import json
import logging
import os
from pathlib import Path
from typing import Any, Generic, TypeVar

from vardrrunner import api, configs, keychain, runner
from vardrrunner.targets import _is_wildcard, _resolve_targets


def _extract_jsonl_field(output: Path, *fields: str) -> list[str]:
    """Read a JSONL file and return the first non-empty value from the given fields.

    Skips blank lines and lines that aren't valid JSON. Returns [] on OSError.
    Accepts multiple field names; the first non-empty value wins (e.g. "url" then "host").
    """
    targets: list[str] = []
    try:
        for line in output.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            for field in fields:
                val = obj.get(field)
                if val:
                    targets.append(val)
                    break
    except OSError as e:
        logging.warning("Failed to read tool output %s: %s", output, e)
    return targets


def _write_host_import_jsonl(hosts: list[str], source: str, path: Path) -> None:
    """Write a list of hostnames to a JSONL file in httpx-import format."""
    with path.open("w") as fh:
        for host in hosts:
            fh.write(json.dumps({"host": host, "source": source}) + "\n")


C = TypeVar("C")


class ToolHandler(Generic[C]):
    """Base class for a tool handler. ``tool`` is the executable name on PATH."""

    tool: str = ""

    def parse_config(self, cfg: dict) -> C:
        raise NotImplementedError

    def resolve_targets(
        self, client: api.VardrMapClient, program_id: str, target_source: str, config: C
    ) -> list[str]:
        raise NotImplementedError

    def running_label(self, targets: list[str], config: C) -> str:
        return f"{self.tool} against {len(targets)} target(s)"

    def execute(self, targets: list[str], run_dir: Path, config: C) -> Path | None:
        """Run the tool. Return the artifact to upload, or None if nothing was produced."""
        raise NotImplementedError

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        """Push the artifact to the backend. Return a one-line human summary."""
        raise NotImplementedError

    def extract_handoff_targets(self, output: Path) -> list[str]:
        """Extract targets from this stage's output to pass to the next pipeline stage.

        Returns [] for terminal stages (nuclei, nmap, naabu) or unparseable output.
        A non-empty return causes the pipeline to write a local handoff file so the
        next stage reads from it instead of the shared backend recon store.
        """
        return []

    def normalize_handoff_targets(self, targets: list[str]) -> list[str]:
        """Normalize targets read from a handoff file before passing to execute().

        Default is identity. Override for tools that need bare host/IP input (nmap,
        dnsx, naabu) to strip URL scheme/path the way their resolve_targets() does.
        """
        return targets


def _resolve_standard(
    client: api.VardrMapClient, program_id: str, target_source: str, config: Any
) -> list[str]:
    """Scope/recon target resolution shared by httpx, nuclei, and nmap."""
    return _resolve_targets(
        client,
        program_id,
        scope=(target_source == "scope"),
        from_recon=(target_source == "recon"),
        target=None,
        targets_file=None,
        status_code=getattr(config, "status_code", None),
        limit=config.limit,
    )


class HttpxHandler(ToolHandler[configs.HttpxConfig]):
    tool = "httpx"

    def parse_config(self, cfg: dict) -> configs.HttpxConfig:
        return configs.HttpxConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        program_id: str,
        target_source: str,
        config: configs.HttpxConfig,
    ) -> list[str]:
        return _resolve_standard(client, program_id, target_source, config)

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.HttpxConfig
    ) -> Path | None:
        output = run_dir / "httpx.jsonl"
        runner.run_httpx(targets, output, timeout=config.timeout)
        return output

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(program_id, "httpx", str(output))
        count = result.get("import_record", {}).get("imported_count", "?")
        return f"imported {count} result(s)"

    def extract_handoff_targets(self, output: Path) -> list[str]:
        return _extract_jsonl_field(output, "url", "host")


class NucleiHandler(ToolHandler[configs.NucleiConfig]):
    tool = "nuclei"

    def parse_config(self, cfg: dict) -> configs.NucleiConfig:
        return configs.NucleiConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        program_id: str,
        target_source: str,
        config: configs.NucleiConfig,
    ) -> list[str]:
        return _resolve_standard(client, program_id, target_source, config)

    def running_label(self, targets: list[str], config: configs.NucleiConfig) -> str:
        label = f"severity={config.severity}" if config.severity else "all"
        return f"nuclei ({label}) against {len(targets)} target(s)"

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.NucleiConfig
    ) -> Path | None:
        output = run_dir / "nuclei.jsonl"
        runner.run_nuclei(
            targets,
            output,
            severity=config.severity,
            templates=config.templates,
            timeout=config.timeout,
        )
        return output

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(program_id, "nuclei", str(output))
        count = result.get("import_record", {}).get("imported_count", "?")
        return f"imported {count} finding(s)"


class NmapHandler(ToolHandler[configs.NmapConfig]):
    tool = "nmap"

    def parse_config(self, cfg: dict) -> configs.NmapConfig:
        return configs.NmapConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        program_id: str,
        target_source: str,
        config: configs.NmapConfig,
    ) -> list[str]:
        raw = _resolve_standard(client, program_id, target_source, config)
        # nmap needs bare hosts, not full URLs; normalize and de-duplicate.
        return list(dict.fromkeys(runner.strip_url_to_host(t) for t in raw if t.strip()))

    def running_label(self, targets: list[str], config: configs.NmapConfig) -> str:
        return f"nmap --top-ports {config.top_ports} against {len(targets)} target(s)"

    def normalize_handoff_targets(self, targets: list[str]) -> list[str]:
        return list(dict.fromkeys(runner.strip_url_to_host(t) for t in targets if t.strip()))

    def execute(self, targets: list[str], run_dir: Path, config: configs.NmapConfig) -> Path | None:
        xml_path = run_dir / "nmap.xml"
        runner.run_nmap(
            targets,
            xml_path,
            top_ports=config.top_ports,
            timing=config.timing,
            timeout=config.timeout,
        )
        return xml_path

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        services = runner.parse_nmap_xml(output)
        if not services:
            return "no open ports found"
        result = client.create_services(program_id, services)
        created = result.get("created", 0)
        updated = result.get("updated", 0)
        return f"{created} new, {updated} updated service(s)"


class SubfinderHandler(ToolHandler[configs.SubfinderConfig]):
    tool = "subfinder"

    def parse_config(self, cfg: dict) -> configs.SubfinderConfig:
        return configs.SubfinderConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        program_id: str,
        target_source: str,
        config: configs.SubfinderConfig,
    ) -> list[str]:
        # subfinder enumerates wildcard scope entries (*.example.com → example.com),
        # regardless of target_source.
        raw = client.scope(program_id)
        domains = []
        for item in raw.get("in", []):
            val = item.get("value", "")
            if _is_wildcard(val):
                stripped = val.lstrip("*").lstrip(".")
                if stripped:
                    domains.append(stripped)
        return domains

    def running_label(self, targets: list[str], config: configs.SubfinderConfig) -> str:
        return f"subfinder on {len(targets)} domain(s)"

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.SubfinderConfig
    ) -> Path | None:
        sf_output = run_dir / "subfinder.txt"

        runner.run_subfinder(targets, sf_output, timeout=config.timeout)
        if not sf_output.exists() or sf_output.stat().st_size == 0:
            return None
        hosts = [line.strip() for line in sf_output.read_text().splitlines() if line.strip()]
        if not hosts:
            return None
        # Convert discovered hosts into httpx-compatible JSONL for the import endpoint.
        jsonl_path = run_dir / "subfinder_httpx.jsonl"
        _write_host_import_jsonl(hosts, "subfinder", jsonl_path)
        return jsonl_path

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(program_id, "httpx", str(output))
        count = result.get("import_record", {}).get("imported_count", "?")
        return f"imported {count} subdomain(s) as recon targets"

    def extract_handoff_targets(self, output: Path) -> list[str]:
        return _extract_jsonl_field(output, "host")


class DnsxHandler(ToolHandler[configs.DnsxConfig]):
    tool = "dnsx"

    def parse_config(self, cfg: dict) -> configs.DnsxConfig:
        return configs.DnsxConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        program_id: str,
        target_source: str,
        config: configs.DnsxConfig,
    ) -> list[str]:
        raw = _resolve_standard(client, program_id, target_source, config)
        # dnsx resolves bare hostnames, not URLs.
        return list(dict.fromkeys(runner.strip_url_to_host(t) for t in raw if t.strip()))

    def running_label(self, targets: list[str], config: configs.DnsxConfig) -> str:
        return f"dnsx on {len(targets)} host(s)"

    def normalize_handoff_targets(self, targets: list[str]) -> list[str]:
        return list(dict.fromkeys(runner.strip_url_to_host(t) for t in targets if t.strip()))

    def execute(self, targets: list[str], run_dir: Path, config: configs.DnsxConfig) -> Path | None:
        out = run_dir / "dnsx.txt"
        runner.run_dnsx(targets, out, timeout=config.timeout)
        if not out.exists() or out.stat().st_size == 0:
            return None
        hosts = [line.strip() for line in out.read_text().splitlines() if line.strip()]
        if not hosts:
            return None
        # Resolvable hosts become recon targets (httpx-compatible JSONL).
        jsonl_path = run_dir / "dnsx_httpx.jsonl"
        _write_host_import_jsonl(hosts, "dnsx", jsonl_path)
        return jsonl_path

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(program_id, "httpx", str(output))
        count = result.get("import_record", {}).get("imported_count", "?")
        return f"imported {count} resolvable host(s)"

    def extract_handoff_targets(self, output: Path) -> list[str]:
        return _extract_jsonl_field(output, "host")


class NaabuHandler(ToolHandler[configs.NaabuConfig]):
    tool = "naabu"

    def parse_config(self, cfg: dict) -> configs.NaabuConfig:
        return configs.NaabuConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        program_id: str,
        target_source: str,
        config: configs.NaabuConfig,
    ) -> list[str]:
        raw = _resolve_standard(client, program_id, target_source, config)
        return list(dict.fromkeys(runner.strip_url_to_host(t) for t in raw if t.strip()))

    def running_label(self, targets: list[str], config: configs.NaabuConfig) -> str:
        return f"naabu --top-ports {config.top_ports} on {len(targets)} host(s)"

    def normalize_handoff_targets(self, targets: list[str]) -> list[str]:
        return list(dict.fromkeys(runner.strip_url_to_host(t) for t in targets if t.strip()))

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.NaabuConfig
    ) -> Path | None:
        out = run_dir / "naabu.json"
        runner.run_naabu(targets, out, top_ports=config.top_ports, timeout=config.timeout)
        return out

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        services = runner.parse_naabu_json(output)
        if not services:
            return "no open ports found"
        result = client.create_services(program_id, services)
        created = result.get("created", 0)
        updated = result.get("updated", 0)
        return f"{created} new, {updated} updated service(s)"


def _resolve_identity_secrets(test_case: dict) -> dict:
    """Return a copy of ``test_case`` with each identity credential's value
    resolved from a local source, so real secrets never travel through — or
    persist in — the backend.

    A credential may specify at most one of:
      - ``value`` — a literal (used as-is; convenient for local runs)
      - ``value_env`` — an environment variable name, read on this machine
      - ``value_keychain`` — an account looked up in the OS keychain

    A referenced-but-missing secret raises ``ConfigError`` so the job fails
    instead of silently running with a blank credential.
    """
    resolved = copy.deepcopy(test_case)
    identities = resolved.get("identities")
    if isinstance(identities, list):
        for idx, identity in enumerate(identities):
            cred = identity.get("credential") if isinstance(identity, dict) else None
            if isinstance(cred, dict):
                _resolve_one_credential(cred, str(identity.get("id", f"#{idx}")))
    return resolved


def _resolve_one_credential(cred: dict, identity_id: str) -> None:
    provided = [k for k in ("value", "value_env", "value_keychain") if cred.get(k)]
    if len(provided) > 1:
        raise configs.ConfigError(
            f"identity {identity_id!r}: credential must specify only one of "
            "value, value_env, value_keychain"
        )
    env_name = cred.pop("value_env", None)
    kc_account = cred.pop("value_keychain", None)
    if env_name:
        value = os.environ.get(str(env_name))
        if not value:
            raise configs.ConfigError(
                f"identity {identity_id!r}: environment variable {env_name!r} is not set"
            )
        cred["value"] = value
    elif kc_account:
        value = keychain.get_secret(str(kc_account))
        if not value:
            raise configs.ConfigError(
                f"identity {identity_id!r}: no keychain secret for account {kc_account!r}"
            )
        cred["value"] = value
    # Otherwise: a literal value or an anonymous credential — left untouched.


class VardrGateHandler(ToolHandler[configs.VardrGateConfig]):
    """Run a VardrGate API authorization test job and upload its result.

    This handler differs from the recon handlers: the job is self-contained, so
    there are no scope/recon targets to resolve, and the result is attached to
    the job itself (``POST /jobs/{id}/upload``) rather than imported to a program.
    The runner never imports VardrGate internals — it shells out to the binary
    and uploads the sanitized JSON result.
    """

    tool = "vardrgate_api_test"

    def parse_config(self, cfg: dict) -> configs.VardrGateConfig:
        return configs.VardrGateConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        program_id: str,
        target_source: str,
        config: configs.VardrGateConfig,
    ) -> list[str]:
        # The endpoint under test travels inside the test case; surface it as the
        # single "target" so the lifecycle proceeds and operators see what runs.
        request = config.test_case.get("request") or {}
        url = request.get("url")
        if url:
            return [str(url)]
        return [str(config.test_case.get("id", "vardrgate-job"))]

    def running_label(self, targets: list[str], config: configs.VardrGateConfig) -> str:
        return f"vardrgate authorization test against {targets[0] if targets else 'target'}"

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.VardrGateConfig
    ) -> Path | None:
        output = run_dir / "vardrgate_result.json"
        # Resolve credential references to real values locally, keeping secrets
        # out of the backend. Raises ConfigError if a referenced secret is missing.
        test_case = _resolve_identity_secrets(config.test_case)
        job = {"config": {"test_case": test_case, "execution": config.execution}}
        timeout = config.execution.get("timeout_seconds")
        runner.run_vardrgate(job, output, timeout=timeout if isinstance(timeout, int) else None)
        return output

    def upload(
        self, client: api.VardrMapClient, program_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = json.loads(output.read_text())
        if job_id:
            client.post(f"/jobs/{job_id}/upload", json=result)
        findings = result.get("findings") or []
        return f"{len(findings)} finding(s)"


# Registry: job type → handler. Add a tool by adding a handler here.
REGISTRY: dict[str, ToolHandler[Any]] = {
    h.tool: h
    for h in (
        HttpxHandler(),
        NucleiHandler(),
        NmapHandler(),
        SubfinderHandler(),
        DnsxHandler(),
        NaabuHandler(),
        VardrGateHandler(),
    )
}
