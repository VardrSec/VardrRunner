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

from vardrrunner import api, configs, keychain, redaction, runner
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
        logging.warning(
            "Failed to read tool output %s: %s",
            redaction.redact_text(str(output)),
            redaction.redact_exception(e),
        )
    return targets


def _write_host_import_jsonl(hosts: list[str], source: str, path: Path) -> None:
    """Write a list of hostnames to a JSONL file in httpx-import format."""
    with path.open("w") as fh:
        for host in hosts:
            fh.write(json.dumps({"host": host, "source": source}) + "\n")


def _read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    """Every JSON object in a JSONL file; blank, malformed, and non-object lines are skipped."""
    if not path.exists():
        return []
    objects = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                objects.append(obj)
    return objects


def _write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")


def _wildcard_domains(client: api.VardrMapClient, engagement_id: str) -> list[str]:
    """Base domains of the engagement's wildcard scope entries (*.example.com → example.com)."""
    raw = client.scope(engagement_id)
    domains = []
    for item in raw.get("in", []):
        val = item.get("value", "")
        if _is_wildcard(val):
            stripped = val.lstrip("*").lstrip(".")
            if stripped:
                domains.append(stripped)
    return domains


# VardrMap refuses imports over 2 MiB by default (MAX_UPLOAD_BYTES). Large crawl and
# archive results are sent in pieces under that, leaving room for multipart overhead.
# The backend de-duplicates URL recon per engagement and source, within and across
# uploads, so splitting a result changes nothing about what ends up stored.
UPLOAD_CHUNK_BYTES = 1_500_000


def _upload_jsonl_in_chunks(
    client: api.VardrMapClient,
    engagement_id: str,
    tool: str,
    output: Path,
    max_bytes: int | None = None,
    job_id: str = "",
) -> int:
    """Upload a JSONL file in line-aligned pieces of at most ``max_bytes``; return the total.

    ``max_bytes`` defaults to ``UPLOAD_CHUNK_BYTES``, read at call time. A file that
    already fits is uploaded as-is. Piece files are always removed.
    """
    max_bytes = max_bytes or UPLOAD_CHUNK_BYTES

    def _count(result: dict) -> int:
        count = result.get("import_record", {}).get("imported_count", 0)
        return count if isinstance(count, int) else 0

    if output.stat().st_size <= max_bytes:
        return _count(
            client.import_file(
                engagement_id, tool, str(output), **({"job_id": job_id} if job_id else {})
            )
        )

    total = 0
    pieces: list[Path] = []
    try:
        chunk: list[bytes] = []
        size = 0
        with output.open("rb") as fh:
            lines = [line if line.endswith(b"\n") else line + b"\n" for line in fh if line.strip()]
        for line in lines + [b""]:
            if chunk and (not line or size + len(line) > max_bytes):
                piece = output.with_name(f"{output.stem}.part{len(pieces) + 1}.jsonl")
                piece.write_bytes(b"".join(chunk))
                pieces.append(piece)
                total += _count(
                    client.import_file(
                        engagement_id, tool, str(piece), **({"job_id": job_id} if job_id else {})
                    )
                )
                chunk, size = [], 0
            if line:
                chunk.append(line)
                size += len(line)
    finally:
        for piece in pieces:
            piece.unlink(missing_ok=True)
    return total


def _katana_record(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Reduce one katana result to the fields VardrMap imports.

    katana writes the full raw request and response, bodies included, on every
    line. Uploading that would be large and would carry page content the operator
    never asked to store, so only the endpoint and response metadata are kept.
    """
    raw_request, raw_response = obj.get("request"), obj.get("response")
    request: dict[str, Any] = raw_request if isinstance(raw_request, dict) else {}
    response: dict[str, Any] = raw_response if isinstance(raw_response, dict) else {}
    url = request.get("endpoint")
    if not isinstance(url, str) or not url:
        return None
    raw_headers = response.get("headers")
    headers: dict[str, Any] = raw_headers if isinstance(raw_headers, dict) else {}
    content_type = next(
        (v for k, v in headers.items() if isinstance(k, str) and k.lower() == "content-type"), None
    )
    status = response.get("status_code")
    length = response.get("content_length")
    return {
        "url": url,
        "method": str(request.get("method") or "GET"),
        "status_code": status if isinstance(status, int) else None,
        "content_length": length if isinstance(length, int) else None,
        "content_type": content_type if isinstance(content_type, str) else None,
        "source": "katana",
    }


C = TypeVar("C")


class ToolHandler(Generic[C]):
    """Base class for a tool handler. ``tool`` is the executable name on PATH."""

    tool: str = ""

    def parse_config(self, cfg: dict) -> C:
        raise NotImplementedError

    def resolve_targets(
        self, client: api.VardrMapClient, engagement_id: str, target_source: str, config: C
    ) -> list[str]:
        raise NotImplementedError

    def running_label(self, targets: list[str], config: C) -> str:
        return f"{self.tool} against {len(targets)} target(s)"

    def execute(self, targets: list[str], run_dir: Path, config: C) -> Path | None:
        """Run the tool. Return the artifact to upload, or None if nothing was produced."""
        raise NotImplementedError

    def upload(
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
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
    client: api.VardrMapClient, engagement_id: str, target_source: str, config: Any
) -> list[str]:
    """Scope/recon target resolution shared by httpx, nuclei, and nmap."""
    return _resolve_targets(
        client,
        engagement_id,
        scope=(target_source == "scope"),
        from_recon=(target_source == "recon"),
        target=None,
        targets_file=None,
        status_code=getattr(config, "status_code", None),
        limit=config.limit,
        apply_local_policy=False,
    )


class HttpxHandler(ToolHandler[configs.HttpxConfig]):
    tool = "httpx"

    def parse_config(self, cfg: dict) -> configs.HttpxConfig:
        return configs.HttpxConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        engagement_id: str,
        target_source: str,
        config: configs.HttpxConfig,
    ) -> list[str]:
        return _resolve_standard(client, engagement_id, target_source, config)

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.HttpxConfig
    ) -> Path | None:
        output = run_dir / "httpx.jsonl"
        runner.run_httpx(targets, output, timeout=config.timeout)
        return output

    def upload(
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(
            engagement_id, "httpx", str(output), **({"job_id": job_id} if job_id else {})
        )
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
        engagement_id: str,
        target_source: str,
        config: configs.NucleiConfig,
    ) -> list[str]:
        return _resolve_standard(client, engagement_id, target_source, config)

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
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(
            engagement_id, "nuclei", str(output), **({"job_id": job_id} if job_id else {})
        )
        count = result.get("import_record", {}).get("imported_count", "?")
        return f"imported {count} finding(s)"


class NmapHandler(ToolHandler[configs.NmapConfig]):
    tool = "nmap"

    def parse_config(self, cfg: dict) -> configs.NmapConfig:
        return configs.NmapConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        engagement_id: str,
        target_source: str,
        config: configs.NmapConfig,
    ) -> list[str]:
        raw = _resolve_standard(client, engagement_id, target_source, config)
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
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        services = runner.parse_nmap_xml(output)
        if not services:
            return "no open ports found"
        result = client.create_services(
            engagement_id, services, **({"job_id": job_id} if job_id else {})
        )
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
        engagement_id: str,
        target_source: str,
        config: configs.SubfinderConfig,
    ) -> list[str]:
        # subfinder enumerates wildcard scope entries (*.example.com → example.com),
        # regardless of target_source.
        return _wildcard_domains(client, engagement_id)

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
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(
            engagement_id, "httpx", str(output), **({"job_id": job_id} if job_id else {})
        )
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
        engagement_id: str,
        target_source: str,
        config: configs.DnsxConfig,
    ) -> list[str]:
        raw = _resolve_standard(client, engagement_id, target_source, config)
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
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(
            engagement_id, "httpx", str(output), **({"job_id": job_id} if job_id else {})
        )
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
        engagement_id: str,
        target_source: str,
        config: configs.NaabuConfig,
    ) -> list[str]:
        raw = _resolve_standard(client, engagement_id, target_source, config)
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
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        services = runner.parse_naabu_json(output)
        if not services:
            return "no open ports found"
        result = client.create_services(
            engagement_id, services, **({"job_id": job_id} if job_id else {})
        )
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


class KatanaHandler(ToolHandler[configs.KatanaConfig]):
    tool = "katana"

    def parse_config(self, cfg: dict) -> configs.KatanaConfig:
        return configs.KatanaConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        engagement_id: str,
        target_source: str,
        config: configs.KatanaConfig,
    ) -> list[str]:
        return _resolve_standard(client, engagement_id, target_source, config)

    def running_label(self, targets: list[str], config: configs.KatanaConfig) -> str:
        js = ", JavaScript parsing" if config.js_crawl else ""
        return f"katana crawl (depth {config.depth}{js}) of {len(targets)} target(s)"

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.KatanaConfig
    ) -> Path | None:
        raw_output = run_dir / "katana.jsonl"
        runner.run_katana(
            targets,
            raw_output,
            depth=config.depth,
            js_crawl=config.js_crawl,
            timeout=config.timeout,
        )
        seen: set[tuple[str, str]] = set()
        records = []
        for obj in _read_jsonl_objects(raw_output):
            record = _katana_record(obj)
            if record is None:
                continue
            key = (record["method"], record["url"])
            if key not in seen:
                seen.add(key)
                records.append(record)
        if not records:
            return None
        import_path = run_dir / "katana_import.jsonl"
        _write_jsonl(records, import_path)
        return import_path

    def upload(
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        count = _upload_jsonl_in_chunks(client, engagement_id, "katana", output, job_id=job_id)
        return f"imported {count} endpoint(s)"

    def extract_handoff_targets(self, output: Path) -> list[str]:
        return list(dict.fromkeys(_extract_jsonl_field(output, "url")))


class GauHandler(ToolHandler[configs.GauConfig]):
    tool = "gau"

    def parse_config(self, cfg: dict) -> configs.GauConfig:
        return configs.GauConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        engagement_id: str,
        target_source: str,
        config: configs.GauConfig,
    ) -> list[str]:
        # Like subfinder, gau works on domains: the wildcard scope entries.
        return _wildcard_domains(client, engagement_id)

    def running_label(self, targets: list[str], config: configs.GauConfig) -> str:
        providers = ", ".join(config.providers) if config.providers else "all providers"
        return f"gau archive lookup ({providers}) for {len(targets)} domain(s)"

    def execute(self, targets: list[str], run_dir: Path, config: configs.GauConfig) -> Path | None:
        raw_output = run_dir / "gau.jsonl"
        runner.run_gau(
            targets,
            raw_output,
            subs=config.subs,
            providers=config.providers,
            timeout=config.timeout,
        )
        urls = []
        for obj in _read_jsonl_objects(raw_output):
            url = obj.get("url")
            if isinstance(url, str) and url:
                urls.append(url)
        urls = list(dict.fromkeys(urls))
        if not urls:
            return None
        import_path = run_dir / "gau_import.jsonl"
        _write_jsonl([{"url": url, "source": "gau"} for url in urls], import_path)
        return import_path

    def upload(
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        count = _upload_jsonl_in_chunks(client, engagement_id, "gau", output, job_id=job_id)
        return f"imported {count} URL(s)"

    def extract_handoff_targets(self, output: Path) -> list[str]:
        return _extract_jsonl_field(output, "url")


class DalfoxHandler(ToolHandler[configs.DalfoxConfig]):
    """XSS scanning with dalfox, uploading candidates for a human to verify.

    The report is uploaded as dalfox wrote it, bar the one thing that must not
    travel: nothing here re-grades a match, renames a tier or decides what is
    confirmed. VardrMap's importer reads dalfox's own field names, and the
    verification signal (tier, detection method, confidence) is preserved end to
    end so the operator triages on what the scanner actually said.
    """

    tool = "dalfox"

    def parse_config(self, cfg: dict) -> configs.DalfoxConfig:
        return configs.DalfoxConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        engagement_id: str,
        target_source: str,
        config: configs.DalfoxConfig,
    ) -> list[str]:
        # dalfox needs URLs with parameters to fuzz, so recon URLs are the useful
        # source; scope entries work when they are concrete URLs.
        raw = _resolve_standard(client, engagement_id, target_source, config)
        return list(dict.fromkeys(t.strip() for t in raw if t.strip()))

    def running_label(self, targets: list[str], config: configs.DalfoxConfig) -> str:
        mining = "" if config.mining else ", no mining"
        return (
            f"dalfox XSS scan ({config.worker} workers/target, {config.delay}ms delay"
            f"{mining}) over {len(targets)} URL(s)"
        )

    def execute(
        self, targets: list[str], run_dir: Path, config: configs.DalfoxConfig
    ) -> Path | None:
        """Run dalfox and reconcile what the process said with what the report says.

        Four outcomes, and a report file existing decides none of them:

        - exit 0 + a readable report with no findings: a **valid empty result**.
        - exit 1 + a readable report with findings: **usable findings**.
        - exit 2 or any other code: an **execution failure** (``run_dalfox`` raises),
          whatever is on disk — a report left by a run that errored is not a result.
        - a report that is absent, unreadable or the wrong shape: **outcome unknown**,
          which is not the same as "no XSS found".

        The exit code and the report must also agree. Exit 1 with an empty report
        means dalfox claims to have found something that was never written down;
        exit 0 with findings means the report contradicts the process. Either way
        one of the two is wrong and there is no telling which, so the job fails
        rather than uploading a possibly-wrong answer or silently discarding it.
        """
        output = run_dir / "dalfox.json"
        code = runner.run_dalfox(
            targets,
            output,
            worker=config.worker,
            delay=config.delay,
            mining=config.mining,
            timeout=config.timeout,
        )
        findings = _read_dalfox_findings(output)
        if code == runner.DALFOX_EXIT_FINDINGS and not findings:
            raise runner.ToolError(
                "dalfox exited 1 (findings reported) but its report contains none, so what "
                "it found is unknown. The job fails rather than report a clean scan."
            )
        if code == runner.DALFOX_EXIT_CLEAN and findings:
            raise runner.ToolError(
                f"dalfox exited 0 (no findings) but its report contains {len(findings)}. "
                "The process and the report disagree, so neither can be trusted; the job "
                "fails rather than upload or discard them."
            )
        if code not in runner.DALFOX_OK_EXIT_CODES:
            raise runner.ToolError(f"dalfox returned unexpected exit code {code!r}")
        return output

    def upload(
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
    ) -> str:
        result = client.import_file(
            engagement_id, "dalfox", str(output), **({"job_id": job_id} if job_id else {})
        )
        record = result.get("import_record", {})
        count = record.get("imported_count", "?")
        # The backend dedupes dalfox, so the interesting number is what is new.
        # Say "candidate" rather than "finding": nothing here has been verified.
        incomplete = _dalfox_incomplete(output)
        suffix = " (dalfox reported the scan incomplete)" if incomplete else ""
        return f"imported {count} new XSS candidate(s){suffix}"


def _read_dalfox_findings(output: Path) -> list[dict[str, Any]]:
    """The finding objects in dalfox's report, or ToolError if the report is unusable.

    "No findings" and "could not read the report" must never look alike: a valid
    ``{"findings": []}`` is a clean scan, while an absent file, unreadable file,
    non-JSON, or JSON without a ``findings`` array means the outcome is unknown.
    A file merely existing is not evidence of anything — it may be empty,
    truncated, or left behind by a run that failed.
    """
    try:
        raw = output.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise runner.ToolError(
            f"dalfox left no readable report ({exc.__class__.__name__}), so the run's "
            "outcome is unknown. The job fails rather than report no findings."
        ) from exc
    try:
        report = json.loads(raw)
    except ValueError as exc:
        raise runner.ToolError(
            "dalfox's report is not valid JSON, so the run's outcome is unknown. The job "
            "fails rather than report no findings."
        ) from exc
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, list):
        raise runner.ToolError(
            "dalfox's report has no 'findings' array, so the run's outcome is unknown. "
            "The job fails rather than report no findings."
        )
    return [f for f in findings if isinstance(f, dict)]


def _dalfox_incomplete(output: Path) -> bool:
    """Whether dalfox flagged its own scan as incomplete, from the report's meta.

    Worth surfacing in the job summary: an incomplete scan that found nothing is
    not evidence that there is nothing to find, and the operator reading the job
    log is the person who needs to know that.
    """
    try:
        report = json.loads(output.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return False
    meta = report.get("meta") if isinstance(report, dict) else None
    return bool(meta.get("incomplete")) if isinstance(meta, dict) else False


class VardrGateHandler(ToolHandler[configs.VardrGateConfig]):
    """Run a VardrGate API authorization test job and upload its result.

    This handler differs from the recon handlers: the job is self-contained, so
    there are no scope/recon targets to resolve, and the result is attached to
    the job itself (``POST /jobs/{id}/upload``) rather than imported to an engagement.
    The runner never imports VardrGate internals — it shells out to the binary
    and uploads the sanitized JSON result.
    """

    tool = "vardrgate_api_test"

    def parse_config(self, cfg: dict) -> configs.VardrGateConfig:
        return configs.VardrGateConfig.from_dict(cfg)

    def resolve_targets(
        self,
        client: api.VardrMapClient,
        engagement_id: str,
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
        self, client: api.VardrMapClient, engagement_id: str, output: Path, job_id: str = ""
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
        KatanaHandler(),
        GauHandler(),
        DalfoxHandler(),
        VardrGateHandler(),
    )
}
