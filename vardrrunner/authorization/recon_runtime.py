"""One explicitly signed finite DNS/HTTP journey through Runner's existing launcher."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from vardrrunner import (
    config,
    execution_control,
    launch_guard,
    manifests,
    resources,
    runner,
    toolchain,
)

from .codec import digest, encoded, require
from .contracts import ValidationContext, approved, timestamp
from .ledger import AuthorizationLedger
from .recon_plan import RUNTIME_PROFILE, select_runtime_candidates

_VERSIONS = {"dnsx": "1.3.1", "httpx": "1.12.0"}
_MODULES = {
    "dnsx": {"github.com/projectdiscovery/retryabledns": "v1.0.116"},
    "httpx": {
        "github.com/projectdiscovery/fastdialer": "v0.5.19",
        "github.com/projectdiscovery/retryablehttp-go": "v1.3.25",
    },
}


def qualified_tools() -> tuple[dict[str, Path], dict[str, str]]:
    """Recheck managed bytes; arbitrary PATH binaries cannot enable this profile."""
    paths, hashes = {}, {}
    receipt = toolchain._read_lock()
    manifest = toolchain.load_manifest()["tools"]
    for name, version in _VERSIONS.items():
        toolchain.verify(name)
        entry = receipt.get(name, {})
        require(
            entry.get("version") == manifest[name]["version"] == version, "unqualified_recon_tool"
        )
        provenance = entry.get("origin")
        if provenance is not None:
            require(
                isinstance(provenance, dict) and provenance.get("kind") == "go-module-source",
                "unqualified_recon_tool",
            )
            modules = provenance.get("modules", {})
            require(
                all(
                    modules.get(module, {}).get("version") == expected
                    for module, expected in _MODULES[name].items()
                ),
                "unqualified_recon_dependencies",
            )
        binary = Path(runner.program(name)).resolve(strict=True)
        require(
            binary.parent == config.tools_dir().resolve(strict=True), "managed_recon_tool_required"
        )
        paths[name], hashes[name] = binary, digest(binary.read_bytes())
        require(hashes[name] == entry.get("binary_sha256"), "tool_changed")
    return paths, hashes


def _json_lines(path: Path, maximum: int, rows: int) -> list[dict]:
    require(path.is_file() and not path.is_symlink(), "missing_recon_output")
    resources.enforce_artifact(path, maximum)
    result: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            require(isinstance(value, dict) and len(result) < rows, "invalid_recon_output")
            result.append(value)
    return result


def execute_recon(
    ledger: AuthorizationLedger,
    envelope: dict,
    approval: dict,
    plan: dict,
    case: dict,
    execution: dict,
    anchors: tuple,
    context: ValidationContext,
    run_dir: Path,
    *,
    on_reserved: Callable[[], None] | None = None,
    before_finish: Callable[[Path], None] | None = None,
    expiring_grants: bool = False,
) -> Path:
    """One ordinal, one authority/deadline, and no permission from discovered data."""
    require(
        plan.get("profile") == RUNTIME_PROFILE and context.origin == "standalone",
        "unsupported_enforcement",
    )
    require(
        execution_control.current() is not None or on_reserved is not None,
        "controlled_process_tree_required",
    )
    require(run_dir.is_dir() and not any(run_dir.iterdir()), "exclusive_output_required")
    paths, hashes = qualified_tools()
    require(hashes == {"httpx": context.tool_sha256, "dnsx": context.dnsx_sha256}, "tool_changed")
    require(
        plan["execution"]["allow_private_targets"]
        == (os.environ.get("VARDRRUNNER_ALLOW_PRIVATE_TARGETS") == "1"),
        "local_private_option_mismatch",
    )
    permission = approved(approval, anchors)["context"]
    require(not permission["credential_grants"], "unsupported_recon_authority")
    current = replace(context, now=datetime.now(timezone.utc), managed_status_verified=False)
    claimed = ledger.consume(envelope, approval, plan, case, execution, anchors, current)
    hard_end = time.monotonic() + min(
        execution["timeout_seconds"], permission["max_duration_seconds"]
    )
    if on_reserved is not None:
        on_reserved()
    require(execution_control.current() is not None, "controlled_process_tree_required")
    ending = min(
        timestamp(claimed["expires_at"]),
        timestamp(permission["expires_at"]),
        timestamp(permission["testing_end"]),
        timestamp(execution["deadline"]),
    )
    maximum = min(
        execution["max_artifact_bytes"],
        permission["max_artifact_bytes"],
        resources.load_limits().max_artifact_bytes,
    )
    home = run_dir / "tool-home"
    home.mkdir(mode=0o700)
    for name in ("tmp", "config", "cache"):
        (home / name).mkdir(mode=0o700)
    seeds, resolvers, networks = (
        run_dir / name for name in ("dns-input.txt", "resolvers.txt", "destinations.txt")
    )
    for path, lines in (
        (seeds, case["hostnames"]),
        (resolvers, [f"{r['address']}:{r['port']}" for r in case["resolvers"]]),
        (networks, case["destination_cidrs"]),
    ):
        manifests.write_exclusive(path, ("\n".join(lines) + "\n").encode("ascii"))
    launched = False

    def run(name: str, arguments: list[str]) -> None:
        nonlocal launched
        control = execution_control.current()
        require(control is not None, "controlled_process_tree_required")
        assert control is not None
        execution_control.require_permission(control)
        remaining = int(
            min((ending - datetime.now(timezone.utc)).total_seconds(), hard_end - time.monotonic())
        )
        require(remaining > 0, "execution_deadline")
        if launched and os.name != "nt":
            from vardrrunner.worker_lifecycle import SequentialWorkerOwner
            from vardrrunner.worker_lifecycle import current as owner_context

            owner = owner_context()
            require(isinstance(owner, SequentialWorkerOwner), "local_owner_required")
            assert isinstance(owner, SequentialWorkerOwner)
            owner.prepare_next_tool(control)
        # Explicit verification runs before every launch, even after a prior success.
        toolchain.verify(name)
        require(digest(paths[name].read_bytes()) == hashes[name], "tool_changed")
        with launch_guard.monotonic_deadline(hard_end):
            runner._run_tool([str(paths[name]), *arguments], None, name, remaining)
        launched = True

    with config.isolated_tool_environment(home):
        dns_output = run_dir / "dnsx.jsonl"
        manifests.write_exclusive(dns_output, b"")
        run(
            "dnsx",
            [
                "-l",
                str(seeds),
                "-r",
                str(resolvers),
                "-a",
                "-retry",
                "1",
                "-t",
                "1",
                "-timeout",
                "1s",
                "-json",
                "-silent",
                "-no-color",
                "-disable-update-check",
                "-o",
                str(dns_output),
            ],
        )
        dns_rows = _json_lines(dns_output, maximum, len(case["hostnames"]))
        answers = []
        for row in dns_rows:
            addresses = row.get("a", [])
            require(isinstance(addresses, list), "invalid_recon_answers")
            if addresses:
                answers.append({"hostname": row.get("host"), "addresses": addresses})
            else:
                require(row.get("host") in case["hostnames"], "unapproved_recon_answer")
        candidates = select_runtime_candidates(plan, answers)
        observations = []
        total = dns_output.stat().st_size
        for index, candidate in enumerate(candidates):
            output = run_dir / f"httpx-{index:04d}.jsonl"
            manifests.write_exclusive(output, b"")
            hostname, address = candidate["hostname"], candidate["address"]
            run(
                "httpx",
                [
                    "-u",
                    f"https://{address}:443/",
                    "-sni-name",
                    hostname,
                    "-H",
                    f"Host: {hostname}:443",
                    "-no-fallback-scheme",
                    "-protocol",
                    "http11",
                    "-retries",
                    "0",
                    "-timeout",
                    "1",
                    "-threads",
                    "1",
                    "-rate-limit",
                    "10",
                    "-allow",
                    str(networks),
                    "-r",
                    str(resolvers),
                    "-random-agent=false",
                    "-cdn=false",
                    "-disable-update-check",
                    "-json",
                    "-silent",
                    "-no-color",
                    "-no-stdin",
                    "-response-size-to-read",
                    "65536",
                    "-o",
                    str(output),
                ],
            )
            rows = _json_lines(output, maximum, 1)
            total += output.stat().st_size
            require(total <= maximum, "artifact_limit")
            observations.append(
                {
                    "candidate": {k: v for k, v in candidate.items() if k != "address"},
                    "address": address,
                    "logical_url": f"https://{hostname}:443/",
                    "observations": rows,
                    "outcome": "response_observed" if rows else "no_response_reported",
                }
            )
    artifact = run_dir / "recon_result.json"
    document = {
        "schema": "vardr.recon-evidence/1",
        "profile": RUNTIME_PROFILE,
        "plan_sha256": digest(encoded(plan)),
        "case_hash": plan["case_hash"],
        "tools": plan["tools"],
        "provenance": manifests.evidence_provenance(
            case,
            plan["case_hash"],
            {
                name: {
                    "sha256": hashes[name],
                    "version": version,
                    "hash_basis": "qualified_managed_binary",
                }
                for name, version in _VERSIONS.items()
            },
        ),
        "dns": dns_rows,
        "http": observations,
        "counting": {
            "dns_question_ceiling": plan["max_dns_queries"],
            "http_request_ceiling": plan["max_http_dispatches"],
            "basis": "reviewed_tool_source_bounds_not_packet_measurement",
        },
        "handoff": {
            "candidate_urls": [row["logical_url"] for row in observations if row["observations"]],
            "requires_new_review": True,
            "execution_authority": False,
        },
        "limitations": [
            "A-only; original HTTPS/443 GET-root candidates only",
            "No response is not proof of absence or authorization safety",
        ],
    }
    content = json.dumps(document, sort_keys=True, allow_nan=False).encode("utf-8")
    require(len(content) <= maximum, "artifact_limit")
    manifests.write_exclusive(artifact, content)
    require(time.monotonic() < hard_end, "execution_deadline")
    if before_finish is not None:
        with launch_guard.monotonic_deadline(hard_end):
            before_finish(artifact)
    require(
        datetime.now(timezone.utc) < ending and time.monotonic() < hard_end, "execution_deadline"
    )
    ledger.finish(claimed)
    return artifact
