"""Operator provisioning for the existing signed standalone execution protocol."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import typer
from rich.console import Console

from vardrrunner import config, credential_grants, identity, manifests, resources, runner
from vardrrunner.authorization.codec import TrustAnchor, b64, digest, encoded, fields, require
from vardrrunner.authorization.contracts import ValidationContext, approve
from vardrrunner.authorization.documents import read_anchors, read_document
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.plan import compile_gate_plan, origin
from vardrrunner.journal import Journal
from vardrrunner.workspaces import Workspaces, validate_id

console = Console()
DOCUMENTS = ("approval", "contract", "plan", "case", "execution", "trust")


def _workspace(workspace_id: str) -> Journal:
    validate_id(workspace_id)
    journal = Journal(config.journal_file())
    require(Workspaces(journal).get(workspace_id) is not None, "unknown_workspace")
    return journal


def _separate(first: Path, second: Path) -> None:
    require(
        first != second and first not in second.parents and second not in first.parents,
        "issuer_execution_state_overlap",
    )


def _issuer_directory(path: Path) -> Path:
    # Resolve operator-selected paths before comparing custody boundaries. Packaging
    # must also keep this directory out of every execution container's mounts.
    require(not path.is_symlink(), "exclusive_path_required")
    path = path.expanduser().resolve()
    for state in (config.config_dir(), config.runs_dir(), config.journal_file()):
        _separate(path, state.resolve())
    return path


def _new_directory(path: Path) -> Path:
    require(not path.is_symlink(), "exclusive_path_required")
    path = path.expanduser().resolve()
    require(path.parent.is_dir() and not path.exists(), "exclusive_output_required")
    path.mkdir(mode=0o700)
    return path


def _secret(path: Path) -> bytes:
    require(not path.is_symlink(), "issuer_key_unavailable")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_size == 32
            and (os.name == "nt" or info.st_mode & 0o077 == 0),
            "issuer_key_unavailable",
        )
        value = stream.read(33)
    require(len(value) == 32, "issuer_key_unavailable")
    return value


def authority_init(workspace_id: str, *, output: Path) -> None:
    """Create a private local issuer, never inside the execution-state directory."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        destination = _issuer_directory(output)
        journal = _workspace(workspace_id)
        who = identity.load_or_create()
        key = Ed25519PrivateKey.generate()
        issuer = {"id": "local-" + uuid.uuid4().hex, "key_id": uuid.uuid4().hex}
        metadata: dict = {
            "schema": "vardr.workspace-authority/1",
            "workspace_id": workspace_id,
            "runner_id": who.runner_id,
            "issuer": issuer,
            "public_key": b64(key.public_key().public_bytes_raw()),
            "authority_revision": 1,
        }
        metadata["authority_sha256"] = digest(encoded(metadata))
        trust = [
            {
                "issuer_id": issuer["id"],
                "key_id": issuer["key_id"],
                "public_key": metadata["public_key"],
                "purposes": ["approval", "contract"],
                "origins": ["standalone"],
                "revoked": False,
            }
        ]
        destination = _new_directory(destination)
        manifests.write_exclusive(destination / "signing.key", key.private_bytes_raw())
        manifests.write_exclusive(destination / "trust.json", encoded(trust))
        AuthorizationLedger(journal).set_state(
            issuer["id"], workspace_id, 1, False, metadata["authority_sha256"]
        )
        # This last file is the completion marker; partial output is never repaired.
        manifests.write_exclusive(destination / "authority.json", encoded(metadata))
        console.print_json(
            json.dumps(
                {
                    "workspace_id": workspace_id,
                    "authority_sha256": metadata["authority_sha256"],
                    "status": "issuer_ready",
                }
            )
        )
    except Exception:
        console.print("[red]Local issuer creation refused; retain any partial output.[/red]")
        raise typer.Exit(1) from None


def _authority(workspace_id: str, path: Path) -> tuple[dict, bytes, tuple[TrustAnchor, ...]]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = _issuer_directory(path)
    metadata = read_document(path / "authority.json")
    fields(
        metadata,
        {
            "schema",
            "workspace_id",
            "runner_id",
            "issuer",
            "public_key",
            "authority_revision",
            "authority_sha256",
        },
    )
    fields(metadata["issuer"], {"id", "key_id"})
    require(
        metadata["schema"] == "vardr.workspace-authority/1"
        and metadata["workspace_id"] == workspace_id
        and metadata["runner_id"] == identity.load_or_create().runner_id
        and type(metadata["authority_revision"]) is int
        and metadata["authority_revision"] == 1
        and metadata["authority_sha256"]
        == digest(encoded({k: v for k, v in metadata.items() if k != "authority_sha256"})),
        "issuer_binding_changed",
    )
    key = _secret(path / "signing.key")
    public = Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes_raw()
    anchors = read_anchors(path / "trust.json")
    require(
        len(anchors) == 1
        and anchors[0].issuer_id == metadata["issuer"]["id"]
        and anchors[0].key_id == metadata["issuer"]["key_id"]
        and anchors[0].public_key == public
        and b64(public) == metadata["public_key"]
        and anchors[0].purposes == frozenset({"approval", "contract"})
        and anchors[0].origins == frozenset({"standalone"})
        and not anchors[0].revoked,
        "issuer_binding_changed",
    )
    return metadata, key, anchors


def authorize(
    workspace_id: str,
    *,
    authority: Path,
    case: Path,
    execution: Path | None,
    output: Path,
    expires_in: int = 900,
) -> None:
    """Review one exact plan, approve its reference grants, and issue one execution."""
    try:
        require(sys.stdin.isatty(), "interactive_operator_required")
        require(type(expires_in) is int and 1 <= expires_in <= 86400, "invalid_window")
        journal = _workspace(workspace_id)
        metadata, key, anchors = _authority(workspace_id, authority)
        destination = output.expanduser().resolve()
        _separate(destination, _issuer_directory(authority))
        require(
            not destination.exists() and destination.parent.is_dir(), "exclusive_output_required"
        )
        case_input = read_document(case)
        options = {} if execution is None else read_document(execution)
        binary = runner.program("vardrgate_api_test")
        tool = Path(shutil.which(binary) or binary)
        compiled = compile_gate_plan(case_input, options, tool_sha256=digest(tool.read_bytes()))
        scopes = sorted(
            {
                (
                    origin(d["request"]["url"]),
                    urlsplit(d["request"]["url"]).path or "/",
                    d["request"]["method"],
                )
                for d in compiled["dispatches"]
            }
        )
        console.print(f"Workspace: {workspace_id}")
        console.print(f"Plan SHA-256: {digest(encoded(compiled))}")
        console.print(f"One execution; HTTP dispatch ceiling: {compiled['max_http_dispatches']}")
        for site, path, method in scopes:
            console.print(f"{method} {site}{path}", markup=False)
        for ref in compiled["credential_references"]:
            console.print(f"Credential reference: {ref['source']} {ref['name']}", markup=False)
        console.print(f"Approval and credential references expire in {expires_in} seconds.")
        require(
            typer.prompt("Review the case and scope, then type APPROVE") == "APPROVE",
            "operator_declined",
        )
        now = datetime.now(timezone.utc).replace(microsecond=0)
        end = now + timedelta(seconds=expires_in)

        def stamp(value: datetime) -> str:
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")

        context = ValidationContext(
            runner_id=metadata["runner_id"],
            engagement_id=workspace_id,
            job_id=str(uuid.uuid4()),
            attempt_id=str(uuid.uuid4()),
            fence=1,
            origin="standalone",
            now=now,
            authority_revision=metadata["authority_revision"],
            authority_sha256=metadata["authority_sha256"],
            tool_sha256=compiled["tool_sha256"],
        )
        permission = {
            "runner_id": context.runner_id,
            "engagement_id": workspace_id,
            "job_id": context.job_id,
            "authority_revision": context.authority_revision,
            "authority_sha256": context.authority_sha256,
            "plan_sha256": digest(encoded(compiled)),
            "mode": "strict",
            "scope": [
                {"origin": site, "path": path, "method": method, "excluded": False, "reason": ""}
                for site, path, method in scopes
            ],
            "exceptions": [],
            "not_before": stamp(now),
            "expires_at": stamp(end),
            "testing_start": stamp(now),
            "testing_end": stamp(end),
            "max_executions": 1,
            "max_duration_seconds": compiled["execution"]["timeout_seconds"],
            "max_http_dispatches": compiled["max_http_dispatches"],
            "max_artifact_bytes": min(resources.load_limits().max_artifact_bytes, 1024**3),
            "credential_grants": [
                {**ref, "revision": 1, "expires_at": stamp(end)}
                for ref in compiled["credential_references"]
            ],
            "control": "local_offline",
        }
        ledger = AuthorizationLedger(journal, clock=lambda: datetime.now(timezone.utc))
        # Never silently reset a stopped/revoked authority, even after a new review.
        ledger.check_state(context, metadata["issuer"]["id"])
        for ref in compiled["credential_references"]:
            for site in sorted({s[0] for s in scopes}):
                credential_grants.Store().approve(
                    "standalone",
                    workspace_id,
                    site,
                    ref["source"].removeprefix("value_"),
                    ref["name"],
                    expires_in,
                )
        if permission["credential_grants"]:
            revision = config.load()[credential_grants.KEY]["revision"]
            for grant in permission["credential_grants"]:
                grant["revision"] = revision
        receipt = approve(
            permission,
            metadata["issuer"],
            "standalone",
            context.runner_id,
            uuid.uuid4().hex,
            stamp(now),
            key,
        )
        envelope = ledger.issue(
            receipt,
            anchors,
            metadata["issuer"],
            key,
            str(uuid.uuid4()),
            context.attempt_id,
            context,
            compiled,
            case_input,
            options,
        )
        destination = _new_directory(destination)
        for name, value in zip(
            DOCUMENTS,
            (
                receipt,
                envelope,
                compiled,
                case_input,
                options,
                read_document(_issuer_directory(authority) / "trust.json"),
            ),
            strict=True,
        ):
            manifests.write_exclusive(destination / (name + ".json"), encoded(value))
        console.print_json(
            json.dumps(
                {
                    "workspace_id": workspace_id,
                    "plan_sha256": digest(encoded(compiled)),
                    "expires_at": stamp(end),
                    "status": "authorized_once",
                }
            )
        )
    except Exception:
        console.print("[red]Standalone authorization refused; retain any partial output.[/red]")
        raise typer.Exit(1) from None


def execute(
    workspace_id: str, *, authorization: Path, output: Path, export: Path | None = None
) -> None:
    """Execute the public bundle through the existing native consumer, then export."""
    from vardrrunner.commands import audit, workspace_gate

    try:
        directory = authorization.expanduser().resolve(strict=True)
        require(directory.is_dir(), "authorization_bundle_unavailable")
        paths = {name: directory / (name + ".json") for name in DOCUMENTS}
        require(
            all(path.is_file() and not path.is_symlink() for path in paths.values()),
            "authorization_bundle_unavailable",
        )
        require(not (directory / "signing.key").exists(), "private_issuer_in_execution_bundle")
    except Exception:
        console.print("[red]Public authorization bundle unavailable.[/red]")
        raise typer.Exit(1) from None
    finished = workspace_gate.run(workspace_id, **paths, output=output)
    if export is not None:
        audit.export_run(finished.run_id, export)
