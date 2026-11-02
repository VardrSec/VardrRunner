"""Explicit file-based NM-1 prototypes; never starts tools or polls Map."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .codec import AuthorizationError, TrustAnchor, decoded, digest, encoded, require, unb64
from .contracts import ValidationContext, approve, timestamp, validate
from .ledger import AuthorizationLedger
from .plan import compile_gate_plan


def _read(path: str):
    return decoded(Path(path).read_bytes())


def _write(path: str, value: dict) -> None:
    # Exclusive output; no overwrite of an approval, result or operator file.
    with Path(path).open("xb") as stream:
        stream.write(encoded(value))


def _anchors(path: str) -> tuple[TrustAnchor, ...]:
    data = _read(path)
    require(isinstance(data, list) and len(data) <= 100, "invalid_trust_store")
    return tuple(
        TrustAnchor(
            a["issuer_id"],
            a["key_id"],
            unb64(a["public_key"]),
            frozenset(a["purposes"]),
            frozenset(a["origins"]),
            a["revoked"],
        )
        for a in data
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="NM-1 authorization reference prototypes (no target execution)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--case", required=True)
    plan.add_argument("--execution", required=True)
    plan.add_argument("--tool", required=True, help="Explicit Gate binary to bind by SHA-256")
    plan.add_argument("--out", required=True)
    approval = commands.add_parser("approve")
    for name in (
        "context",
        "issuer",
        "key-id",
        "key-file",
        "origin",
        "approver",
        "approval-id",
        "at",
        "out",
    ):
        approval.add_argument("--" + name, required=True)
    for command in ("issue", "validate"):
        sub = commands.add_parser(command)
        for name in ("approval", "plan", "case", "execution", "trust", "context"):
            sub.add_argument("--" + name, required=True)
        if command == "issue":
            for name in ("issuer", "key-id", "key-file", "journal", "contract-id", "out"):
                sub.add_argument("--" + name, required=True)
        else:
            sub.add_argument("--contract", required=True)
            sub.add_argument("--consume-journal")
    state = commands.add_parser("state")
    for name in ("journal", "issuer", "engagement"):
        state.add_argument("--" + name, required=True)
    state.add_argument("--revision", type=int, required=True)
    state.add_argument("--authority-sha256", required=True)
    state.add_argument("--stopped", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result = compile_gate_plan(
                _read(args.case),
                _read(args.execution),
                tool_sha256=digest(Path(args.tool).read_bytes()),
            )
            _write(args.out, result)
        elif args.command == "approve":
            context = _read(args.context)
            # No --yes, unattended approval, MCP tool or queue-facing approval API.
            print(
                f"Approval reserves at most {context['max_executions']} unchanged-plan executions."
            )
            print(f"Plan SHA-256: {context['plan_sha256']}")
            require(sys.stdin.isatty(), "interactive_operator_required")
            require(
                input("Review the context and type APPROVE: ") == "APPROVE", "operator_declined"
            )
            result = approve(
                context,
                {"id": args.issuer, "key_id": args.key_id},
                args.origin,
                args.approver,
                args.approval_id,
                args.at,
                Path(args.key_file).read_bytes(),
            )
            _write(args.out, result)
        elif args.command == "state":
            from vardrrunner.journal import Journal

            AuthorizationLedger(Journal(Path(args.journal))).set_state(
                args.issuer, args.engagement, args.revision, args.stopped, args.authority_sha256
            )
        else:
            raw_context = _read(args.context)
            require("managed_status_verified" not in raw_context, "managed_control_unsupported")
            raw_context["now"] = timestamp(raw_context["now"])
            context = ValidationContext(**raw_context)
            receipt, plan, case, execution = (
                _read(p) for p in (args.approval, args.plan, args.case, args.execution)
            )
            require(Path(args.plan).read_bytes() == encoded(plan), "plan_bytes_changed")
            anchors = _anchors(args.trust)
            if args.command == "issue":
                from vardrrunner.journal import Journal

                result = AuthorizationLedger(Journal(Path(args.journal))).issue(
                    receipt,
                    anchors,
                    {"id": args.issuer, "key_id": args.key_id},
                    Path(args.key_file).read_bytes(),
                    args.contract_id,
                    context.attempt_id,
                    context,
                    plan,
                    case,
                    execution,
                )
                _write(args.out, result)
            else:
                envelope = _read(args.contract)
                if args.consume_journal:
                    from vardrrunner.journal import Journal

                    AuthorizationLedger(Journal(Path(args.consume_journal))).consume(
                        envelope, receipt, plan, case, execution, anchors, context
                    )
                else:
                    validate(envelope, receipt, plan, case, execution, anchors, context)
                print("valid_reference_contract; no target execution or managed-control claim")
        return 0
    except (AuthorizationError, OSError, ValueError, TypeError, KeyError):
        # A caller-selected filename or malformed payload can contain secrets.
        print("authorization_prototype_refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
