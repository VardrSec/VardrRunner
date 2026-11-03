"""Explicit fixed Gate target binding; never universal tool target discovery."""

import os
import shutil
from pathlib import Path

from vardrrunner import configs, handlers, runner
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.plan import compile_gate_plan, origin


def prepare(cfg):
    if not isinstance(cfg, configs.VardrGateConfig):
        raise configs.ConfigError("target budgets support fixed Gate only")
    try:
        binary = runner.program("vardrgate_api_test")
        tool_hash = digest(Path(shutil.which(binary) or binary).read_bytes())
        execution = {
            **cfg.execution,
            "allow_private_targets": os.environ.get("VARDRRUNNER_ALLOW_PRIVATE_TARGETS") == "1",
        }
        plan = compile_gate_plan(cfg.test_case, execution, tool_sha256=tool_hash)
        origins = sorted({origin(value) for value in handlers._case_origins(cfg.test_case)})
        if not 1 <= len(origins) <= 100:
            raise configs.ConfigError("target origin count out of range")
        binding = {
            "profile": plan["profile"],
            "case_sha256": digest(encoded(cfg.test_case)),
            "origins": origins,
        }
        return binding, plan
    except (AuthorizationError, ValueError, OSError):
        raise configs.ConfigError("unsupported fixed Gate target plan") from None


def receipt_matches(receipt, expected):
    if not isinstance(receipt, dict) or receipt.get("binding") != expected:
        return False
    charged, spent, limit = (receipt.get(key) for key in ("charged", "spent", "limit"))
    return (
        type(charged) is int
        and type(spent) is int
        and type(limit) is int
        and charged == len(expected["origins"])
        and charged <= spent <= limit
    )
