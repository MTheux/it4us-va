#!/usr/bin/env python3
"""Run Draxen's offline infrastructure review inside a VA run directory.

Only persisted scanner evidence is analyzed. This bridge has no target or
network arguments, and rejects any Draxen result claiming network activity.
"""
from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print(json.dumps({"ok": False, "reason": "invalid arguments"}))
        return 2
    root = Path(sys.argv[1]).resolve(strict=True)
    artifact = Path(sys.argv[2]).resolve(strict=True)
    engagement = sys.argv[3]
    if artifact.parent != root or artifact.name != "analysis-input.json":
        print(json.dumps({"ok": False, "reason": "artifact outside VA run"}))
        return 2
    if not engagement.startswith("it4us-va-") or not engagement.removeprefix("it4us-va-").isalnum():
        print(json.dumps({"ok": False, "reason": "invalid engagement"}))
        return 2
    engine_dir = Path(os.environ.get("IT4US_DRAXEN_ENGINE_DIR", "")).expanduser()
    if not engine_dir.is_dir() or not (engine_dir / "hermes_driver.py").is_file():
        print(json.dumps({"ok": False, "reason": "Draxen engine unavailable"}))
        return 2
    sys.path.insert(0, str(engine_dir))
    from hermes_driver import inspect  # imported only after path validation
    from draxen_agent_state import AgentState
    from draxen_next_action import rank_actions

    result = inspect(root, engagement, "infrastructure", [str(artifact)])
    if result.get("network_requests") != 0 or result.get("executed_artifacts") != 0:
        print(json.dumps({"ok": False, "reason": "offline contract violated"}))
        return 2
    if result.get("ok"):
        receipt = json.loads(artifact.read_text(encoding="utf-8"))
        hosts = (receipt.get("result") or {}).get("hosts") or []
        if not isinstance(hosts, list) or len(hosts) > 16:
            print(json.dumps({"ok": False, "reason": "invalid VA host inventory"}))
            return 2
        plans = []
        for host in hosts:
            target = host.get("target")
            if host.get("status") != "completed" or not isinstance(target, str):
                continue
            candidates = host.get("candidates") or []
            if not isinstance(candidates, list) or len(candidates) > 2000:
                print(json.dumps({"ok": False, "reason": "invalid VA candidate inventory"}))
                return 2
            state = AgentState.from_engagement(
                engagement + "-" + hashlib.sha256(target.encode()).hexdigest()[:8],
                target, "infrastructure", {},
                coverage={"source": "it4us-va", "network_requests": 0},
                budgets={"network_requests": 0},
            )
            for service in host.get("services") or []:
                if service.get("IP") != target:
                    continue
                port = service.get("Port")
                if isinstance(port, int) and 1 <= port <= 65535:
                    state.add_asset({"id": f"{target}:{port}", "type": "service",
                                     "name": str(service.get("Service") or "unknown")[:100],
                                     "port": port, "confidence": 1.0}, source="va.discovery")
            for index, candidate in enumerate(candidates):
                asset = candidate.get("asset") or candidate.get("Asset") or {}
                if asset.get("ip", asset.get("IP")) != target:
                    continue
                state.add_finding({
                    "id": "VA-" + hashlib.sha256(f"{target}:{index}".encode()).hexdigest()[:12],
                    "state": "candidate", "target": target,
                    "category": str(candidate.get("check", candidate.get("Check", "va")))[:80],
                    "severity": str(candidate.get("severity", candidate.get("Severity", "medium"))).lower(),
                    "confidence": 0.5, "evidence": ["analysis-input.json"],
                }, source="va.candidate")
            plan = rank_actions(state, limit=10)
            actions = [action for action in plan.get("actions", [])
                       if action.get("target") == target and action.get("action_class") == "active_read"]
            plans.append({"target": target, "services": len(host.get("services") or []),
                          "candidates": len(candidates), "proposed_actions": actions,
                          "executed_actions": 0, "policy": "SOC must authorize any follow-up"})
        result["va_review"] = {"hosts": plans, "executed_actions": 0}
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
