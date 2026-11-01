"""Start the whole platform locally — five services, one command (Windows, macOS, Linux).

    python -m scripts.run_all
    → open http://127.0.0.1:8000/console

    Service            Port   What it is
    api-gateway        8000   Edge: token validation, routing, rate limits, header hygiene
    agent-api          8080   Orchestrator + agents + human review (reachable only through the gateway)
    mcp-tool-service   8765   Governed MCP tools (the agents' only route to business systems)
    customer-service   8101   System of record: profile, transactions, card status (synthetic)
    case-service       8102   Case management: complaints, disputes, fraud referrals (synthetic)

All services share one hash-chained audit store (``<data-dir>/audit.db``) and use
workload identity (service tokens) for every internal call. Logs are written to
``<data-dir>/logs/<service>.log``. Press Ctrl+C to stop everything.

Options: ``--data-dir``, ``--port-offset`` (shift all ports, e.g. 100), ``--fresh`` (wipe data first).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BASE_PORTS = {"api-gateway": 8000, "agent-api": 8080, "mcp-tool-service": 8765, "customer-service": 8101,
              "case-service": 8102}
START_ORDER = ["customer-service", "case-service", "mcp-tool-service", "agent-api", "api-gateway"]


@dataclass
class Stack:
    data_dir: Path
    ports: dict[str, int]
    procs: dict[str, subprocess.Popen] = field(default_factory=dict)
    logs: dict[str, object] = field(default_factory=dict)

    def url(self, service: str) -> str:
        return f"http://127.0.0.1:{self.ports[service]}"

    @property
    def gateway(self) -> str:
        return self.url("api-gateway")

    def stop(self) -> None:
        for name in reversed(START_ORDER):
            p = self.procs.get(name)
            if p and p.poll() is None:
                p.terminate()
        for name, p in self.procs.items():
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        for f in self.logs.values():
            f.close()


def _env(stack: Stack) -> dict[str, dict[str, str]]:
    d = str(stack.data_dir)
    common = {
        "CCAGENT_ENV": os.getenv("CCAGENT_ENV", "local"),
        "CCAGENT_DATA_DIR": d,
        "CCAGENT_AUDIT_DB_PATH": str(stack.data_dir / "audit.db"),
        "CCAGENT_SERVICE_AUTH": "local",
        "PYTHONUNBUFFERED": "1",
    }
    customer, case, mcp = stack.url("customer-service"), stack.url("case-service"), stack.url("mcp-tool-service")
    return {
        "customer-service": common,
        "case-service": common,
        "mcp-tool-service": common | {
            "CCAGENT_SQLITE_PATH": str(stack.data_dir / "mcp.db"),
            "CCAGENT_CUSTOMER_SERVICE": "http", "CUSTOMER_API_BASE_URL": customer,
            "CCAGENT_CASE_SERVICE": "http", "CASE_API_BASE_URL": case,
            "MCP_PORT": str(stack.ports["mcp-tool-service"]),
        },
        "agent-api": common | {
            "CCAGENT_SQLITE_PATH": str(stack.data_dir / "ccagent.db"),
            "CCAGENT_MCP_MODE": "http", "CCAGENT_MCP_URL": mcp + "/mcp",
            "CCAGENT_CASE_SERVICE": "http", "CASE_API_BASE_URL": case,
            "CCAGENT_REQUIRE_GATEWAY": "true",
        },
        "api-gateway": common | {
            "GATEWAY_UPSTREAM_AGENT_API": stack.url("agent-api"),
            "GATEWAY_HEALTH_MCP": mcp, "GATEWAY_HEALTH_CUSTOMER": customer, "GATEWAY_HEALTH_CASE": case,
        },
    }


def _command(name: str, port: int) -> list[str]:
    if name == "mcp-tool-service":
        return [sys.executable, "-m", "ccagent.mcp_server"]
    factory = {"customer-service": "services.customer_service.app:create_app",
               "case-service": "services.case_service.app:create_app",
               "agent-api": "ccagent.api.app:create_app",
               "api-gateway": "services.gateway.app:create_app"}[name]
    return [sys.executable, "-m", "uvicorn", factory, "--factory", "--host", "127.0.0.1", "--port", str(port),
            "--log-level", "warning"]


def _wait_healthy(url: str, proc: subprocess.Popen, timeout_s: float = 60) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited with code {proc.returncode}")
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=1) as r:  # noqa: S310 - local URL
                if r.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.25)
    raise RuntimeError(f"{url} not healthy after {timeout_s}s")


def _init_secrets(data_dir: Path) -> None:
    """Create the local dev keys once, before any service starts, so every process shares them."""
    env = {**os.environ, "CCAGENT_DATA_DIR": str(data_dir), "CCAGENT_ENV": os.getenv("CCAGENT_ENV", "local")}
    code = ("from ccagent.config import Settings; from ccagent.secrets import *; "
            "from ccagent.security.service_tokens import SERVICE_SIGNING_KEY as S; "
            "p = build_secret_provider(Settings.from_env()); "
            "[p.get(n) for n in (JWT_SIGNING_KEY, DELEGATION_SIGNING_KEY, APPROVAL_SIGNING_KEY, "
            "CHECKPOINT_ENCRYPTION_KEY, S)]")
    subprocess.run([sys.executable, "-c", code], env=env, cwd=ROOT, check=True)


def start_stack(data_dir: Path | str = ROOT / ".data" / "stack", port_offset: int = 0, fresh: bool = False,
                quiet: bool = True) -> Stack:
    data_dir = Path(data_dir).resolve()
    if fresh and data_dir.exists():
        shutil.rmtree(data_dir)
    (data_dir / "logs").mkdir(parents=True, exist_ok=True)
    stack = Stack(data_dir=data_dir, ports={k: v + port_offset for k, v in BASE_PORTS.items()})
    _init_secrets(data_dir)
    envs = _env(stack)
    try:
        for name in START_ORDER:
            log = open(data_dir / "logs" / f"{name}.log", "ab")  # noqa: SIM115 - closed in Stack.stop
            stack.logs[name] = log
            env = {**os.environ, **envs[name]}
            env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), os.environ.get("PYTHONPATH")]))
            stack.procs[name] = subprocess.Popen(_command(name, stack.ports[name]), cwd=ROOT, env=env,
                                                 stdout=log, stderr=subprocess.STDOUT)
            _wait_healthy(stack.url(name), stack.procs[name])
            if not quiet:
                print(f"  ✓ {name:<17} {stack.url(name)}")
    except Exception:
        stack.stop()
        raise
    return stack


def main() -> None:
    ap = argparse.ArgumentParser(description="Start all five services locally.")
    ap.add_argument("--data-dir", default=str(ROOT / ".data" / "stack"))
    ap.add_argument("--port-offset", type=int, default=0)
    ap.add_argument("--fresh", action="store_true", help="delete existing local data first")
    a = ap.parse_args()
    print("Starting services…")
    try:
        stack = start_stack(a.data_dir, a.port_offset, a.fresh, quiet=False)
    except RuntimeError as e:
        print(f"\nCould not start: {e}\nSee logs in {Path(a.data_dir) / 'logs'}. "
              f"If a port is in use, try --port-offset 100.")
        sys.exit(1)
    with urllib.request.urlopen(stack.gateway + "/gateway/health", timeout=5) as r:  # noqa: S310
        health = json.load(r)
    print(f"\nAll services {health['status']}.  Open the demo:  {stack.gateway}/console")
    print(f"Gateway health: {stack.gateway}/gateway/health   Logs: {stack.data_dir / 'logs'}")
    print("Press Ctrl+C to stop.")
    try:
        while all(p.poll() is None for p in stack.procs.values()):
            time.sleep(1)
        dead = [n for n, p in stack.procs.items() if p.poll() is not None]
        print(f"Stopped unexpectedly: {', '.join(dead)} (see logs)")
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        stack.stop()


if __name__ == "__main__":
    main()
