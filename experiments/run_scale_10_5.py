#!/usr/bin/env python3
"""
Эксперимент масштаба 10×5 (10 пользователей × 5 сервисов).

Реализует методологию Главы 5:
- 3 режима нагрузки: sparse, boundary, dense
- 10–20 прогонов на режим
- Метрики: T_setup, T_revoke, RTT, AS̅_direct

Использует Docker-контейнеры client-01..client-10 как независимые
пользовательские агенты с изолированными сетевыми namespace.
"""

import asyncio
import json
import os
import random
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

# --- Configuration ---
USERS = [f"user{i:02d}" for i in range(1, 11)]
SERVICES = [f"protected-service-{i}" for i in range(1, 6)]
CONTAINER_PREFIX = "ztna-client-"
RUNS_PER_MODE = 10  # 10–20 по методологии

# Load patterns per mode: mapping user_idx -> list of service indices (0-based)
LOAD_PATTERNS = {
    "sparse": {  # K_avg ≈ 10 (each user -> 1 service)
        i: [i % 5] for i in range(10)
    },
    "boundary": {  # K_avg ≈ 15 (mix of 1 and 2 services)
        **{i: [i % 5] for i in range(5)},
        **{i: [i % 5, (i + 1) % 5] for i in range(5, 10)},
    },
    "dense": {  # K_avg = 50 (each user -> all 5 services)
        i: list(range(5)) for i in range(10)
    },
}

REPORTS_DIR = Path(__file__).parent / "reports"


@dataclass
class RunResult:
    mode: str
    run_id: int
    setup_times_ms: Dict[str, float] = field(default_factory=dict)
    revoke_times_ms: Dict[str, float] = field(default_factory=dict)
    rtts_ms: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


def docker_exec(container: str, cmd: List[str], timeout: int = 30) -> tuple:
    """Execute a command inside a Docker container."""
    full_cmd = ["docker", "exec", container] + cmd
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


async def run_single_access(
    container: str, service_id: str
) -> tuple[float, str | None]:
    """Request access and return (setup_time_ms, jti_or_error)."""
    t0 = time.perf_counter()
    rc, stdout, stderr = docker_exec(
        container,
        ["python", "main.py", "request-access", "--service-id", service_id],
        timeout=30,
    )
    t1 = time.perf_counter()
    setup_ms = (t1 - t0) * 1000

    if rc != 0:
        return setup_ms, f"ERROR: {stderr or stdout}"

    # Extract JTI from output
    jti = None
    for line in stdout.splitlines():
        if "Ticket received:" in line:
            jti = line.split("Ticket received:")[1].strip()
            break
    return setup_ms, jti


async def run_single_revoke(
    container: str, jti: str
) -> tuple[float, str | None]:
    """Revoke local access and return (revoke_time_ms, error_or_none)."""
    t0 = time.perf_counter()
    rc, stdout, stderr = docker_exec(
        container,
        ["python", "main.py", "revoke-local", "--jti", jti],
        timeout=10,
    )
    t1 = time.perf_counter()
    revoke_ms = (t1 - t0) * 1000

    if rc != 0:
        return revoke_ms, f"ERROR: {stderr or stdout}"
    return revoke_ms, None


async def run_single_rtt(container: str, service_id: str) -> tuple[float, str | None]:
    """Measure RTT to a service via HTTP ping through the tunnel."""
    # The tunnel in our prototype is HTTP-level; we ping the service directly
    # on the data-plane network. In a real TUN setup this would go
    # through the tunnel interface.
    service_ip = f"172.21.0.{50 + int(service_id.split('-')[-1]) - 1}"
    t0 = time.perf_counter()
    rc, stdout, stderr = docker_exec(
        container,
        ["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
         f"http://{service_ip}:8000/health"],
        timeout=10,
    )
    t1 = time.perf_counter()
    rtt_ms = (t1 - t0) * 1000

    if rc != 0:
        return rtt_ms, f"ERROR: {stderr}"
    return rtt_ms, None


async def run_experiment_mode(mode: str, run_id: int) -> RunResult:
    """Run one experiment iteration for a given load mode."""
    pattern = LOAD_PATTERNS[mode]
    result = RunResult(mode=mode, run_id=run_id)

    # --- Phase 1: Setup (all users request their services concurrently) ---
    setup_tasks = []
    access_map: Dict[str, List[tuple[str, str]]] = {}  # container -> [(service, jti)]

    for user_idx, service_indices in pattern.items():
        container = f"{CONTAINER_PREFIX}{user_idx + 1:02d}"
        access_map[container] = []
        for si in service_indices:
            service = SERVICES[si]
            task = asyncio.create_task(run_single_access(container, service))
            setup_tasks.append((container, service, task))

    for container, service, task in setup_tasks:
        setup_ms, jti = await task
        key = f"{container}:{service}"
        result.setup_times_ms[key] = setup_ms
        if jti and not jti.startswith("ERROR"):
            access_map[container].append((service, jti))
        else:
            result.errors.append(f"Setup failed {key}: {jti}")

    # Small stabilization delay
    await asyncio.sleep(1)

    # --- Phase 2: RTT measurement ---
    rtt_tasks = []
    for container, accesses in access_map.items():
        for service, _ in accesses:
            task = asyncio.create_task(run_single_rtt(container, service))
            rtt_tasks.append((container, service, task))

    for container, service, task in rtt_tasks:
        rtt_ms, err = await task
        key = f"{container}:{service}"
        result.rtts_ms[key] = rtt_ms
        if err:
            result.errors.append(f"RTT failed {key}: {err}")

    # --- Phase 3: Revoke (all sessions) ---
    revoke_tasks = []
    for container, accesses in access_map.items():
        for service, jti in accesses:
            task = asyncio.create_task(run_single_revoke(container, jti))
            revoke_tasks.append((container, service, task))

    for container, service, task in revoke_tasks:
        revoke_ms, err = await task
        key = f"{container}:{service}"
        result.revoke_times_ms[key] = revoke_ms
        if err:
            result.errors.append(f"Revoke failed {key}: {err}")

    return result


def compute_aggregates(results: List[RunResult]) -> dict:
    """Compute aggregate statistics across all runs."""
    all_setup = []
    all_revoke = []
    all_rtt = []
    total_errors = 0

    for r in results:
        all_setup.extend(r.setup_times_ms.values())
        all_revoke.extend(r.revoke_times_ms.values())
        all_rtt.extend(r.rtts_ms.values())
        total_errors += len(r.errors)

    def stats(values: List[float]) -> dict:
        if not values:
            return {"count": 0, "mean": 0, "min": 0, "max": 0, "p95": 0}
        values_sorted = sorted(values)
        n = len(values_sorted)
        p95_idx = int(n * 0.95)
        return {
            "count": n,
            "mean": round(sum(values) / n, 3),
            "min": round(min(values), 3),
            "max": round(max(values), 3),
            "p95": round(values_sorted[min(p95_idx, n - 1)], 3),
        }

    return {
        "setup_ms": stats(all_setup),
        "revoke_ms": stats(all_revoke),
        "rtt_ms": stats(all_rtt),
        "total_errors": total_errors,
        "total_runs": len(results),
    }


def save_report(mode: str, results: List[RunResult], aggregates: dict):
    """Save experiment report to JSON."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    path = REPORTS_DIR / f"scale_10_5_{mode}_{ts}.json"

    payload = {
        "scale": {"users": 10, "services": 5},
        "mode": mode,
        "load_pattern": {
            str(k): [SERVICES[i] for i in v]
            for k, v in LOAD_PATTERNS[mode].items()
        },
        "aggregates": aggregates,
        "runs": [
            {
                "run_id": r.run_id,
                "setup_times_ms": r.setup_times_ms,
                "revoke_times_ms": r.revoke_times_ms,
                "rtts_ms": r.rtts_ms,
                "errors": r.errors,
            }
            for r in results
        ],
    }

    with open(path, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"[report] Saved to {path}")
    return path


async def main():
    print("=" * 60)
    print("Direct-ZTNA Experiment: Scale 10×5")
    print("=" * 60)

    # Ensure infrastructure is up
    print("[infra] Checking containers...")
    for i in range(1, 11):
        container = f"{CONTAINER_PREFIX}{i:02d}"
        rc, _, _ = docker_exec(container, ["echo", "ok"], timeout=5)
        if rc != 0:
            print(f"[FATAL] Container {container} is not running. Run docker-compose up first.")
            sys.exit(1)
    print("[infra] All 10 client containers are up.")

    for mode in ["sparse", "boundary", "dense"]:
        print(f"\n{'='*60}")
        print(f"Mode: {mode.upper()}")
        print(f"{'='*60}")

        k_avg = sum(len(v) for v in LOAD_PATTERNS[mode].values()) / 10
        print(f"  K_avg = {k_avg:.1f} (U+S = 15)")

        results: List[RunResult] = []
        for run_id in range(1, RUNS_PER_MODE + 1):
            print(f"  Run {run_id}/{RUNS_PER_MODE} ...", end=" ", flush=True)
            result = await run_experiment_mode(mode, run_id)
            results.append(result)
            print(
                f"setup={result.setup_times_ms and sum(result.setup_times_ms.values())/len(result.setup_times_ms):.1f}ms "
                f"revoke={result.revoke_times_ms and sum(result.revoke_times_ms.values())/len(result.revoke_times_ms):.1f}ms "
                f"rtt={result.rtts_ms and sum(result.rtts_ms.values())/len(result.rtts_ms):.1f}ms "
                f"errors={len(result.errors)}"
            )

        aggregates = compute_aggregates(results)
        print(f"  Aggregate: setup_mean={aggregates['setup_ms']['mean']}ms  "
              f"revoke_mean={aggregates['revoke_ms']['mean']}ms  "
              f"rtt_mean={aggregates['rtt_ms']['mean']}ms  "
              f"errors={aggregates['total_errors']}")

        save_report(mode, results, aggregates)

    print("\n" + "=" * 60)
    print("Experiment complete.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
