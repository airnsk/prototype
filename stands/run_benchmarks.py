#!/usr/bin/env python3
"""
Многократные прогоны экспериментов для статистики (mean, min, max, P95).

Для каждого стенда:
  1. Поднимаем docker-compose
  2. Запускаем exposure_experiment.py (1 раз)
  3. Запускаем experiment.py N_RUNS раз, собирая report.json
  4. Опускаем стенд
  5. Вычисляем агрегаты
"""

import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

N_RUNS = 10

STANDS = {
    "direct": {
        "compose": Path(__file__).parent / "direct" / "docker-compose.yml",
        "experiment": Path(__file__).parent / "direct" / "experiment.py",
        "exposure": Path(__file__).parent / "direct" / "exposure_experiment.py",
    },
    "gateway": {
        "compose": Path(__file__).parent / "gateway" / "docker-compose.yml",
        "experiment": Path(__file__).parent / "gateway" / "experiment.py",
        "exposure": Path(__file__).parent / "gateway" / "exposure_experiment.py",
    },
    "vpn": {
        "compose": Path(__file__).parent / "vpn" / "docker-compose.yml",
        "experiment": Path(__file__).parent / "vpn" / "experiment.py",
        "exposure": Path(__file__).parent / "vpn" / "exposure_experiment.py",
    },
}


def docker_compose(compose_file: Path, *args):
    inner = shlex.join(["docker-compose", "-f", str(compose_file), *args])
    cmd = ["sg", "docker", "-c", inner]
    subprocess.run(cmd, check=True, capture_output=True)


def run_python(script: Path):
    result = subprocess.run(
        ["python3", str(script)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"ERROR running {script}: {result.stderr}", file=sys.stderr)
    return result.returncode == 0


def read_report(script: Path, report_name: str = "report.json") -> dict:
    report_path = script.parent / report_name
    with open(report_path) as f:
        return json.load(f)


def compute_stats(values: list[float]) -> dict:
    if not values:
        return {"mean": 0, "min": 0, "max": 0, "p95": 0, "count": 0}
    values_sorted = sorted(values)
    n = len(values_sorted)
    p95_idx = int(n * 0.95)
    return {
        "mean": round(sum(values) / n, 3),
        "min": round(min(values), 3),
        "max": round(max(values), 3),
        "p95": round(values_sorted[min(p95_idx, n - 1)], 3),
        "count": n,
    }


def benchmark_stand(name: str, info: dict) -> dict:
    print(f"\n{'='*60}")
    print(f"Benchmarking: {name.upper()}")
    print(f"{'='*60}")

    # Bring up
    print(f"  [infra] Bringing up...")
    docker_compose(info["compose"], "up", "-d", "--force-recreate")

    # Run exposure once
    print(f"  [exposure] Running...")
    run_python(info["exposure"])
    exposure_report = read_report(info["exposure"], "exposure_report.json")

    # Run main experiment N times
    print(f"  [experiment] Running {N_RUNS} times...")
    results = []
    for i in range(1, N_RUNS + 1):
        ok = run_python(info["experiment"])
        if not ok:
            print(f"    Run {i}/{N_RUNS} FAILED, skipping")
            continue
        report = read_report(info["experiment"])
        results.append(report)
        t_setup = report["timing"]["t_setup_ms"]
        t_revoke = report["timing"]["t_revoke_ms"]
        rtt = report["timing"]["rtt_ms"].get("mean")
        rtt_str = f"{rtt:.1f}ms" if rtt is not None else "N/A"
        print(f"    Run {i}/{N_RUNS}: setup={t_setup:.0f}ms revoke={t_revoke:.0f}ms rtt={rtt_str}")

    # Tear down
    print(f"  [infra] Tearing down...")
    docker_compose(info["compose"], "down")

    # Aggregates
    t_setups = [r["timing"]["t_setup_ms"] for r in results]
    t_revokes = [r["timing"]["t_revoke_ms"] for r in results]
    rtts = [r["timing"]["rtt_ms"]["mean"] for r in results if r["timing"]["rtt_ms"].get("mean")]

    aggregates = {
        "t_setup_ms": compute_stats(t_setups),
        "t_revoke_ms": compute_stats(t_revokes),
        "rtt_ms": compute_stats(rtts),
    }

    print(f"  Aggregates:")
    print(f"    T_setup:  mean={aggregates['t_setup_ms']['mean']}  p95={aggregates['t_setup_ms']['p95']}  max={aggregates['t_setup_ms']['max']}")
    print(f"    T_revoke: mean={aggregates['t_revoke_ms']['mean']}  p95={aggregates['t_revoke_ms']['p95']}  max={aggregates['t_revoke_ms']['max']}")
    print(f"    RTT:      mean={aggregates['rtt_ms']['mean']}  p95={aggregates['rtt_ms']['p95']}  max={aggregates['rtt_ms']['max']}")

    return {
        "architecture": name,
        "runs": N_RUNS,
        "successful_runs": len(results),
        "exposure": exposure_report.get("phases", {}),
        "aggregates": aggregates,
        "raw_results": results,
    }


def main():
    all_results = {}
    for name, info in STANDS.items():
        all_results[name] = benchmark_stand(name, info)

    report_path = Path(__file__).parent / "benchmark_report.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"Benchmark complete. Report saved to {report_path}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
