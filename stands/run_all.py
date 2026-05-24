#!/usr/bin/env python3
"""
Запуск всех трёх сравнительных экспериментов.
"""

import json
import subprocess
import sys
from pathlib import Path

STANDS = ["direct", "vpn", "gateway"]

def run_stand(name: str):
    print(f"\n{'='*60}")
    print(f"Running {name.upper()} stand")
    print(f"{'='*60}")
    compose_file = Path(__file__).parent / name / "docker-compose.yml"
    exp_file = Path(__file__).parent / name / "experiment.py"

    # Bring up
    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "up", "-d"],
        check=True,
    )
    # Run experiment
    result = subprocess.run(
        ["python3", str(exp_file)],
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"ERROR: {result.stderr}", file=sys.stderr)
    # Tear down
    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "down"],
        check=True,
    )


def main():
    for stand in STANDS:
        run_stand(stand)

    print("\n" + "=" * 60)
    print("All stands completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()
