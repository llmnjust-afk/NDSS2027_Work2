from __future__ import annotations

import argparse

from effectpathbench.runner import MODES, run_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the deterministic EffectPathBench harness")
    parser.add_argument("--output", default="effectpathbench-results", help="output directory")
    parser.add_argument("--adapter", choices=("reference", "agentdojo"), default="reference")
    parser.add_argument("--mode", action="append", choices=MODES, dest="modes")
    args = parser.parse_args()
    events, summaries = run_benchmark(args.output, modes=args.modes or MODES, adapter_name=args.adapter)
    print(f"wrote {len(events)} events and {len(summaries)} summary rows to {args.output}")


if __name__ == "__main__":
    main()
