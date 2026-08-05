"""Deterministic, CPU-only benchmark for effect-path authorization."""

from effectpathbench.runner import MODES, run_benchmark
from effectpathbench.scenarios import CATEGORIES, build_scenarios

__all__ = ["CATEGORIES", "MODES", "build_scenarios", "run_benchmark"]
