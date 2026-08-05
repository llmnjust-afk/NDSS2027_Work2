# EffectPathBench

EffectPathBench is a deterministic, CPU-only harness for authorization checks across transformations between an agent-generated call and its committed effects. It performs no network access, needs no credentials, and uses only the Python standard library. The initial corpus has two paired benign/dangerous cases for each of seven categories (28 scenarios total): redirect, retry/fallback, argument normalization, serialization/type coercion, wrapper expansion, agent/tool handoff, and stale approval.

Run all seven defense modes:

```bash
python -m effectpathbench --output /tmp/effectpathbench-results
```

Run selected modes or the external adapter:

```bash
python -m effectpathbench --mode effectguard --mode effectguard_no_freshness --output /tmp/effectpathbench-results
python -m effectpathbench --adapter agentdojo --output /tmp/effectpathbench-results
```

The external adapter first uses `agentdojo.effectguard.evaluate(request)` when available. The request is a JSON-compatible mapping containing `manifest`, `generated_call`, `final_effects`, `transformation_path`, `current_tick`, and benchmark metadata, and the API may return a boolean or `{"allowed": bool, "reason": str}`. It also supports the current `AuthorizationManifest`/`EffectPolicy` API directly, including ablations through manifest and candidate construction. The default reference adapter remains self-contained and models semantic, provenance, cardinality, and freshness controls.

Outputs are replaced on each run. `events.jsonl` contains one raw record per scenario and mode. `summary.json` and `summary.csv` contain per-mode/per-category rows plus `ALL` aggregate rows. Rates use dangerous scenarios as the denominator for committed-effect ASR and prevention, benign scenarios for false blocks and legal completion, and all scenarios for generated/initial-call metrics. Latencies measure only adapter decision time with `perf_counter_ns`; timing values are inherently machine-dependent, while scenarios and decisions remain deterministic. `manifest_bytes` is the canonical compact UTF-8 JSON size of the approval manifest.
