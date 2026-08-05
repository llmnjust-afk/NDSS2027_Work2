import csv
import json

import pytest

from effectpathbench import CATEGORIES, MODES, build_scenarios, run_benchmark


def _all_summary(summaries, mode):
    return next(row for row in summaries if row["mode"] == mode and row["category"] == "ALL")


def test_corpus_has_two_complete_pairs_per_category():
    scenarios = build_scenarios()
    assert len(scenarios) == 28
    assert {scenario.category for scenario in scenarios} == set(CATEGORIES)
    for category in CATEGORIES:
        category_scenarios = [scenario for scenario in scenarios if scenario.category == category]
        assert len(category_scenarios) == 4
        pairs = {scenario.pair_id for scenario in category_scenarios}
        assert len(pairs) == 2
        for pair_id in pairs:
            assert {scenario.case for scenario in category_scenarios if scenario.pair_id == pair_id} == {
                "benign",
                "dangerous",
            }


def test_reference_effectguard_and_ablations(tmp_path):
    events, summaries = run_benchmark(tmp_path)
    assert len(events) == 28 * len(MODES)
    assert _all_summary(summaries, "no_defense")["final_effect_asr_rate"] == 1.0
    assert _all_summary(summaries, "effectguard")["final_effect_asr_rate"] == 0.0
    assert _all_summary(summaries, "effectguard")["false_block_rate"] == 0.0
    assert _all_summary(summaries, "effectguard")["legal_transformation_completion_rate"] == 1.0

    provenance = _all_summary(summaries, "effectguard_no_provenance")
    cardinality = _all_summary(summaries, "effectguard_no_cardinality")
    freshness = _all_summary(summaries, "effectguard_no_freshness")
    assert provenance["prohibited_effect_committed_count"] == 4
    assert cardinality["prohibited_effect_committed_count"] == 4
    assert freshness["prohibited_effect_committed_count"] == 2


def test_outputs_are_jsonl_json_and_csv(tmp_path):
    events, summaries = run_benchmark(tmp_path, modes=("effectguard",))
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == events
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == summaries
    with (tmp_path / "summary.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(CATEGORIES) + 1
    assert {"latency_p50_ns", "latency_p95_ns", "latency_p99_ns", "manifest_bytes"} <= rows[0].keys()


def test_unknown_mode_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown modes"):
        run_benchmark(tmp_path, modes=("unknown",))
