"""Validate the structure and core invariants of checked-in result artifacts."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def load(name: str):
    path = RESULTS / name
    if not path.is_file():
        raise AssertionError(f"missing artifact: {path.relative_to(ROOT)}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    system = load("llm_system_test.json")
    assert system["tests_passed"] == system["tests_total"]

    trace = load("full_system_trace.json")
    assert trace["step_3_reviewer_prompt"]["signing_secrets_present"] is False
    assert trace["step_7_verify_and_execute"][
        "final_signature_valid_and_first_execution_accepted"
    ] is True
    assert trace["step_7_verify_and_execute"]["same_nonce_replay_accepted"] is False

    baselines = load("authorization_baselines.json")
    assert baselines["all_expected_outcomes_observed"] is True
    assert baselines["design_scenario_checks"] == 28

    committee = load("committee.json")
    assert committee["params"]["seed"] == 20260720
    assert len(committee["panel_a"]["sweep_t"]) == committee["panel_a"]["n"]

    bench = load("bls_bench.json")
    assert bench["rows"]
    assert all(row["malformed_partial_rejected"] for row in bench["rows"])
    assert all(row["signature_bytes"] == 48 for row in bench["rows"])

    print("validated 5 checked-in result artifacts")


if __name__ == "__main__":
    main()
