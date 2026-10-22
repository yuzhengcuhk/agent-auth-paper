# Experiment guide

All commands below run from the repository root. Checked-in JSON files are the
paper's artifact snapshot; regenerating them may update runtime metadata or
timings. The experiments do not require network access unless a live LLM backend
is selected explicitly.

| Experiment | Command | Output | Interpretation |
| --- | --- | --- | --- |
| Authorization invariants | `make demo` | `results/llm_system_test.json` | Deterministic in-process system tests with scripted reviewer decisions. |
| Inspectable protocol trace | `make trace` | `results/full_system_trace.json` | Canonical action, review inputs/outputs, signing gates, combination, verification, and replay check. Secrets are intentionally omitted. |
| Authorization baselines | `make baselines` | `results/authorization_baselines.json` | Controlled fault injection across four authorization designs. Decisions and compromises are fixtures, not measured rates or real exploits. |
| Security bounds | `make bounds` | terminal output | Analytical unsafe-authorization and valid-completion examples. |
| Committee sensitivity | `make simulate` | `results/committee.json` | Seeded Monte Carlo sweep under a one-factor latent Gaussian error model. It is not a measurement of LLM reviewer quality. |
| Threshold-BLS microbenchmark | `make bench` | `results/bls_bench.json` | Pure-Python BLS12-381 timings. Absolute timings depend on the machine and are not production-performance claims. |
| Paper figures | `make figures` | `figures/*.pdf` | Renders the committee and cryptographic scaling figures from checked-in JSON. |

Run all offline experiments and validate their output structure with:

```bash
make results
make check-artifacts
```

Run the complete unit and integration test suite with `make test`. The tests
cover canonical encoding, exact-action and evidence binding, authenticated
approval gating, malformed or duplicate approvals, signature-share validation,
threshold combination, expiry, and replay rejection.

## Reproducibility classes

- `llm_system_test.json`, `full_system_trace.json`,
  `authorization_baselines.json`, and `committee.json` are deterministic for the
  checked-in code and seeds.
- `bls_bench.json` records the Python, platform, package version, repetition
  counts, and timing summaries. Its correctness checks are deterministic, but
  its timing values naturally vary.
- `llm_codex_demo.json` is a preserved live-model example. It requires a Codex
  login to regenerate and should not be treated as a deterministic benchmark.
- Files matching `results/llm_live_*.json` are ignored because prompts or model
  output may contain sensitive evidence.

## Optional live backends

OpenAI Responses API:

```bash
OPENAI_API_KEY=... OPENAI_MODEL=gpt-5-mini \
  .venv/bin/python code/llm_threshold_prototype.py \
  --backend openai --output results/llm_live_demo.json
```

Codex CLI reviewers:

```bash
.venv/bin/python code/llm_threshold_prototype.py \
  --backend codex --model gpt-5.6-sol --reasoning-effort medium \
  --output results/llm_codex_demo.json
```

The adapters request structured decisions and do not provide signing shares or
approval-channel keys to the model. Inspect all evidence and generated output
before publishing a live run.

## Scope

This is a research prototype. Signer isolation and authenticated channels are
modeled within one process, and test keys use deterministic dealer-generated
Shamir shares. Production use requires separate protected signer domains,
authenticated provisioning, DKG/VSS, durable state, policy registration,
attempt controls, key rotation, monitoring, and application-specific integration.

