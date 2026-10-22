# KITA: Key-Isolated Threshold Authorization for LLM Agents

Code and experiment artifact for *From Review to Authorization: Key-Isolated
Threshold Signing for LLM Agents* by Yu Zheng and Qizhi Zhang.

KITA separates LLM review from signing authority. Reviewers return structured
decisions; isolated signer services release threshold-BLS shares only for
authenticated approvals of the same canonical action; and an executor accepts
the action only after final-signature, expiry, and replay checks.

This repository intentionally contains the experiment artifact only. The paper
source is not included.

## Quick start

Python 3.9 or newer is required. The default workflow is offline after
dependencies are installed.

```bash
make setup
make test
make check-artifacts
```

Regenerate all offline experiment artifacts and figures with:

```bash
make results
```

See [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) for the experiment-to-artifact
map, interpretation, determinism, and optional live-model backends.

## Repository layout

```text
code/
  llm_threshold_prototype.py       reviewer -> signer -> executor prototype
  authorization_baselines.py       controlled four-design fault injection
  security_bounds.py               analytical safety/availability bounds
  committee_sim.py                 correlated-error sensitivity simulation
  threshold_bls_bench.py           threshold-BLS reference microbenchmark
  plot_figures.py                  figure generation from JSON artifacts
  test_*.py                        unit and integration tests
docs/EXPERIMENTS.md                reproduction guide and scope
results/                            checked-in JSON artifact snapshot
figures/                            figures generated from the JSON snapshot
scripts/check_artifacts.py          artifact structure/invariant validation
requirements.txt                    minimal direct dependencies
requirements-lock.txt               fully pinned reproduction environment
```

## What the artifact validates

- Exact-action and evidence binding through canonical encoding and digests.
- Authenticated, distinct reviewer approvals before signature-share release.
- Threshold combination with partial-signature verification.
- Rejection of malformed shares, substitutions, expired actions, and replay.
- Analytical safety and completion bounds under independent or dependent errors.
- Committee sensitivity to threshold, size, and correlated reviewer errors.

Scripted decisions, injected faults, and simulated rates are controlled fixtures,
not measurements of production LLM quality, isolation, or attack frequency.
The implementation models signer isolation and authenticated channels in one
process and uses deterministic dealer-generated Shamir shares for test setup.

## Citation and license

Citation metadata is in [CITATION.cff](CITATION.cff). The code and artifact are
released under the [MIT License](LICENSE).
