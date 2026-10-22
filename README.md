# KITA: Key-Isolated Threshold Authorization for LLM Agents

Research artifact for *From Review to Authorization: Key-Isolated Threshold
Signing for LLM Agents* by Yu Zheng and Qizhi Zhang.

KITA separates LLM review from signing authority. Reviewers return structured
decisions; isolated signer services release threshold-BLS shares only for
authenticated approvals of the same canonical action; and an executor accepts
the action only after final-signature, expiry, and replay checks. The proposer
holds no signing share, so the execution path cannot bypass the configured
reviewer quorum.

This repository contains the paper source, executable prototype, deterministic
system tests, analytical security calculations, controlled authorization
baselines, a seeded committee simulation, a threshold-BLS microbenchmark, and
the checked-in result artifacts used to produce the figures.

## Quick start

Python 3.9 or newer is required. The default workflow is offline and makes no
model or network calls after dependencies are installed.

```bash
make setup
make test
make check-artifacts
```

To regenerate all code artifacts and figures:

```bash
make results
```

Timing fields in `results/bls_bench.json` will vary by machine. See the
[experiment guide](docs/EXPERIMENTS.md) for individual commands, artifact
semantics, determinism, and optional live-model backends.

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
docs/EXPERIMENTS.md                experiment-to-artifact map and scope
results/                            checked-in JSON artifact snapshot
figures/                            paper figures generated from the snapshot
scripts/check_artifacts.py          artifact structure/invariant validation
main.tex                            preprint paper source
anonymous_workshop.tex              double-blind workshop wrapper
infpriv_final.tex                    InfPriv camera-ready wrapper
requirements.txt                    minimal direct Python dependencies
requirements-lock.txt               fully pinned reproduction environment
```

## Main claims exercised by the artifact

- Exact-action and evidence binding through canonical encoding and digests.
- Authenticated, distinct reviewer approvals before signature-share release.
- Threshold combination with partial-signature verification.
- Rejection of malformed shares, substitutions, expired actions, and replay.
- Analytical unsafe-authorization and valid-completion bounds under both
  independent errors and arbitrary dependence.
- Sensitivity of committee false approvals and false rejections to threshold,
  committee size, and correlated reviewer errors.

The scripted decisions, injected faults, and simulated error rates are fixtures
for testing mechanisms and assumptions. They are not measurements of real LLM
review quality, production isolation, or attack frequency.

## Build the paper

A TeX distribution with `pdflatex`, `bibtex`, and the packages required by the
NeurIPS style is needed.

```bash
make paper       # main.pdf
make workshop    # anonymous_workshop.pdf
make infpriv     # infpriv_final.pdf
```

The three entry points reuse `main.tex`. The included NeurIPS style is the
author-kit style used by this manuscript.

## Prototype scope

The implementation is an executable research prototype, not a production
authorization service. Signer isolation and authenticated channels are modeled
inside one process. Test setup uses deterministic dealer-generated Shamir
shares rather than production DKG/VSS. Deployment additionally requires
separate protected signer domains, authenticated policy and key provisioning,
durable decision/replay state, request-level attempt controls, key rotation,
monitoring, and application-specific integration.

## Publishing hygiene

`.gitignore` excludes virtual environments, LaTeX build products, scratch
directories, release bundles, local environment files, and live-model outputs.
The checked-in trace intentionally omits signing shares and approval-channel
keys. Still inspect any new live-model trace or evidence before committing it.

## Citation and license

Citation metadata is in [CITATION.cff](CITATION.cff). The code and artifact
packaging are released under the [MIT License](LICENSE). Third-party style files
and dependencies remain subject to their respective licenses.
