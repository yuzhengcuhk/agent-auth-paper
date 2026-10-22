"""Illustrative committee simulation for the authorization review layer.

A request is good (should be approved) or bad (should be rejected). A valid
authorization is possible iff at least t of n reviewers approve. The two
reported errors are false approval (FA) of a bad request and false rejection
(FR) of a good request.

Votes use a one-factor latent Gaussian model:

  score_i = sqrt(rho) z + sqrt(1-rho) e_i; approve iff score_i > tau.

The parameter rho is the correlation between latent scores, not the correlation
between binary errors. The latter depends on the marginal approval rate; the
simulation therefore reports its empirical value separately for each class.
This is a sensitivity analysis, not a benchmark of real agent systems.
"""
import json
from statistics import NormalDist

import numpy as np

SEED = 20260720
RNG = np.random.default_rng(SEED)
ND = NormalDist()

P_G = 0.90
P_B = 0.20
TAU_G = ND.inv_cdf(1.0 - P_G)
TAU_B = ND.inv_cdf(1.0 - P_B)
T_TRIALS = 400_000


def approval_counts(n, latent_rho, tau, trials=T_TRIALS):
    """Sample the number of approvals in each trial."""
    shared = RNG.standard_normal((trials, 1))
    idiosyncratic = RNG.standard_normal((trials, n))
    scores = np.sqrt(latent_rho) * shared + np.sqrt(1.0 - latent_rho) * idiosyncratic
    return (scores > tau).sum(axis=1)


def binary_pairwise_correlation(counts, n):
    """Estimate mean pairwise correlation from exchangeable vote counts."""
    marginal = float(np.mean(counts) / n)
    denominator = n * marginal * (1.0 - marginal)
    if n < 2 or denominator == 0:
        return 0.0
    estimate = (float(np.var(counts)) / denominator - 1.0) / (n - 1)
    return float(np.clip(estimate, -1.0, 1.0))


def rate_record(event):
    """Return an estimate and normal 95% Monte Carlo confidence interval."""
    probability = float(np.mean(event))
    half_width = 1.96 * np.sqrt(probability * (1.0 - probability) / len(event))
    return {
        "rate": probability,
        "ci95_low": max(0.0, probability - float(half_width)),
        "ci95_high": min(1.0, probability + float(half_width)),
    }


def fa_fr(n, t, latent_rho):
    bad = approval_counts(n, latent_rho, TAU_B)
    good = approval_counts(n, latent_rho, TAU_G)
    return {
        "FA": rate_record(bad >= t),
        "FR": rate_record(good < t),
        "binary_corr_bad": binary_pairwise_correlation(bad, n),
        "binary_corr_good": binary_pairwise_correlation(good, n),
    }


def panel_a(n=7, latent_rho=0.2):
    """Sweep t while reusing the same draws at a fixed latent correlation."""
    bad = approval_counts(n, latent_rho, TAU_B)
    good = approval_counts(n, latent_rho, TAU_G)
    sweep = []
    for t in range(1, n + 1):
        sweep.append({"t": t, "FA": rate_record(bad >= t), "FR": rate_record(good < t)})
    return {
        "n": n,
        "latent_rho": latent_rho,
        "binary_corr_bad": binary_pairwise_correlation(bad, n),
        "binary_corr_good": binary_pairwise_correlation(good, n),
        "sweep_t": sweep,
    }


def panel_b(n=7, t=4, latent_rhos=None):
    """Fix majority threshold and sweep the latent score correlation."""
    if latent_rhos is None:
        latent_rhos = list(np.round(np.linspace(0.0, 0.98, 25), 3))
    sweep = []
    for latent_rho in latent_rhos:
        row = fa_fr(n, t, float(latent_rho))
        row["latent_rho"] = float(latent_rho)
        sweep.append(row)
    return {
        "n": n,
        "t": t,
        "sweep_latent_rho": sweep,
        "single_reviewer": {"FA": P_B, "FR": 1.0 - P_G},
    }


def majority_vs_n(latent_rho=0.2, ns=range(3, 16)):
    output = []
    for n in ns:
        t = n // 2 + 1
        row = fa_fr(n, t, latent_rho)
        row.update({"n": n, "t": t})
        output.append(row)
    return {"latent_rho": latent_rho, "majority": output}


if __name__ == "__main__":
    results = {
        "params": {
            "P_G": P_G,
            "P_B": P_B,
            "trials_per_estimate": T_TRIALS,
            "seed": SEED,
            "model": "one-factor latent Gaussian score model",
        },
        "panel_a": panel_a(),
        "panel_b": panel_b(),
        "majority_vs_n": majority_vs_n(),
    }
    with open("results/committee.json", "w", encoding="utf-8") as output:
        json.dump(results, output, indent=2)

    print(f"single reviewer: FA={P_B:.3f}  FR={1-P_G:.3f}")
    panel = results["panel_a"]
    print(
        f"\n[n=7, latent rho=0.2; binary corr bad={panel['binary_corr_bad']:.3f}, "
        f"good={panel['binary_corr_good']:.3f}]"
    )
    for row in panel["sweep_t"]:
        print(f"t={row['t']}  FA={row['FA']['rate']:.5f}  FR={row['FR']['rate']:.5f}")
    print("\nsaved -> results/committee.json")
