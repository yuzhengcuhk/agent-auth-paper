"""Analytical bounds for KITA, not measured agent performance.

p: unsafe-proposal probability; q: false approval conditional on unsafe input;
r: missing valid approval by deadline; f: fully corrupt reviewer domains.
Negligible cryptographic failure terms are omitted from numerical outputs.
"""

from math import comb, fsum, isfinite


def probability(value):
    if not isfinite(value) or not 0 <= value <= 1:
        raise ValueError("probabilities must be finite and in [0, 1]")
    return value


def binomial_tail(n, k, rate):
    probability(rate)
    if not isinstance(n, int) or n < 0 or not isinstance(k, int):
        raise ValueError("n must be a nonnegative integer and k an integer")
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    return min(1.0, fsum(
        comb(n, j) * rate**j * (1 - rate)**(n - j)
        for j in range(k, n + 1)
    ))


def bounds(n, t, f, p, q, r):
    if not all(isinstance(v, int) for v in (n, t, f)):
        raise ValueError("n, t, f must be integers")
    if not 0 <= f < t <= n:
        raise ValueError("the bounds require 0 <= f < t <= n")
    for value in (p, q, r):
        probability(value)
    remaining, needed = n - f, t - f
    return {
        "unsafe_independent_upper": p * binomial_tail(remaining, needed, q),
        "unsafe_dependent_upper": p * min(1.0, remaining * q / needed),
        "valid_completion_independent_lower": binomial_tail(remaining, t, 1 - r),
        "valid_completion_dependent_lower": (
            max(0.0, 1 - remaining * r / (remaining - t + 1))
            if t <= remaining else 0.0
        ),
    }


def symmetric_outcomes(n, t, p, q):
    """Idealized exact outcomes: f=0, r=q, no stalls, quorum-only acceptance."""
    record = bounds(n, t, 0, p, q, q)
    unsafe = record["unsafe_independent_upper"]
    valid = (1 - p) * record["valid_completion_independent_lower"]
    return {
        "unsafe_accepted": unsafe,
        "unsafe_blocked": p - unsafe,
        "valid_completed": valid,
        "valid_blocked": (1 - p) - valid,
        "correct_decision": valid + p - unsafe,
    }


def repeated_attempt_bound(per_attempt_bounds):
    """Union bound, requiring the assumptions after every prior history."""
    return min(1.0, fsum(probability(value) for value in per_attempt_bounds))


if __name__ == "__main__":
    print("Illustrative bounds: p=0.1, q=0.2, r=0.1; no measured rates.")
    print("Unsafe: corrupt domains sign. Completion: corrupt domains withhold.")
    print("n t f | unsafe independent | unsafe dependent | valid completion")
    for n, t, f in ((3, 2, 0), (3, 3, 0), (3, 2, 1), (3, 3, 1), (5, 3, 1)):
        row = bounds(n, t, f, 0.1, 0.2, 0.1)
        print(
            f"{n} {t} {f} | {row['unsafe_independent_upper']:.5f}"
            f" | {row['unsafe_dependent_upper']:.5f}"
            f" | {row['valid_completion_independent_lower']:.5f}"
        )
