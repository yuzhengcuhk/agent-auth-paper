"""Independent enumeration and joint-distribution checks for the paper."""

import itertools
import math
import random
import unittest

from security_bounds import (
    binomial_tail, bounds, repeated_attempt_bound, symmetric_outcomes,
)


class SecurityBoundTests(unittest.TestCase):
    def test_tail_against_enumeration(self):
        for n in range(1, 7):
            for q in (0.0, 0.2, 0.5, 1.0):
                for k in range(n + 2):
                    expected = math.fsum(
                        math.prod(q if bit else 1 - q for bit in bits)
                        for bits in itertools.product((0, 1), repeat=n)
                        if sum(bits) >= k
                    )
                    self.assertAlmostEqual(binomial_tail(n, k, q), expected)

    def test_corruption_and_withholding_by_enumeration(self):
        for n in range(2, 7):
            for t in range(2, n + 1):
                for f in range(t):
                    q, r, p = 0.2, 0.1, 0.3
                    states = list(itertools.product((0, 1), repeat=n - f))
                    unsafe = math.fsum(
                        math.prod(q if bit else 1 - q for bit in bits)
                        for bits in states if sum(bits) + f >= t
                    )
                    valid = math.fsum(
                        math.prod(1 - r if bit else r for bit in bits)
                        for bits in states if sum(bits) >= t
                    )
                    row = bounds(n, t, f, p, q, r)
                    self.assertAlmostEqual(row["unsafe_independent_upper"], p * unsafe)
                    self.assertAlmostEqual(row["valid_completion_independent_lower"], valid)

    def test_arbitrary_joint_distributions(self):
        rng = random.Random(17)
        for n in range(2, 7):
            states = list(itertools.product((0, 1), repeat=n))
            for _ in range(10):
                weights = [rng.random() for _ in states]
                total = sum(weights)
                masses = [w / total for w in weights]
                q = max(sum(w * bits[i] for bits, w in zip(states, masses)) for i in range(n))
                for t in range(1, n + 1):
                    row = bounds(n, t, 0, 1, q, q)
                    unsafe = sum(w for bits, w in zip(states, masses) if sum(bits) >= t)
                    # Interpret the same indicators as failures to return a share.
                    valid = sum(w for bits, w in zip(states, masses) if n - sum(bits) >= t)
                    self.assertLessEqual(unsafe, row["unsafe_dependent_upper"] + 1e-12)
                    self.assertGreaterEqual(valid, row["valid_completion_dependent_lower"] - 1e-12)

    def test_sharp_dependent_bound_witness(self):
        for n in range(2, 7):
            for k in range(1, n + 1):
                q = 0.1
                error_mass = n * q / k
                subsets = list(itertools.combinations(range(n), k))
                for i in range(n):
                    marginal = sum(error_mass / len(subsets) for subset in subsets if i in subset)
                    self.assertAlmostEqual(marginal, q)
                self.assertAlmostEqual(
                    bounds(n, k, 0, 1, q, 0)["unsafe_dependent_upper"], error_mass
                )

    def test_unanimity_and_common_mode(self):
        p, q = 0.1, 0.2
        for n in range(2, 7):
            for f in range(n):
                row = bounds(n, n, f, p, q, 0.0)
                self.assertAlmostEqual(row["unsafe_independent_upper"], p * q**(n - f))
                self.assertAlmostEqual(row["unsafe_dependent_upper"], p * q)
                self.assertEqual(row["valid_completion_independent_lower"], 0.0 if f else 1.0)

    def test_symmetric_partition_and_boundary_rates(self):
        for p in (0.0, 0.1, 1.0):
            for q in (0.0, 0.2, 1.0):
                row = symmetric_outcomes(5, 3, p, q)
                self.assertAlmostEqual(sum(v for k, v in row.items() if k != "correct_decision"), 1)
                self.assertAlmostEqual(
                    row["correct_decision"], row["unsafe_blocked"] + row["valid_completed"]
                )
        self.assertEqual(bounds(3, 2, 1, 1, 0, 0)["unsafe_independent_upper"], 0.0)
        self.assertEqual(bounds(3, 2, 1, 1, 1, 0)["unsafe_independent_upper"], 1.0)

    def test_retries_and_invalid_assumptions(self):
        self.assertAlmostEqual(repeated_attempt_bound([0.1] * 3), 0.3)
        self.assertEqual(repeated_attempt_bound([0.8, 0.8]), 1.0)
        self.assertEqual(repeated_attempt_bound([]), 0.0)
        for args in ((3, 2, 2, 0.1, 0.2, 0.1), (3, 4, 0, 0.1, 0.2, 0.1),
                     (3, 2, 0, -0.1, 0.2, 0.1), (3, 2, 0, 0.1, float("nan"), 0.1)):
            with self.assertRaises(ValueError):
                bounds(*args)


if __name__ == "__main__":
    unittest.main()
