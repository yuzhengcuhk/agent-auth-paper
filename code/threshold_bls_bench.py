"""Threshold-BLS reference implementation and microbenchmark (BLS12-381).

The prototype instantiates the paper's signing layer with dealer-generated
Shamir shares. The architecture calls for DKG in deployment; this small
prototype deliberately does not implement or benchmark DKG/VSS.

It implements:
  * non-interactive partial signatures sigma_i = sk_i * H(m) in G1;
  * verification of each partial against an authenticated public share;
  * Lagrange-in-the-exponent aggregation; and
  * final BLS verification against the group public key.

py_ecc is a pure-Python reference library. Absolute timings are not claims
about a production implementation. The seeded PRNG is used only to make the
benchmark repeatable and must not be used for key generation in deployment.
"""
import hashlib
import importlib.metadata
import json
import platform
import random
import statistics
import sys
import time

from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.point_compression import compress_G1, compress_G2
from py_ecc.optimized_bls12_381 import (
    G2,
    add,
    curve_order,
    field_modulus,
    multiply,
    pairing,
)

DST = b"AGENTAUTH_BLS12381G1_XMD:SHA-256_SSWU_RO_"
SEED = 7
RNG = random.Random(SEED)
REPS_FAST = 25
REPS_SLOW = 5


def rand_scalar():
    return RNG.randrange(1, curve_order)


def poly_eval(coeffs, x):
    """Evaluate a polynomial modulo the BLS scalar-field order."""
    acc, xp = 0, 1
    for coefficient in coeffs:
        acc = (acc + coefficient * xp) % curve_order
        xp = (xp * x) % curve_order
    return acc


def shamir_share(secret, t, n):
    """Dealer-generate n evaluations of a degree-(t-1) polynomial."""
    coefficients = [secret] + [rand_scalar() for _ in range(t - 1)]
    return {i: poly_eval(coefficients, i) for i in range(1, n + 1)}


def lagrange_at_zero(indices):
    """Coefficients lambda_i such that sum lambda_i f(i) = f(0)."""
    coefficients = {}
    for i in indices:
        numerator, denominator = 1, 1
        for j in indices:
            if j == i:
                continue
            numerator = (numerator * (-j)) % curve_order
            denominator = (denominator * (i - j)) % curve_order
        coefficients[i] = (numerator * pow(denominator, -1, curve_order)) % curve_order
    return coefficients


def hash_to_point(message):
    return hash_to_G1(message, DST, hashlib.sha256)


def milliseconds(samples):
    values = [1e3 * value for value in samples]
    return {
        "mean": round(statistics.fmean(values), 3),
        "median": round(statistics.median(values), 3),
        "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
        "repetitions": len(values),
    }


def verify_partial(public_share, message_point, partial):
    """Verify one share before admitting it to the interpolation set."""
    return pairing(G2, partial) == pairing(public_share, message_point)


def bench_config(n, t, reps_fast=REPS_FAST, reps_slow=REPS_SLOW):
    message = f"authorize-order:{n}:{t}".encode()
    secret = rand_scalar()
    public_key = multiply(G2, secret)
    shares = shamir_share(secret, t, n)
    public_shares = {i: multiply(G2, share) for i, share in shares.items()}
    message_point = hash_to_point(message)
    signer_set = list(range(1, t + 1))

    samples = []
    for _ in range(reps_fast):
        start = time.perf_counter()
        multiply(message_point, shares[signer_set[0]])
        samples.append(time.perf_counter() - start)
    partial_sign = milliseconds(samples)

    partials = {i: multiply(message_point, shares[i]) for i in signer_set}

    samples = []
    for _ in range(reps_slow):
        start = time.perf_counter()
        ok = verify_partial(
            public_shares[signer_set[0]], message_point, partials[signer_set[0]]
        )
        samples.append(time.perf_counter() - start)
        assert ok
    partial_verify = milliseconds(samples)

    malformed = multiply(message_point, (shares[signer_set[0]] + 1) % curve_order)
    assert not verify_partial(public_shares[signer_set[0]], message_point, malformed)

    # Only valid shares enter the interpolation set.
    assert all(
        verify_partial(public_shares[i], message_point, partials[i]) for i in signer_set
    )
    samples = []
    aggregate = None
    for _ in range(reps_fast):
        start = time.perf_counter()
        coefficients = lagrange_at_zero(signer_set)
        aggregate = None
        for i in signer_set:
            term = multiply(partials[i], coefficients[i])
            aggregate = term if aggregate is None else add(aggregate, term)
        samples.append(time.perf_counter() - start)
    aggregate_stats = milliseconds(samples)

    assert pairing(G2, aggregate) == pairing(public_key, message_point)
    samples = []
    for _ in range(reps_slow):
        start = time.perf_counter()
        ok = pairing(G2, aggregate) == pairing(public_key, message_point)
        samples.append(time.perf_counter() - start)
        assert ok
    final_verify = milliseconds(samples)

    # Derive encoded sizes from the compressed point representations.
    field_bytes = (field_modulus.bit_length() + 7) // 8
    compressed_signature = compress_G1(aggregate)
    compressed_public_key = compress_G2(public_key)
    signature_bytes = len(compressed_signature.to_bytes(field_bytes, "big"))
    public_key_bytes = sum(
        len(component.to_bytes(field_bytes, "big"))
        for component in compressed_public_key
    )

    return {
        "n": n,
        "t": t,
        "partial_sign_ms": partial_sign,
        "partial_verify_ms": partial_verify,
        "aggregate_ms": aggregate_stats,
        "final_verify_ms": final_verify,
        "signature_bytes": signature_bytes,
        "partial_signature_bytes": signature_bytes,
        "public_key_bytes": public_key_bytes,
        "signing_rounds": 1,
        "malformed_partial_rejected": True,
    }


if __name__ == "__main__":
    configurations = [(3, 2), (5, 3), (7, 5), (10, 7), (16, 11), (24, 17), (32, 22)]
    rows = [bench_config(n, t) for n, t in configurations]
    results = {
        "implementation": "py_ecc pure-Python reference implementation",
        "setup": "dealer-generated Shamir shares (DKG/VSS not implemented)",
        "rng": f"deterministic benchmark-only PRNG, seed={SEED}",
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "py_ecc": importlib.metadata.version("py-ecc"),
        },
        "rows": rows,
    }
    for row in rows:
        print(
            f"n={row['n']:2d} t={row['t']:2d}  "
            f"sign={row['partial_sign_ms']['mean']:.3f} ms  "
            f"partial-verify={row['partial_verify_ms']['mean']:.3f} ms  "
            f"aggregate={row['aggregate_ms']['mean']:.3f} ms  "
            f"final-verify={row['final_verify_ms']['mean']:.3f} ms"
        )
    with open("results/bls_bench.json", "w", encoding="utf-8") as output:
        json.dump(results, output, indent=2)
    print("\nsaved -> results/bls_bench.json")
