"""Controlled authorization fault injection; no live LLMs or measured error rates.

All keys and decisions are deterministic fixtures. BLS operations are executed
using the existing prototype. Direct approval verification uses its HMAC channel
model, with V trusted. Deliberate private-field access models domain compromise;
it is not an exploit or a test of operating-system isolation.
"""

import argparse
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

from py_ecc.optimized_bls12_381 import G2, multiply

from llm_threshold_prototype import (
    ReviewDecision, ScriptedReviewer, VerifierExecutor, build_committee,
    canonical_json, digest, hash_to_point, sample_authorization,
)


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
DESIGNS = ("agent_key", "central_signer", "direct_approvals", "kita")


class ApprovalVerifier:
    """Checks distinct, authenticated approvals on the exact action."""

    def __init__(self, gateways, threshold=2):
        self.credentials = {
            g.signer_index: (g.reviewer_id, g.channel_key) for g in gateways
        }
        self.threshold = threshold
        self.spent = set()

    def quorum(self, message, envelopes):
        indices = set()
        for envelope in envelopes:
            credential = self.credentials.get(envelope.signer_index)
            if credential is None:
                continue
            reviewer_id, channel_key = credential
            expected = hmac.new(
                channel_key, envelope.authenticated_bytes(), hashlib.sha256
            ).hexdigest()
            if (envelope.reviewer_id == reviewer_id
                    and envelope.outcome == "approve"
                    and envelope.message_digest == digest(message)
                    and hmac.compare_digest(expected, envelope.authenticator)):
                indices.add(envelope.signer_index)
        return len(indices) >= self.threshold

    def execute(self, message, envelopes):
        if not self.quorum(message, envelopes):
            return False
        action = json.loads(message)
        expiry = datetime.fromisoformat(action["expiry"].replace("Z", "+00:00"))
        if expiry <= NOW or action["nonce"] in self.spent:
            return False
        self.spent.add(action["nonce"])
        return True


def run_case(name, approvals=(), custody_breach=False, substitute=False, replay=False):
    committee, combiner, kita_verifier = build_committee(
        [ScriptedReviewer("reject") for _ in range(3)], threshold=2, seed=17
    )
    gateways = [gateway for _, gateway, _ in committee]
    direct = ApprovalVerifier(gateways)
    central_gate = ApprovalVerifier(gateways)
    # Two independent full-key fixtures for the agent and central-signer designs.
    agent_secret, central_secret = 101, 211
    agent_verifier = VerifierExecutor(multiply(G2, agent_secret), NOW)
    central_verifier = VerifierExecutor(multiply(G2, central_secret), NOW)
    original = canonical_json(sample_authorization(nonce=name))
    submitted = canonical_json(sample_authorization(amount=1399, nonce=name)) if substitute else original
    envelopes, shares = [], []
    for _, gateway, signer in committee:
        if gateway.signer_index in approvals:
            decision = ReviewDecision("approve", digest(original), (), "Fixture approval")
            envelope = gateway.attest(decision, digest(original))
            envelopes.append(envelope)
            shares.append((signer.signer_index, signer.sign(original, envelope)))

    if custody_breach:
        # In direct approvals, one reviewer credential is exposed; in KITA,
        # one entire reviewer-signer domain is exposed. Central custody exposes
        # the complete execution key. The trusted V is never compromised.
        _, compromised_gateway, compromised_signer = committee[0]
        envelope = compromised_gateway.attest(
            ReviewDecision("approve", digest(submitted), (), "Injected credential breach"),
            digest(submitted),
        )
        envelopes.append(envelope)
        shares.append((1, multiply(hash_to_point(submitted), compromised_signer._signing_key_share)))

    agent_sig = multiply(hash_to_point(submitted), agent_secret)
    central_sig = None
    if custody_breach or central_gate.quorum(submitted, envelopes):
        central_sig = multiply(hash_to_point(submitted), central_secret)
    kita_sig, indices = combiner.combine(submitted, shares)

    def execute():
        return dict(zip(DESIGNS, (
            agent_verifier.execute(submitted, agent_sig),
            central_verifier.execute(submitted, central_sig),
            direct.execute(submitted, envelopes),
            kita_verifier.execute(submitted, kita_sig),
        )))

    first = execute()
    if replay and not all(first.values()):
        raise AssertionError("Replay scenario must first execute successfully in every design")
    observed = execute() if replay else first
    return {
        "scenario": name, "approval_indices": list(approvals),
        "custody_breach": custody_breach, "action_substitution": substitute,
        "replay": replay, "accepted": observed,
        "first_execution": first, "kita_valid_indices": list(indices),
    }


def run_experiment():
    # Unsafe scenarios use an externally assigned semantic label, e.g. renewed
    # product despite a new-only requirement. All payment fields pass the same
    # structural constraints. Review outcomes are deliberately injected.
    cases = [
        ("valid_two_approvals", {"approvals": (1, 2)}, (True, True, True, True)),
        ("unsafe_no_approval", {}, (True, False, False, False)),
        ("unsafe_one_false_approval", {"approvals": (1,)}, (True, False, False, False)),
        ("unsafe_two_false_approvals", {"approvals": (1, 2)}, (True, True, True, True)),
        ("one_custody_domain_breached", {"custody_breach": True}, (True, True, False, False)),
        ("post_review_substitution", {"approvals": (1, 2), "substitute": True}, (True, False, False, False)),
        ("replay", {"approvals": (1, 2), "replay": True}, (False, False, False, False)),
    ]
    records = []
    for name, options, expected in cases:
        record = run_case(name, **options)
        record["expected"] = dict(zip(DESIGNS, expected))
        record["matches_expected"] = record["accepted"] == record["expected"]
        if not record["matches_expected"]:
            raise AssertionError(record)
        records.append(record)
    return {
        "experiment": "controlled authorization-boundary fault injection",
        "reviewer_backend": "scripted decisions; no model calls",
        "threshold": 2, "committee_size": 3,
        "design_scenario_checks": len(records) * len(DESIGNS),
        "all_expected_outcomes_observed": all(r["matches_expected"] for r in records),
        "scope": "In-process fixtures with real BLS and HMAC checks; no isolation exploit, model-risk estimate, or latency comparison.",
        "cases": records,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results/authorization_baselines.json"))
    args = parser.parse_args()
    result = run_experiment()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
