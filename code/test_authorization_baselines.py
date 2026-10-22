"""Authentication edge cases for the controlled baseline comparison."""
import unittest
from dataclasses import replace

from authorization_baselines import ApprovalVerifier, NOW
from llm_threshold_prototype import ReviewDecision, ReviewGateway, canonical_json, digest, sample_authorization


class ApprovalBaselineTests(unittest.TestCase):
    def setUp(self):
        self.gateways = [ReviewGateway(f"reviewer-{i}", i, bytes([i]) * 32) for i in (1, 2, 3)]
        self.verifier = ApprovalVerifier(self.gateways)
        self.message = canonical_json(sample_authorization())
        self.envelopes = [g.attest(ReviewDecision("approve", digest(self.message), (), "fixture"), digest(self.message)) for g in self.gateways]

    def test_duplicate_does_not_reach_quorum(self):
        self.assertFalse(self.verifier.quorum(self.message, self.envelopes[:1] * 3))

    def test_forged_approval_does_not_reach_quorum(self):
        forged = replace(self.envelopes[1], authenticator="0" * 64)
        self.assertFalse(self.verifier.quorum(self.message, [self.envelopes[0], forged]))

    def test_identity_mismatch_rejected(self):
        wrong = replace(self.envelopes[1], reviewer_id="reviewer-1")
        self.assertFalse(self.verifier.quorum(self.message, [self.envelopes[0], wrong]))

    def test_action_binding_and_replay(self):
        changed = canonical_json(sample_authorization(amount=1399))
        self.assertFalse(self.verifier.execute(changed, self.envelopes[:2]))
        self.assertTrue(self.verifier.execute(self.message, self.envelopes[:2]))
        self.assertFalse(self.verifier.execute(self.message, self.envelopes[:2]))

    def test_expired_action_rejected(self):
        action = sample_authorization()
        action["expiry"] = NOW.isoformat()
        message = canonical_json(action)
        envelopes = [g.attest(ReviewDecision("approve", digest(message), (), "fixture"), digest(message)) for g in self.gateways]
        self.assertFalse(self.verifier.execute(message, envelopes))


if __name__ == "__main__":
    unittest.main()
