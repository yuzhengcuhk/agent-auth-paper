"""Unit and integration tests for the LLM-threshold authorization prototype."""

import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from llm_threshold_prototype import (
    ApprovalEnvelope,
    CodexCLIReviewer,
    OpenAIResponsesReviewer,
    ReviewDecision,
    ReviewGateway,
    ScriptedReviewer,
    SignerService,
    authorize,
    build_committee,
    canonical_json,
    default_evidence,
    default_policy,
    digest,
    run_full_trace,
    run_system_tests,
    sample_authorization,
)


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class PrototypeTests(unittest.TestCase):
    def test_canonical_json_is_order_independent(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), canonical_json({"a": 1, "b": 2}))

    def test_all_reported_system_tests_pass(self):
        result = run_system_tests()
        self.assertEqual(result["tests_passed"], result["tests_total"])
        self.assertEqual(result["tests_total"], 6)

    def test_gateway_authenticates_only_matching_approval(self):
        gateway = ReviewGateway("reviewer-1", 1, b"a" * 32)
        expected = "1" * 64
        approved = ReviewDecision("approve", expected, (), "ok")
        rejected = ReviewDecision("reject", expected, (), "no")
        wrong = ReviewDecision("approve", "2" * 64, (), "wrong object")
        self.assertIsNotNone(gateway.attest(approved, expected))
        self.assertIsNone(gateway.attest(rejected, expected))
        self.assertIsNone(gateway.attest(wrong, expected))

    def test_signer_rejects_tampered_authenticated_envelope(self):
        message = canonical_json({"nonce": "n", "expiry": "2030-01-01T00:00:00Z"})
        gateway = ReviewGateway("reviewer-1", 1, b"b" * 32)
        signer = SignerService("reviewer-1", 1, 7, b"b" * 32)
        envelope = gateway.attest(ReviewDecision("approve", digest(message), (), "ok"), digest(message))
        self.assertIsNotNone(signer.sign(message, envelope))
        tampered = ApprovalEnvelope(
            reviewer_id=envelope.reviewer_id,
            signer_index=envelope.signer_index,
            message_digest="0" * 64,
            outcome=envelope.outcome,
            authenticator=envelope.authenticator,
        )
        self.assertIsNone(signer.sign(message, tampered))

    def test_openai_adapter_requests_strict_structured_output(self):
        captured = {}

        def fake_transport(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            output = {
                "outcome": "approve",
                "message_digest": "a" * 64,
                "reason_codes": ["WITHIN_POLICY"],
                "rationale": "The action satisfies the supplied constraints.",
            }
            return FakeHTTPResponse({"output_text": json.dumps(output)})

        reviewer = OpenAIResponsesReviewer(
            "reviewer-1", "test-model", api_key="test-key", transport=fake_transport
        )
        decision = reviewer.review({"message_digest": "a" * 64, "policy": {}, "evidence": {}})
        self.assertEqual(decision.outcome, "approve")
        self.assertFalse(captured["body"]["store"])
        output_format = captured["body"]["text"]["format"]
        self.assertEqual(output_format["type"], "json_schema")
        self.assertTrue(output_format["strict"])

    def test_codex_adapter_requests_isolated_structured_output(self):
        captured = {}

        def fake_runner(command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs
            output_path = Path(command[command.index("--output-last-message") + 1])
            output_path.write_text(
                json.dumps(
                    {
                        "outcome": "approve",
                        "message_digest": "a" * 64,
                        "reason_codes": ["WITHIN_POLICY"],
                        "rationale": "The supplied action satisfies the policy.",
                    }
                ),
                encoding="utf-8",
            )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        reviewer = CodexCLIReviewer(
            "reviewer-1", "gpt-5.6-sol", reasoning_effort="medium", runner=fake_runner
        )
        decision = reviewer.review({"message_digest": "a" * 64, "policy": {}, "evidence": {}})
        self.assertEqual(decision.outcome, "approve")
        self.assertIn("--ephemeral", captured["command"])
        self.assertIn("read-only", captured["command"])
        self.assertIn("gpt-5.6-sol", captured["command"])
        self.assertIn("--output-schema", captured["command"])

    def test_evidence_must_match_canonical_commitment(self):
        committed_evidence = default_evidence()
        message = canonical_json(sample_authorization(evidence=committed_evidence))
        committee, combiner, _ = build_committee(
            [ScriptedReviewer("approve"), ScriptedReviewer("approve"), ScriptedReviewer("reject")]
        )
        changed_evidence = {**committed_evidence, "product": "different-product"}
        with self.assertRaisesRegex(ValueError, "evidence does not match"):
            authorize(committee, combiner, message, changed_evidence, default_policy())

    def test_full_trace_exposes_inputs_without_exposing_secrets(self):
        trace = run_full_trace()
        prompt = trace["step_3_reviewer_prompt"]
        reviews = trace["step_4_to_5_review_gate_and_sign"]
        self.assertTrue(prompt["same_input_sent_to_all_reviewers"])
        self.assertFalse(prompt["signing_secrets_present"])
        self.assertEqual(
            [item["signer_output"]["status"] for item in reviews],
            ["signature_share_released", "signature_share_released", "no_signature_share"],
        )
        self.assertEqual(trace["step_6_combine"]["selected_signer_indices"], [1, 2])
        self.assertTrue(
            trace["step_7_verify_and_execute"][
                "final_signature_valid_and_first_execution_accepted"
            ]
        )
        self.assertFalse(trace["step_7_verify_and_execute"]["same_nonce_replay_accepted"])
        serialized = json.dumps(trace["step_3_reviewer_prompt"])
        self.assertNotIn("signing_key_share", serialized)
        self.assertNotIn("channel_key", serialized)


if __name__ == "__main__":
    unittest.main()
