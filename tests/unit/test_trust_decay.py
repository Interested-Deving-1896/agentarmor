"""Tests for time-based trust decay in TrustScorer."""

import datetime

import pytest
from agentarmor.layers.interagent.trust import TrustRecord, TrustScorer


class TestTrustDecay:
    """Core decay formula: effective = stored_trust × (decay_rate ** days_since)."""

    def test_decay_after_30_days(self):
        """Trust 0.9, decay_rate 0.99, 30 days dormant → ≈ 0.67."""
        scorer = TrustScorer(decay_rate=0.99)
        scorer._records["agent-1"] = TrustRecord(
            trust_score=0.9,
            last_interaction_timestamp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30),
            interaction_count=5,
        )
        effective = scorer.get_score("agent-1")
        expected = 0.9 * (0.99 ** 30)  # ≈ 0.6652
        assert abs(effective - expected) < 0.01

    def test_no_decay_same_day(self):
        """Trust 0.9, last interaction today → effective = 0.9 (0 days = no decay)."""
        scorer = TrustScorer(decay_rate=0.99)
        scorer._records["agent-1"] = TrustRecord(
            trust_score=0.9,
            last_interaction_timestamp=datetime.datetime.now(datetime.timezone.utc),
            interaction_count=1,
        )
        assert scorer.get_score("agent-1") == 0.9

    def test_decay_rate_one_never_decays(self):
        """decay_rate=1.0 → no decay regardless of time elapsed."""
        scorer = TrustScorer(decay_rate=1.0)
        scorer._records["agent-1"] = TrustRecord(
            trust_score=0.9,
            last_interaction_timestamp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365),
            interaction_count=1,
        )
        assert scorer.get_score("agent-1") == 0.9

    def test_unknown_agent_returns_default(self):
        scorer = TrustScorer()
        assert scorer.get_score("nobody") == 0.5

    def test_effective_trust_clamped_to_zero(self):
        """Very low stored trust after long dormancy should clamp to 0.0."""
        scorer = TrustScorer(decay_rate=0.5)
        scorer._records["agent-1"] = TrustRecord(
            trust_score=0.1,
            last_interaction_timestamp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=100),
            interaction_count=1,
        )
        effective = scorer.get_score("agent-1")
        assert effective >= 0.0


class TestTrustUpdate:
    """Update should refresh timestamp and increment interaction_count."""

    def test_update_refreshes_timestamp(self):
        scorer = TrustScorer()
        before = datetime.datetime.now(datetime.timezone.utc)
        scorer.update("agent-1", success=True)
        record = scorer._records["agent-1"]
        assert record.last_interaction_timestamp >= before
        assert record.interaction_count == 1

    def test_multiple_updates_increment_count(self):
        scorer = TrustScorer()
        scorer.update("agent-1", success=True)
        scorer.update("agent-1", success=True)
        scorer.update("agent-1", success=False)
        assert scorer._records["agent-1"].interaction_count == 3

    def test_success_increases_trust(self):
        scorer = TrustScorer()
        scorer._scores["agent-1"] = 0.5
        scorer.update("agent-1", True)
        assert scorer._records["agent-1"].trust_score > 0.5

    def test_failure_decreases_trust(self):
        scorer = TrustScorer()
        scorer._scores["agent-1"] = 0.8
        scorer.update("agent-1", False)
        assert scorer._records["agent-1"].trust_score < 0.8


class TestTrustDebugInfo:
    def test_debug_info_with_known_agent(self):
        scorer = TrustScorer(decay_rate=0.99)
        scorer._records["agent-1"] = TrustRecord(
            trust_score=0.9,
            last_interaction_timestamp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10),
            interaction_count=7,
        )
        info = scorer.get_trust_debug_info("agent-1")
        assert info["agent_id"] == "agent-1"
        assert info["stored_trust"] == 0.9
        assert info["days_since_last_interaction"] == 10
        assert info["interaction_count"] == 7
        assert abs(info["decay_applied"] - 0.99 ** 10) < 0.001
        assert abs(info["effective_trust"] - 0.9 * (0.99 ** 10)) < 0.01

    def test_debug_info_with_unknown_agent(self):
        scorer = TrustScorer()
        info = scorer.get_trust_debug_info("unknown")
        assert info["stored_trust"] == 0.5
        assert info["effective_trust"] == 0.5
        assert info["interaction_count"] == 0
        assert info["decay_applied"] == 1.0


class TestIsTrusted:
    def test_dormant_agent_falls_below_threshold(self):
        """An agent that was trusted should become untrusted after enough dormancy."""
        scorer = TrustScorer(min_trust=0.7, decay_rate=0.99)
        scorer._records["agent-1"] = TrustRecord(
            trust_score=0.75,
            last_interaction_timestamp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30),
            interaction_count=5,
        )
        # 0.75 * 0.99^30 ≈ 0.555 < 0.7
        assert not scorer.is_trusted("agent-1")

    def test_recently_active_agent_stays_trusted(self):
        scorer = TrustScorer(min_trust=0.7, decay_rate=0.99)
        scorer._records["agent-1"] = TrustRecord(
            trust_score=0.75,
            last_interaction_timestamp=datetime.datetime.now(datetime.timezone.utc),
            interaction_count=5,
        )
        assert scorer.is_trusted("agent-1")


class TestScoresProxyBackwardCompat:
    """The _scores proxy should keep existing test patterns working."""

    def test_set_and_get(self):
        scorer = TrustScorer(min_trust=0.7)
        scorer._scores["agent-1"] = 0.5
        assert scorer._scores["agent-1"] == 0.5

    def test_get_default(self):
        scorer = TrustScorer()
        assert scorer._scores.get("nonexistent") == 0.5
