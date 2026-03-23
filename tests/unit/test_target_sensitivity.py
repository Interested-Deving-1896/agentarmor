"""Tests for param-aware target sensitivity scoring in L4 planning layer."""

import pytest
from agentarmor.core.types import AgentEvent, RiskScore
from agentarmor.layers.planning.target_sensitivity import (
    DEFAULT_MULTIPLIER,
    compute_composite_score,
    get_target_multiplier,
)
from agentarmor.layers.planning.validator import CATEGORY_RISK, PlanningLayer, ActionCategory


# ============================================================
# Unit tests for get_target_multiplier
# ============================================================


class TestGetTargetMultiplier:
    def test_etc_shadow(self):
        assert get_target_multiplier({"path": "/etc/shadow"}) == 4.0

    def test_etc_passwd(self):
        assert get_target_multiplier({"file": "/etc/passwd"}) == 4.0

    def test_etc_wildcard(self):
        assert get_target_multiplier({"path": "/etc/hosts"}) == 4.0

    def test_ssh_key(self):
        assert get_target_multiplier({"path": "~/.ssh/id_rsa"}) == 4.0

    def test_aws_credentials(self):
        assert get_target_multiplier({"target": "~/.aws/credentials"}) == 4.0

    def test_gnupg(self):
        assert get_target_multiplier({"resource": "~/.gnupg/secring.gpg"}) == 4.0

    def test_root_directory(self):
        assert get_target_multiplier({"path": "/root/.bashrc"}) == 3.5

    def test_sys_directory(self):
        assert get_target_multiplier({"path": "/sys/class/net"}) == 3.5

    def test_proc_directory(self):
        assert get_target_multiplier({"path": "/proc/1/environ"}) == 3.5

    def test_var_log(self):
        assert get_target_multiplier({"path": "/var/log/syslog"}) == 2.0

    def test_tmp_directory(self):
        assert get_target_multiplier({"path": "/tmp/cache.json"}) == 0.5

    def test_var_tmp(self):
        assert get_target_multiplier({"path": "/var/tmp/scratch"}) == 0.5

    def test_no_matching_keys(self):
        assert get_target_multiplier({}) == DEFAULT_MULTIPLIER

    def test_no_matching_pattern(self):
        assert get_target_multiplier({"path": "/home/user/notes.txt"}) == DEFAULT_MULTIPLIER

    def test_url_key(self):
        assert get_target_multiplier({"url": "/etc/shadow"}) == 4.0

    def test_key_key(self):
        assert get_target_multiplier({"key": "/tmp/foo"}) == 0.5

    def test_first_matching_param_key_used(self):
        """When multiple target keys exist, the first one (by priority) is used."""
        params = {"path": "/etc/shadow", "file": "/tmp/foo"}
        assert get_target_multiplier(params) == 4.0

    def test_empty_string_value(self):
        assert get_target_multiplier({"path": ""}) == DEFAULT_MULTIPLIER

    def test_non_string_value_ignored(self):
        assert get_target_multiplier({"path": 42}) == DEFAULT_MULTIPLIER


# ============================================================
# Unit tests for compute_composite_score
# ============================================================


class TestComputeCompositeScore:
    def test_read_etc_shadow(self):
        """read.file /etc/shadow → composite >= 4.0"""
        score = compute_composite_score(CATEGORY_RISK[ActionCategory.READ], {"path": "/etc/shadow"})
        assert score >= 4.0  # 1 * 4.0 = 4.0

    def test_delete_tmp(self):
        """delete.file /tmp/cache.json → composite <= 4.0"""
        score = compute_composite_score(CATEGORY_RISK[ActionCategory.DELETE], {"path": "/tmp/cache.json"})
        assert score <= 4.0  # 7 * 0.5 = 3.5

    def test_exec_tmp(self):
        """exec.shell /tmp/script.sh → composite = 4.0 (EXECUTE=8, /tmp=0.5)"""
        score = compute_composite_score(CATEGORY_RISK[ActionCategory.EXECUTE], {"path": "/tmp/script.sh"})
        assert score == 4.0  # 8 * 0.5 = 4.0

    def test_read_ssh_key(self):
        """read.file ~/.ssh/id_rsa → composite >= 4.0"""
        score = compute_composite_score(CATEGORY_RISK[ActionCategory.READ], {"path": "~/.ssh/id_rsa"})
        assert score >= 4.0  # 1 * 4.0 = 4.0

    def test_cap_at_ten(self):
        """admin action on sensitive target caps at 10.0"""
        score = compute_composite_score(CATEGORY_RISK[ActionCategory.ADMIN], {"path": "/etc/shadow"})
        assert score == 10.0  # min(10.0, 10 * 4.0)

    def test_default_multiplier(self):
        """No params → composite equals verb_score unchanged."""
        score = compute_composite_score(3, {})
        assert score == 3.0


# ============================================================
# Unit tests for RiskScore model
# ============================================================


class TestRiskScore:
    def test_build_sensitive(self):
        risk = RiskScore.build(verb_score=1, target_multiplier=4.0)
        assert risk.verb_score == 1
        assert risk.target_multiplier == 4.0
        assert risk.composite_score == 4.0
        assert risk.sensitive_target is True

    def test_build_non_sensitive(self):
        risk = RiskScore.build(verb_score=7, target_multiplier=0.5)
        assert risk.composite_score == 3.5
        assert risk.sensitive_target is False

    def test_build_default(self):
        risk = RiskScore.build(verb_score=3, target_multiplier=1.0)
        assert risk.composite_score == 3.0
        assert risk.sensitive_target is False

    def test_cap_at_10(self):
        risk = RiskScore.build(verb_score=10, target_multiplier=4.0)
        assert risk.composite_score == 10.0


# ============================================================
# Integration tests: PlanningLayer with target-aware scoring
# ============================================================


class TestPlanningLayerCompositeScoring:
    @pytest.fixture
    def layer(self):
        return PlanningLayer()

    @pytest.mark.asyncio
    async def test_read_etc_shadow_escalated(self, layer):
        """read.file targeting /etc/shadow should not be a simple ALLOW."""
        event = AgentEvent(
            agent_id="test", event_type="tool_call",
            action="read.file", params={"path": "/etc/shadow"},
        )
        result = await layer.execute(event)
        assert event.metadata["composite_score"] >= 4.0
        assert result.details["sensitive_target"] is True

    @pytest.mark.asyncio
    async def test_delete_tmp_low_composite(self, layer):
        """delete.file on /tmp should have reduced composite score."""
        event = AgentEvent(
            agent_id="test", event_type="tool_call",
            action="delete.file", params={"path": "/tmp/cache.json"},
        )
        result = await layer.execute(event)
        assert event.metadata["composite_score"] <= 4.0
        # With composite 3.5, this should NOT be escalated
        assert result.details["composite_score"] == 3.5

    @pytest.mark.asyncio
    async def test_exec_shell_tmp(self, layer):
        """exec.shell /tmp/script.sh → composite 4.0 (not a hard deny)."""
        event = AgentEvent(
            agent_id="test", event_type="tool_call",
            action="exec.shell", params={"path": "/tmp/script.sh"},
        )
        result = await layer.execute(event)
        assert event.metadata["composite_score"] == 4.0

    @pytest.mark.asyncio
    async def test_read_ssh_key_high_risk(self, layer):
        """read.file ~/.ssh/id_rsa → composite >= 4.0."""
        event = AgentEvent(
            agent_id="test", event_type="tool_call",
            action="read.file", params={"path": "~/.ssh/id_rsa"},
        )
        result = await layer.execute(event)
        assert event.metadata["composite_score"] >= 4.0
        assert result.details["sensitive_target"] is True

    @pytest.mark.asyncio
    async def test_admin_etc_shadow_denied(self, layer):
        """admin action on /etc/shadow → composite 10, hard deny."""
        event = AgentEvent(
            agent_id="test", event_type="tool_call",
            action="admin.chmod", params={"path": "/etc/shadow"},
        )
        result = await layer.execute(event)
        assert event.metadata["composite_score"] == 10.0
        from agentarmor.core.types import SecurityVerdict
        assert result.verdict == SecurityVerdict.DENY

    @pytest.mark.asyncio
    async def test_metadata_contains_risk_assessment(self, layer):
        """Event metadata should include full risk_assessment dict."""
        event = AgentEvent(
            agent_id="test", event_type="tool_call",
            action="read.file", params={"path": "/etc/shadow"},
        )
        await layer.execute(event)
        assessment = event.metadata["risk_assessment"]
        assert "verb_score" in assessment
        assert "target_multiplier" in assessment
        assert "composite_score" in assessment
        assert "sensitive_target" in assessment
