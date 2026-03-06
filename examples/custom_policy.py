"""Policy example — define and evaluate custom security policies."""

import asyncio
from agentarmor import AgentArmor, AgentEvent
from agentarmor.policy.engine import SecurityPolicy, PolicyRule
from agentarmor.core.types import SecurityVerdict


async def main():
    # Define a custom policy programmatically
    policy = SecurityPolicy(
        name="database_agent",
        agent_type="database",
        risk_level="high",
        global_denied_actions=["database.drop", "database.truncate"],
        require_human_approval_for=["database.delete"],
        rules=[
            PolicyRule(
                name="limit_query_results",
                description="Block queries without LIMIT clause",
                action_pattern="database.query",
                conditions=[
                    {"field": "params.query", "operator": "not_in", "value": "LIMIT"},
                ],
                verdict=SecurityVerdict.AUDIT,
                priority=50,
            ),
            PolicyRule(
                name="block_cross_db_access",
                description="Block access to other databases",
                action_pattern="database.*",
                conditions=[
                    {"field": "params.database", "operator": "!=", "value": "production"},
                ],
                verdict=SecurityVerdict.DENY,
                priority=100,
            ),
        ],
    )

    # Save to YAML
    policy.to_yaml("policies/database_agent.yaml")
    print("Policy saved to policies/database_agent.yaml")

    # Use with AgentArmor
    armor = AgentArmor(policy=policy)
    armor.l8_identity.register_agent("db-agent", permissions={"database.*"})

    # Test: allowed query
    result = await armor.intercept(
        action="database.query",
        params={"query": "SELECT * FROM users LIMIT 10", "database": "production"},
        agent_id="db-agent",
    )
    print(f"\nQuery with LIMIT: {result.final_verdict.value}")

    # Test: DROP blocked
    result = await armor.intercept(
        action="database.drop",
        params={"table": "users", "database": "production"},
        agent_id="db-agent",
    )
    print(f"DROP table: {result.final_verdict.value}")

    # Test: cross-db access blocked
    result = await armor.intercept(
        action="database.query",
        params={"query": "SELECT * FROM secrets", "database": "admin_db"},
        agent_id="db-agent",
    )
    print(f"Cross-DB access: {result.final_verdict.value}")


if __name__ == "__main__":
    asyncio.run(main())
