"""Red Team example — run adversarial tests against your AgentArmor deployment."""

import asyncio
from agentarmor import AgentArmor, ArmorConfig
from agentarmor.redteam import RedTeamSuite


async def main():
    # Set up armor with default config
    config = ArmorConfig()
    config.identity.enabled = False  # Disable identity for testing
    armor = AgentArmor(config=config)

    # Create and run the red team suite
    suite = RedTeamSuite(armor=armor)
    results = await suite.run_all()

    # Print the report
    suite.print_report(results)


if __name__ == "__main__":
    asyncio.run(main())
