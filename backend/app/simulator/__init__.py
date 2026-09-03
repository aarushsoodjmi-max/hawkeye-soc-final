"""
HawkEye SOC — Attack Simulator
================================
Synthetic SOC alert-data generator for detection engineering, SOC analyst
training, dashboard demos, and automated testing. Produces pandas
DataFrames of realistic multi-stage attack alerts across five scenario
types: credential theft, phishing, malware, insider threat, and
ransomware.

This module is self-contained: it does not expose any API/web endpoints,
does not integrate with FastAPI, and does not depend on the rest of the
HawkEye backend. Import it directly:

    from app.simulator import AttackSimulator, simulate

    sim = AttackSimulator(seed=42)
    df = sim.generate_scenario("phishing")

    # or functionally:
    df = simulate("ransomware", seed=7)
    all_df = simulate(seed=7, scenarios_per_type=2)
"""

from .attack_simulator import AttackSimulator, simulate, ALERT_COLUMNS
from .scenarios import SCENARIO_NAMES
from .seed import get_rng, set_global_seed

__all__ = [
    "AttackSimulator",
    "simulate",
    "ALERT_COLUMNS",
    "SCENARIO_NAMES",
    "get_rng",
    "set_global_seed",
]

__version__ = "1.0.0"
