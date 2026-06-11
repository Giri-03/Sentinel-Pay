"""
SentinelPay — Velocity-Risk Engine
Detects rapid-fire transaction bursts using a sliding-window approach.
"""


def velocity_risk(txn: dict, user_history) -> int:
    """
    Score velocity risk.

    Rules
    -----
    * +15 if ≥ 3 transactions (including current) fall within 60 seconds.
    * +5  if the amount is exactly 1 (micro-transaction probing).

    Uses only the tail of *user_history* (deque with maxlen=5),
    so there is no full-dataset scan.
    """
    score = 0

    # ── sliding-window burst check ────────────────────────────────
    if len(user_history) >= 2:
        # Collect the two most recent timestamps + current txn
        timestamps: list[float] = [
            user_history[-2]["timestamp"],
            user_history[-1]["timestamp"],
            txn["timestamp"],
        ]
        timestamps.sort()
        if timestamps[2] - timestamps[0] <= 60:
            score += 15

    # ── micro-transaction probe ───────────────────────────────────
    if txn["amount"] == 1:
        score += 5

    return score
