"""
SentinelPay — Amount-Risk Engine
Flags unusually large single transactions and daily-spend breaches.
"""


def amount_risk(txn: dict, daily_total: dict) -> int:
    """
    Score amount risk.

    Rules
    -----
    * +20 if single amount > 50 000
    * +10 if single amount > 20 000  (but ≤ 50 000)
    * +20 if cumulative daily total exceeds 100 000

    Returns
    -------
    int  — combined risk score for this transaction.
    """
    score = 0
    amount = txn["amount"]

    # ── single-transaction thresholds ─────────────────────────────
    if amount > 50_000:
        score += 20
    elif amount > 20_000:
        score += 10

    # ── daily cumulative threshold ────────────────────────────────
    uid = txn["user_id"]
    current_daily = daily_total.get(uid, 0) + amount
    if current_daily > 100_000:
        score += 20

    return score
