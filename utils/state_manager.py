"""
SentinelPay — In-memory State Manager
Provides O(1) access to user transaction history, device info, and daily totals.
"""

from collections import defaultdict, deque


class StateManager:
    """Holds all in-memory state required by the fraud-detection engines."""

    def __init__(self):
        # Last 5 transactions per user (sliding window)
        self.user_recent_txns = defaultdict(lambda: deque(maxlen=5))

        # Most recent device_id per user
        self.last_device_used: dict[str, str] = {}

        # Running daily spend total per user
        self.daily_total: dict[str, float] = defaultdict(float)

        # SHA-256 hash-chain pointer
        self.previous_hash: str = "GENESIS"

    # ── helpers ───────────────────────────────────────────────────────

    def get_user_history(self, user_id: str) -> deque:
        """Return the recent-transactions deque for *user_id* (O(1))."""
        return self.user_recent_txns[user_id]

    def record_transaction(self, txn: dict) -> None:
        """Append *txn* to the user's sliding window and update daily total."""
        uid = txn["user_id"]
        self.user_recent_txns[uid].append(txn)
        self.daily_total[uid] += txn["amount"]
        self.last_device_used[uid] = txn["device_id"]
