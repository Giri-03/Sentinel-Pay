"""
SentinelPay — Device-Risk Engine
Flags transactions from an unrecognised device.
"""


def device_risk(txn: dict, last_device_used: dict) -> int:
    """
    Score device risk.

    Returns
    -------
    int  — 15 if the device changed, else 0.

    Side-effects: updates *last_device_used* in-place (O(1)).
    """
    uid = txn["user_id"]
    current_device = txn["device_id"]

    if uid in last_device_used and last_device_used[uid] != current_device:
        return 15

    return 0
