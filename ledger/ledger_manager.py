"""
SentinelPay — Ledger Manager
Append-only SHA-256 hash-chain ledger with full integrity verification.
"""

import hashlib
import os


LEDGER_FILE = os.path.join(os.path.dirname(__file__), "ledger.txt")


def compute_hash(data: str) -> str:
    """Return the hex SHA-256 digest of *data*."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def append_ledger(
    txn_id: str,
    score: int,
    decision: str,
    previous_hash: str,
) -> str:
    """
    Append a new entry to the hash-chain ledger.

    Each entry stores:  txn_id | score | decision | previous_hash | current_hash

    Returns the current_hash (becomes the next entry's previous_hash).
    """
    payload = f"{txn_id}|{score}|{decision}|{previous_hash}"
    current_hash = compute_hash(payload)

    entry = f"{txn_id} | {score} | {decision} | {previous_hash} | {current_hash}\n"

    with open(LEDGER_FILE, "a", encoding="utf-8") as fh:
        fh.write(entry)

    return current_hash


def clear_ledger() -> None:
    """Erase the ledger file (used before fresh simulation runs)."""
    if os.path.exists(LEDGER_FILE):
        os.remove(LEDGER_FILE)


def verify_ledger() -> tuple[bool, str]:
    """
    Walk the entire ledger file and re-verify every SHA-256 link.

    Returns
    -------
    (True,  "Ledger integrity verified — N entries OK")   on success
    (False, "<description of first tampered entry>")       on failure
    """
    if not os.path.exists(LEDGER_FILE):
        return True, "Ledger file is empty — nothing to verify"

    expected_prev = "GENESIS"

    with open(LEDGER_FILE, "r", encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue

            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 5:
                return False, f"Line {line_no}: malformed entry (expected 5 fields)"

            txn_id, score_str, decision, stored_prev, stored_hash = parts

            # 1. previous-hash linkage
            if stored_prev != expected_prev:
                return (
                    False,
                    f"Line {line_no} ({txn_id}): previous_hash mismatch — "
                    f"expected {expected_prev[:16]}…, got {stored_prev[:16]}…",
                )

            # 2. recompute current hash and compare
            payload = f"{txn_id}|{score_str}|{decision}|{stored_prev}"
            recomputed = compute_hash(payload)
            if recomputed != stored_hash:
                return (
                    False,
                    f"Line {line_no} ({txn_id}): hash mismatch — "
                    f"recomputed {recomputed[:16]}…, stored {stored_hash[:16]}…",
                )

            expected_prev = stored_hash

    return True, f"Ledger integrity verified — {line_no} entries OK"
