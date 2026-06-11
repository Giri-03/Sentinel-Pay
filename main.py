"""
SentinelPay — Real-Time Fraud Detection System (Hackathon Edition)
Main entry-point: processes transactions, scores risk, records results,
runs chaos-mode stress tests, and prints performance analytics.
"""

import random
import time
from dataclasses import dataclass, field

# ── internal imports ──────────────────────────────────────────────
from engines.geo_engine import geo_risk
from engines.velocity_engine import velocity_risk
from engines.device_engine import device_risk
from engines.amount_engine import amount_risk
from ledger.ledger_manager import append_ledger, verify_ledger, clear_ledger
from utils.state_manager import StateManager


# ── global state & analytics ─────────────────────────────────────
state = StateManager()


@dataclass
class Analytics:
    """Typed container for runtime performance metrics."""
    total: int = 0
    latencies: list[float] = field(default_factory=list)
    approve: int = 0
    otp_required: int = 0
    block: int = 0
    invalid: int = 0

    def record(self, decision: str, latency_ms: float) -> None:
        """Record a single transaction result."""
        self.total += 1
        self.latencies.append(latency_ms)
        if decision == "APPROVE":
            self.approve += 1
        elif decision == "OTP_REQUIRED":
            self.otp_required += 1
        elif decision == "BLOCK":
            self.block += 1
        elif decision == "INVALID_TRANSACTION":
            self.invalid += 1


analytics = Analytics()


def reset_state() -> None:
    """Reset state and analytics for a fresh run."""
    global state, analytics
    state = StateManager()
    analytics = Analytics()
    clear_ledger()


# ── scoring helpers ──────────────────────────────────────────────

def aggregate_risk(geo: int, velocity: int, device: int, amount: int) -> int:
    """Sum individual engine scores into one aggregate risk score."""
    return geo + velocity + device + amount


def make_decision(score: int) -> str:
    """
    Map an aggregate score to a decision string.

    < 20  → APPROVE
    20–50 → OTP_REQUIRED
    > 50  → BLOCK
    """
    if score < 20:
        return "APPROVE"
    if score <= 50:
        return "OTP_REQUIRED"
    return "BLOCK"


# ── input validation ─────────────────────────────────────────────

def _validate(txn: dict) -> str | None:
    """Return an error message if *txn* is invalid, else None."""
    if "amount" not in txn or txn["amount"] <= 0:
        return "Invalid or missing amount (must be > 0)"
    if "timestamp" not in txn:
        return "Missing timestamp"
    if "lat" not in txn or "lon" not in txn:
        return "Missing lat/lon coordinates"
    if not (-90 <= txn["lat"] <= 90) or not (-180 <= txn["lon"] <= 180):
        return "lat/lon out of valid range"
    if "device_id" not in txn or not txn["device_id"]:
        return "Missing device_id"
    return None


# ── core pipeline ────────────────────────────────────────────────

def process_transaction(txn: dict) -> dict:
    """
    Run *txn* through validation → risk engines → decision → ledger.
    Returns a full result dict including reasons list.
    """
    start = time.perf_counter()

    # ── validation gate ───────────────────────────────────────────
    error = _validate(txn)
    if error:
        latency_ms = float((time.perf_counter() - start) * 1000)
        analytics.record("INVALID_TRANSACTION", latency_ms)
        return {
            "txn_id": txn.get("txn_id", "UNKNOWN"),
            "geo_score": 0, "velocity_score": 0,
            "device_score": 0, "amount_score": 0,
            "total_score": 0,
            "decision": "INVALID_TRANSACTION",
            "latency_ms": round(latency_ms, 3),
            "reasons": [error],
        }

    uid = txn["user_id"]
    history = state.get_user_history(uid)

    # ── run engines ───────────────────────────────────────────────
    g = geo_risk(txn, history)
    v = velocity_risk(txn, history)
    d = device_risk(txn, state.last_device_used)
    a = amount_risk(txn, state.daily_total)

    total = aggregate_risk(g, v, d, a)
    decision = make_decision(total)

    # ── fraud explanation ─────────────────────────────────────────
    reasons: list[str] = []
    if g > 0:
        reasons.append("Impossible travel detected")
    if v > 0:
        reasons.append("Burst transaction pattern")
    if d > 0:
        reasons.append("Device mismatch detected")
    if a > 0:
        reasons.append("High amount anomaly")

    # ── ledger ────────────────────────────────────────────────────
    state.previous_hash = append_ledger(
        txn["txn_id"], total, decision, state.previous_hash
    )

    # ── update state AFTER scoring ────────────────────────────────
    state.record_transaction(txn)

    latency_ms = float((time.perf_counter() - start) * 1000)

    # ── analytics ─────────────────────────────────────────────────
    analytics.record(decision, latency_ms)

    return {
        "txn_id": txn["txn_id"],
        "geo_score": g,
        "velocity_score": v,
        "device_score": d,
        "amount_score": a,
        "total_score": total,
        "decision": decision,
        "latency_ms": round(latency_ms, 3),
        "reasons": reasons,
    }


# ── performance summary ─────────────────────────────────────────

def print_performance_summary() -> None:
    """Print a clean performance analytics block."""
    lats = analytics.latencies
    avg = sum(lats) / len(lats) if lats else 0.0
    mx = max(lats) if lats else 0.0

    print("\n" + "=" * 50)
    print("  PERFORMANCE SUMMARY")
    print("=" * 50)
    print(f"  Total Transactions : {analytics.total}")
    print(f"  Average Latency    : {avg:.3f} ms")
    print(f"  Max Latency        : {mx:.3f} ms")
    print(f"  Approvals          : {analytics.approve}")
    print(f"  OTP Required       : {analytics.otp_required}")
    print(f"  Blocked            : {analytics.block}")
    print(f"  Invalid            : {analytics.invalid}")
    print("=" * 50)


# ── chaos mode ───────────────────────────────────────────────────

CHAOS_CITIES = [
    (28.6139, 77.2090),   # New Delhi
    (19.0760, 72.8777),   # Mumbai
    (51.5074, -0.1278),   # London
    (40.7128, -74.0060),  # New York
    (-33.8688, 151.2093), # Sydney
    (35.6762, 139.6503),  # Tokyo
    (48.8566, 2.3522),    # Paris
    (55.7558, 37.6173),   # Moscow
    (-23.5505, -46.6333), # São Paulo
    (1.3521, 103.8198),   # Singapore
]


def chaos_mode() -> list[dict]:
    """
    Simulate 20 high-risk transactions with impossible travel,
    large amounts, rapid timing, and rotating devices.
    """
    results: list[dict] = []
    base_ts = 1700100000

    for i in range(1, 21):
        city = CHAOS_CITIES[i % len(CHAOS_CITIES)]
        txn = {
            "txn_id": f"CHAOS_{i:03d}",
            "user_id": "chaos_user",
            "amount": random.randint(60000, 200000),
            "lat": city[0],
            "lon": city[1],
            "timestamp": base_ts + (i * 5),      # 5 s apart → burst
            "device_id": f"device_{chr(65 + (i % 6))}",  # rotate A-F
        }
        result = process_transaction(txn)
        results.append(result)

        print(
            f"  {result['txn_id']}  |  Score: {result['total_score']:>3}  "
            f"|  {result['decision']:<20}  |  {result['latency_ms']:.3f} ms"
        )

    lats = [r["latency_ms"] for r in results]
    avg = sum(lats) / len(lats)
    mx = max(lats)
    print(f"\n  Chaos Avg Latency : {avg:.3f} ms")
    print(f"  Chaos Max Latency : {mx:.3f} ms")
    assert mx < 200, f"FAIL: max latency {mx:.3f} ms exceeds 200 ms threshold"
    print("  [OK] All transactions processed under 200 ms")

    return results


# ── simulation ───────────────────────────────────────────────────

def main() -> None:
    """Full hackathon-grade demonstration."""
    reset_state()

    transactions = [
        {
            "txn_id": "TXN001",
            "user_id": "user_42",
            "amount": 15000,
            "lat": 28.6139,          # New Delhi
            "lon": 77.2090,
            "timestamp": 1700000000,
            "device_id": "device_A",
        },
        {
            "txn_id": "TXN002",
            "user_id": "user_42",
            "amount": 75000,         # large amount
            "lat": 19.0760,          # Mumbai (~1150 km away)
            "lon": 72.8777,
            "timestamp": 1700000030, # 30 s later → impossible travel
            "device_id": "device_B", # different device
        },
        {
            "txn_id": "TXN003",
            "user_id": "user_42",
            "amount": 1,             # micro-transaction probe
            "lat": 19.0760,
            "lon": 72.8777,
            "timestamp": 1700000050, # 20 s later (burst)
            "device_id": "device_B",
        },
    ]

    # ── header ────────────────────────────────────────────────────
    print("=" * 65)
    print("  SentinelPay — Real-Time Fraud Detection (Hackathon Edition)")
    print("=" * 65)

    # ── process sample transactions ───────────────────────────────
    for txn in transactions:
        result = process_transaction(txn)

        print(f"\n--- Transaction: {result['txn_id']} ---")
        print(f"  Geo Risk       : {result['geo_score']}")
        print(f"  Velocity Risk  : {result['velocity_score']}")
        print(f"  Device Risk    : {result['device_score']}")
        print(f"  Amount Risk    : {result['amount_score']}")
        print(f"  Total Score    : {result['total_score']}")
        print(f"  Decision       : {result['decision']}")
        print(f"  Latency        : {result['latency_ms']} ms")
        if result["reasons"]:
            print(f"  Reasons        : {', '.join(result['reasons'])}")

    # ── ledger integrity check ────────────────────────────────────
    valid, msg = verify_ledger()
    print("\n" + "-" * 65)
    if valid:
        print(f"  Ledger Integrity Status: VALID  ({msg})")
    else:
        print("  +======================================================+")
        print("  |  !!  LEDGER INTEGRITY STATUS: TAMPER DETECTED  !!   |")
        print("  +======================================================+")
        print(f"  Detail: {msg}")
        print("  Halting further processing.")
        return
    print("-" * 65)

    # ── chaos mode ────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  CHAOS MODE - 20 High-Risk Transactions")
    print("=" * 65)
    chaos_mode()

    # ── second ledger check (post-chaos) ──────────────────────────
    valid, msg = verify_ledger()
    print("\n" + "-" * 65)
    if valid:
        print(f"  Ledger Integrity Status: VALID  ({msg})")
    else:
        print("  !!  LEDGER INTEGRITY STATUS: TAMPER DETECTED")
        print(f"  Detail: {msg}")
    print("-" * 65)

    # ── performance summary ───────────────────────────────────────
    print_performance_summary()

    print("\n  Simulation complete. Ledger -> ledger/ledger.txt")
    print("=" * 65)


if __name__ == "__main__":
    main()
