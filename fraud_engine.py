"""
SentinelPay — Rule-Based Fraud Engine
No ML. Pure deterministic scoring based on transaction signals.

Scoring Rules:
  +20  amount > 50,000
  +10  amount > 20,000 (but ≤ 50,000)
  +15  failed_attempts_last_10_min > 0
  +10  is_international_ip == "Yes"
  +15  receiver_risk_category == "High"
  +15  more than 10 transactions in the last hour (burst)
  +20  more than 30 small transactions (< 2000) in current day

Risk Classification:
  < 30  → Low Risk
  30–60 → Medium Risk
  > 60  → High Risk

Daily Limits:
  small_transaction_limit_per_day = 30
  total_transaction_limit_per_day = 50
"""

from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import time

import otp_service


# ── Constants ──────────────────────────────────────────────────────────────────

SMALL_TXN_LIMIT = 30       # max small transactions (< 2000) per day
TOTAL_TXN_LIMIT = 50       # max any transactions per day
HARD_BLOCK_THRESHOLD = 3   # hard blocks in 7 days → manual admin review
OTP_VALIDITY_SECS = 60     # OTP valid for 60 seconds
OTP_MAX_ATTEMPTS = 3       # max OTP attempts before hard block


# ── Risk Score Thresholds ──────────────────────────────────────────────────────

RISK_MEDIUM = 30
RISK_HIGH = 60


# ── Account Status Values ──────────────────────────────────────────────────────

STATUS_ACTIVE = "active"
STATUS_UNDER_REVIEW = "under_review"
STATUS_HARD_BLOCKED = "hard_blocked"
STATUS_ADMIN_REVIEW = "admin_review"


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class UserDailyState:
    """Tracks daily counters and timestamps for one user."""
    date: str = ""                         # YYYY-MM-DD of the counters
    total_txn_count: int = 0
    small_txn_count: int = 0
    hourly_txns: list[float] = field(default_factory=list)   # epoch timestamps
    hard_block_dates: list[str] = field(default_factory=list) # YYYY-MM-DD


@dataclass
class VerificationSession:
    """State for an active 2-step verification session."""
    user_id: str = ""
    txn_id: str = ""
    phone: str = ""       # phone OTP is keyed to in otp_service
    passkey_done: bool = False
    completed: bool = False


# ── Fraud Engine ──────────────────────────────────────────────────────────────

class FraudEngine:
    """
    Stateful rule-based fraud detection engine.
    Call score_transaction() for each incoming transaction.
    """

    def __init__(self):
        # Per-user daily state
        self._user_state: dict[str, UserDailyState] = defaultdict(UserDailyState)
        # Account status per user (overrides anything in the dataset)
        self._account_status: dict[str, str] = {}
        # Active verification sessions
        self._verif_sessions: dict[str, VerificationSession] = {}
        # Processed results list (for dashboard)
        self.results: list[dict] = []

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _get_today(self) -> str:
        return datetime.now().strftime("%Y-%m-%d")

    def _refresh_daily(self, uid: str, today: str) -> UserDailyState:
        """Reset daily counters if it's a new day."""
        st = self._user_state[uid]
        if st.date != today:
            st.date = today
            st.total_txn_count = 0
            st.small_txn_count = 0
            st.hourly_txns = []
        return st

    def _burst_count(self, st: UserDailyState, now_epoch: float) -> int:
        """Count transactions in the last 3600 seconds."""
        cutoff = now_epoch - 3600
        recent = [t for t in st.hourly_txns if t > cutoff]
        st.hourly_txns = recent
        return len(recent)

    def _hard_block_count_last_7_days(self, st: UserDailyState) -> int:
        today = datetime.now()
        cutoff_dt = today.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
        cutoff = cutoff_dt.strftime("%Y-%m-%d")
        return sum(1 for d in st.hard_block_dates if d >= cutoff)

    # ── Scoring ────────────────────────────────────────────────────────────────

    def compute_score(self, txn: dict, st: UserDailyState, now_epoch: float) -> tuple[int, list[str]]:
        """
        Compute a fraud score for *txn*.
        Returns (score, [reasons]).
        """
        score = 0
        reasons: list[str] = []
        amount = float(txn.get("amount", 0))

        # Rule 1: High amount
        if amount > 50_000:
            score += 20
            reasons.append("Amount > ₹50,000 (+20)")
        elif amount > 20_000:
            score += 10
            reasons.append("Amount > ₹20,000 (+10)")

        # Rule 2: Failed login attempts
        failed = int(txn.get("failed_attempts_last_10_min", 0) or 0)
        if failed > 0:
            score += 15
            reasons.append(f"Failed attempts: {failed} (+15)")

        # Rule 3: International IP
        if str(txn.get("is_international_ip", "No")).strip().lower() in ("yes", "true", "1"):
            score += 10
            reasons.append("International IP (+10)")

        # Rule 4: High-risk receiver
        if str(txn.get("receiver_risk_category", "")).strip().lower() == "high":
            score += 15
            reasons.append("High-risk receiver (+15)")

        # Rule 5: Burst (> 10 txns in last hour)
        burst = self._burst_count(st, now_epoch)
        if burst > 10:
            score += 15
            reasons.append(f"Burst: {burst} txns/hr (+15)")

        # Rule 6: Micro-spam (> 30 small txns today)
        if amount < 2_000 and st.small_txn_count >= SMALL_TXN_LIMIT:
            score += 20
            reasons.append(f"Small-txn spam: {st.small_txn_count} today (+20)")

        return score, reasons

    def classify_risk(self, score: int) -> str:
        if score < RISK_MEDIUM:
            return "Low"
        if score <= RISK_HIGH:
            return "Medium"
        return "High"

    # ── Main entry ─────────────────────────────────────────────────────────────

    def score_transaction(self, txn: dict) -> dict:
        """
        Score one transaction dict.
        Updates daily counters and account status.
        Returns a result dict.
        """
        uid = str(txn.get("user_id", "UNKNOWN"))
        today = self._get_today()
        now_epoch = time.time()
        st = self._refresh_daily(uid, today)

        # ── Check if account is blocked ────────────────────────────────────────
        acct_status = self._account_status.get(uid, str(txn.get("account_status", STATUS_ACTIVE)))
        if acct_status == STATUS_HARD_BLOCKED:
            result = self._build_result(txn, 100, "High", ["Account is HARD BLOCKED"],
                                        "BLOCKED", acct_status, uid)
            self.results.append(result)
            return result

        # ── Daily limit check ──────────────────────────────────────────────────
        limit_violated = False
        limit_reasons: list[str] = []

        if st.total_txn_count >= TOTAL_TXN_LIMIT:
            limit_violated = True
            limit_reasons.append(f"Daily limit reached: {st.total_txn_count} transactions")

        amount = float(txn.get("amount", 0))
        if amount < 2_000 and st.small_txn_count >= SMALL_TXN_LIMIT:
            limit_violated = True
            limit_reasons.append(f"Small-txn daily limit: {st.small_txn_count}/30")

        if limit_violated:
            self._account_status[uid] = STATUS_UNDER_REVIEW
            acct_status = STATUS_UNDER_REVIEW

        # ── Fraud scoring ──────────────────────────────────────────────────────
        score, score_reasons = self.compute_score(txn, st, now_epoch)
        risk_level = self.classify_risk(score)
        all_reasons = score_reasons + limit_reasons

        # ── Decision ───────────────────────────────────────────────────────────
        needs_verification = (
            risk_level in ("Medium", "High")
            or limit_violated
        )

        if needs_verification or acct_status == STATUS_UNDER_REVIEW:
            decision = "2FA_REQUIRED"
            if acct_status == STATUS_ACTIVE:
                self._account_status[uid] = STATUS_UNDER_REVIEW
                acct_status = STATUS_UNDER_REVIEW
        else:
            decision = "APPROVED"

        # ── Update counters ────────────────────────────────────────────────────
        st.total_txn_count += 1
        if amount < 2_000:
            st.small_txn_count += 1
        st.hourly_txns.append(now_epoch)

        result = self._build_result(txn, score, risk_level, all_reasons, decision, acct_status, uid)
        self.results.append(result)
        return result

    def _build_result(self, txn, score, risk_level, reasons, decision, acct_status, uid) -> dict:
        return {
            "txn_id": txn.get("transaction_id", txn.get("txn_id", "N/A")),
            "user_id": uid,
            "amount": float(txn.get("amount", 0)),
            "timestamp": str(txn.get("timestamp", "")),
            "merchant_category": txn.get("merchant_category", ""),
            "payment_channel": txn.get("payment_channel", ""),
            "is_international_ip": txn.get("is_international_ip", "No"),
            "receiver_risk_category": txn.get("receiver_risk_category", ""),
            "failed_attempts": int(txn.get("failed_attempts_last_10_min", 0) or 0),
            "fraud_score": score,
            "risk_level": risk_level,
            "reasons": reasons,
            "decision": decision,
            "account_status": acct_status,
        }

    # ── 2-Step Verification ────────────────────────────────────────────────────

    def start_verification(self, uid: str, txn_id: str, phone: str = "") -> VerificationSession:
        """Initiate a new passkey + OTP session for *uid*."""
        # Use uid as fallback phone key for demo if no real phone supplied
        phone_key = phone or uid
        sess = VerificationSession(user_id=uid, txn_id=txn_id, phone=phone_key)
        self._verif_sessions[uid] = sess
        return sess

    def verify_passkey(self, uid: str) -> bool:
        """Mark passkey step as passed (simulated always-success for demo)."""
        sess = self._verif_sessions.get(uid)
        if not sess:
            return False
        sess.passkey_done = True
        # Delegate OTP generation to the unified otp_service
        _otp, _sent, _msg = otp_service.generate_otp(sess.phone, purpose="transaction")
        return True

    def get_otp(self, uid: str) -> str | None:
        """Return the current OTP for display in the demo (delegates to otp_service)."""
        sess = self._verif_sessions.get(uid)
        if sess and sess.passkey_done:
            return otp_service.get_otp_display(sess.phone)
        return None

    def verify_otp(self, uid: str, entered_otp: str) -> dict:
        """
        Validate the entered OTP via the unified otp_service.
        Returns {"success": bool, "message": str, "account_status": str}
        """
        sess = self._verif_sessions.get(uid)
        if not sess or not sess.passkey_done:
            return {"success": False, "message": "Passkey not completed first.", "account_status": self._account_status.get(uid, STATUS_ACTIVE)}
        assert sess is not None

        success, message = otp_service.verify_otp(
            phone_number=sess.phone,
            entered_otp=entered_otp,
            expected_purpose="transaction",
        )

        if success:
            self._account_status[uid] = STATUS_ACTIVE
            sess.completed = True
            daily = self._user_state[uid]
            daily.total_txn_count = max(0, daily.total_txn_count - 5)
            return {"success": True, "message": "Verification complete. Transaction Approved.", "account_status": STATUS_ACTIVE}
        else:
            # otp_service already deleted the record on max-attempts
            # Check if the session is now exhausted
            if not otp_service.has_active_session(sess.phone):
                # Determine if it was attempt exhaustion or expiry
                if "attempts" in message.lower() or "exceeded" in message.lower():
                    self._account_status[uid] = STATUS_HARD_BLOCKED
                    daily = self._user_state[uid]
                    today = self._get_today()
                    daily.hard_block_dates.append(today)
                    if self._hard_block_count_last_7_days(daily) >= HARD_BLOCK_THRESHOLD:
                        self._account_status[uid] = STATUS_ADMIN_REVIEW
                        return {"success": False, "message": "3 hard blocks in 7 days. Account escalated to Admin Review.", "account_status": STATUS_ADMIN_REVIEW}
                    return {"success": False, "message": "Max OTP attempts exceeded. Account HARD BLOCKED for 24h.", "account_status": STATUS_HARD_BLOCKED}
            return {"success": False, "message": message, "account_status": self._account_status.get(uid, STATUS_UNDER_REVIEW)}

    def get_account_status(self, uid: str) -> str:
        return self._account_status.get(uid, STATUS_ACTIVE)

    # ── Bulk batch scoring (for dashboard load) ────────────────────────────────

    def batch_score(self, df) -> list[dict]:
        """Score an entire DataFrame of transactions."""
        self.results = []
        for _, row in df.iterrows():
            self.score_transaction(row.to_dict())
        return self.results

    # ── Analytics helpers ──────────────────────────────────────────────────────

    def summary_stats(self) -> dict:
        if not self.results:
            return {}
        total = len(self.results)
        suspicious = sum(1 for r in self.results if r["risk_level"] in ("Medium", "High"))
        high_risk = sum(1 for r in self.results if r["risk_level"] == "High")
        blocked = sum(1 for r in self.results if r["decision"] == "BLOCKED")
        two_fa = sum(1 for r in self.results if r["decision"] == "2FA_REQUIRED")
        approved = sum(1 for r in self.results if r["decision"] == "APPROVED")
        avg_score: float = sum(r["fraud_score"] for r in self.results) / total if total else 0.0
        limit_violations = sum(
            1 for r in self.results
            if any("limit" in reason.lower() or "spam" in reason.lower() for reason in r["reasons"])
        )
        return {
            "total": total,
            "suspicious": suspicious,
            "high_risk": high_risk,
            "blocked": blocked,
            "two_fa_triggered": two_fa,
            "approved": approved,
            "avg_fraud_score": round(float(avg_score), 1),
            "limit_violations": limit_violations,
        }
