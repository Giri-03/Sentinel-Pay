"""
SentinelPay — OTP Service (Demo / Captcha Mode)

OTPs are generated server-side and returned directly to the frontend
for display as a visual captcha. No SMS provider is needed.

Flow:
  1. generate_otp(phone, purpose) → returns OTP string
  2. Frontend shows it as a captcha image below the input
  3. User reads it and types it in
  4. verify_otp(phone, entered) → True/False
"""

from __future__ import annotations
import random
import time
from typing import Optional


# ── In-memory OTP store (key = phone number) ──────────────────────────────────
OTP_STORE: dict[str, dict] = {}

OTP_VALIDITY_SECS: int = 60
OTP_MAX_ATTEMPTS:  int = 3


# ── OTP Lifecycle ─────────────────────────────────────────────────────────────

def generate_otp(phone: str, purpose: str) -> str:
    """
    Generate a fresh 6-digit OTP for *phone* with *purpose* context.
    Stores it server-side and returns the code for captcha display.
    """
    otp = str(random.randint(100_000, 999_999))
    OTP_STORE[phone] = {
        "otp": otp,
        "expires_at": time.time() + OTP_VALIDITY_SECS,
        "attempts": 0,
        "purpose": purpose,
    }
    return otp


def resend_otp(phone: str, purpose: str) -> str:
    """Clear the old record and generate a fresh OTP. Returns the new OTP."""
    OTP_STORE.pop(phone, None)
    return generate_otp(phone, purpose)


def get_otp_display(phone: str) -> Optional[str]:
    """Return the current OTP for captcha display. None if expired/missing."""
    record = OTP_STORE.get(phone)
    if not record:
        return None
    if time.time() > record["expires_at"]:
        OTP_STORE.pop(phone, None)
        return None
    return record["otp"]


def seconds_remaining(phone: str) -> int:
    """Return seconds until OTP expiry (0 if expired/missing)."""
    record = OTP_STORE.get(phone)
    if not record:
        return 0
    return max(0, int(record["expires_at"] - time.time()))


def has_active_session(phone: str) -> bool:
    """True if an unexpired OTP session exists for this phone."""
    record = OTP_STORE.get(phone)
    if not record:
        return False
    if time.time() > record["expires_at"]:
        OTP_STORE.pop(phone, None)
        return False
    return True


def verify_otp(
    phone: str,
    entered_otp: str,
    expected_purpose: Optional[str] = None,
) -> tuple[bool, str]:
    """
    Validate *entered_otp* for *phone*.
    Returns (success: bool, message: str).
    """
    record = OTP_STORE.get(phone)

    if not record:
        return False, "No active OTP session. Please request a new OTP."

    if time.time() > record["expires_at"]:
        OTP_STORE.pop(phone, None)
        return False, "OTP expired (60 s). Please request a new OTP."

    if expected_purpose and record["purpose"] != expected_purpose:
        return False, f"OTP not valid for this context (expected: {expected_purpose})."

    if record["attempts"] >= OTP_MAX_ATTEMPTS:
        OTP_STORE.pop(phone, None)
        return False, "Maximum OTP attempts exceeded. Please request a new OTP."

    if entered_otp.strip() == record["otp"]:
        OTP_STORE.pop(phone, None)
        return True, "OTP verified successfully."
    else:
        record["attempts"] += 1
        remaining = OTP_MAX_ATTEMPTS - record["attempts"]
        if remaining <= 0:
            OTP_STORE.pop(phone, None)
            return False, "Maximum OTP attempts exceeded. Please request a new OTP."
        return False, f"Incorrect OTP. {remaining} attempt(s) remaining."


# Kept for backward-compat — always False (no real SMS in demo mode)
def is_real_sms_mode() -> bool:
    return False
