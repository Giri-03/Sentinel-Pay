"""
SentinelPay — Full Fraud Detection Dashboard
Run: streamlit run dashboard.py

Tabs:
  0. Login          — phone-number + OTP login
  1. Overview       — system metrics at a glance
  2. Transaction Log — all scored transactions
  3. Live Simulation — enter a transaction, get instant score
  4. 2-Step Verification — Passkey + OTP flow
  5. Account Status — per-user status viewer
"""

import os
import time
import streamlit as st
import pandas as pd

import otp_service
from data_pipeline import run_pipeline
from fraud_engine import (
    FraudEngine,
    STATUS_ACTIVE, STATUS_UNDER_REVIEW, STATUS_HARD_BLOCKED, STATUS_ADMIN_REVIEW,
    SMALL_TXN_LIMIT, TOTAL_TXN_LIMIT,
)

# ─────────────────────────────────────────────────────────────────────────────
# Page config (must be first Streamlit call)
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SentinelPay — Fraud Detection Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Custom CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: #0d1117; color: #e6edf3; }

/* Metric cards */
.metric-card {
    background: linear-gradient(135deg, #161b22 0%, #21262d 100%);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 1.2rem 1rem;
    text-align: center;
    margin-bottom: 0.5rem;
}
.metric-card .label  { font-size: 0.78rem; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; margin-bottom: .3rem; }
.metric-card .value  { font-size: 2rem; font-weight: 700; }

/* Risk colours */
.risk-low    { color: #3fb950; }
.risk-medium { color: #d29922; }
.risk-high   { color: #f85149; }
.risk-block  { color: #8b949e; }

/* Status chips */
.chip {
    display:inline-block; padding:.25rem .7rem;
    border-radius: 20px; font-size:.75rem; font-weight:600;
}
.chip-active   { background:#1a3a24; color:#3fb950; }
.chip-review   { background:#3b2a08; color:#d29922; }
.chip-blocked  { background:#3a1a1a; color:#f85149; }
.chip-admin    { background:#2a1a3a; color:#a371f7; }

/* Sidebar */
section[data-testid="stSidebar"] { background: #161b22 !important; }

/* Score gauge bar */
.gauge-track { background:#21262d; border-radius:4px; height:8px; width:100%; margin-top:.4rem; }
.gauge-fill  { height:8px; border-radius:4px; }

/* Captcha OTP display */
.captcha-box {
    margin-top: 0.6rem;
    padding: 14px 24px;
    display: inline-block;
    width: 100%;
    text-align: center;
    font-family: 'Courier New', monospace;
    font-size: 2.6rem;
    font-weight: 900;
    letter-spacing: 0.55em;
    color: #f0c040;
    background: repeating-linear-gradient(
        45deg,
        #1e2430,
        #1e2430 10px,
        #1a1f2c 10px,
        #1a1f2c 20px
    );
    border: 2.5px dashed #888;
    border-radius: 6px;
    user-select: none;
    text-shadow: 1px 1px 0 #000, -1px -1px 0 #333;
    transform: skewX(-3deg);
}
.captcha-label {
    font-size: 0.72rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: .1em;
    margin-top: .6rem;
}

/* OTP modal card */
.otp-modal {
    background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
    border: 1px solid #30363d;
    border-radius: 16px;
    padding: 1.5rem;
    margin-top: 1rem;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Session State Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_data(show_spinner="Loading & merging datasets…")
def load_dataset() -> pd.DataFrame:
    base = os.path.dirname(os.path.abspath(__file__))
    cache_path = os.path.join(base, "final_dashboard_dataset.csv")
    if not os.path.exists(cache_path):
        return run_pipeline()
    return pd.read_csv(cache_path)


def _init():
    defaults = {
        "engine": FraudEngine(),
        "scored": False,
        "results_df": None,
        # Transaction 2FA state
        "verif_uid": "",
        "verif_txn": "",
        "verif_step": "idle",   # idle | passkey | otp | done
        "verif_phone": "",
        "otp_message": "",
        "otp_success": False,
        # Login state
        "login_phone": "",
        "login_step": "idle",   # idle | otp | done
        "login_message": "",
        "login_success": False,
        "logged_in_user": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init()
engine: FraudEngine = st.session_state.engine


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _score_gauge(score: int) -> str:
    pct = min(score, 100)
    colour = "#3fb950" if score < 30 else "#d29922" if score <= 60 else "#f85149"
    return (
        f'<div class="gauge-track">'
        f'<div class="gauge-fill" style="width:{pct}%;background:{colour};"></div>'
        f'</div>'
    )


def _risk_badge(level: str) -> str:
    classes = {"Low": "risk-low", "Medium": "risk-medium", "High": "risk-high"}
    icons   = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}
    cls = classes.get(level, "risk-block")
    icon = icons.get(level, "⚫")
    return f'<span class="{cls}">{icon} {level}</span>'


def _status_chip(status: str) -> str:
    mapping = {
        STATUS_ACTIVE:       ("chip-active",  "✅ Active"),
        STATUS_UNDER_REVIEW: ("chip-review",  "⚠️ Under Review"),
        STATUS_HARD_BLOCKED: ("chip-blocked", "🚫 Hard Blocked"),
        STATUS_ADMIN_REVIEW: ("chip-admin",   "👤 Admin Review"),
    }
    cls, label = mapping.get(status, ("chip-review", status))
    return f'<span class="chip {cls}">{label}</span>'


def _card(label: str, value, colour_cls: str = "") -> str:
    return (
        f'<div class="metric-card">'
        f'<div class="label">{label}</div>'
        f'<div class="value {colour_cls}">{value}</div>'
        f'</div>'
    )


def _otp_modal(
    phone: str,
    purpose: str,
    success_key: str,
    message_key: str,
    step_key: str,
    done_step: str = "done",
    form_key: str = "otp_form",
) -> None:
    """
    Unified OTP modal UI component.
    Renders countdown timer, input form, OTP hint below input, and resend button.
    Works for both login and transaction verification contexts.
    """
    st.markdown('<div class="otp-modal">', unsafe_allow_html=True)
    st.markdown("#### 🔐 OTP Verification")

    otp_val = otp_service.get_otp_display(phone)
    secs    = otp_service.seconds_remaining(phone)

    if not (otp_val and secs > 0):
        st.warning("OTP session expired or not yet generated.")
        if st.button("🔄 Resend OTP", key=f"resend_{form_key}"):
            otp_service.resend_otp(phone, purpose)
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        return

    # Countdown timer shown above input
    if secs > 30:
        st.success(f"⏱️ OTP valid for **{secs}s**  ·  Max 3 attempts")
    elif secs > 10:
        st.warning(f"⏱️ Expiring in **{secs}s** — enter quickly!")
    else:
        st.error(f"⏱️ **{secs}s** left!")

    with st.form(form_key):
        entered = st.text_input(
            "Enter 6-digit OTP",
            max_chars=6,
            placeholder="••••••",
            help="Enter the 6-digit code shown below",
        )
        col_verify, col_resend = st.columns([3, 1])
        submit_otp = col_verify.form_submit_button("✅ Verify OTP", type="primary", use_container_width=True)
        resend_btn = col_resend.form_submit_button("🔄 Resend", use_container_width=True)

    # ── Captcha OTP display below the input ────────────────────────────────────
    st.markdown('<p class="captcha-label">🔑 Read the code below and type it above:</p>', unsafe_allow_html=True)
    st.markdown(f'<div class="captcha-box">{otp_val}</div>', unsafe_allow_html=True)
    # ─────────────────────────────────────────────────────────────────────────

    if submit_otp:
        success, message = otp_service.verify_otp(phone, entered, expected_purpose=purpose)
        st.session_state[success_key] = success
        st.session_state[message_key] = message
        if success:
            st.session_state[step_key] = done_step
        st.rerun()

    if resend_btn:
        otp_service.resend_otp(phone, purpose)
        st.session_state[message_key] = "New OTP sent!"
        st.rerun()

    if st.session_state[message_key]:
        if st.session_state[success_key]:
            st.success(st.session_state[message_key])
        else:
            st.error(st.session_state[message_key])

    st.markdown("</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ SentinelPay")
    st.caption("Rule-Based Fraud Detection System")

    if st.session_state.logged_in_user:
        st.success(f"👤 Logged in: **{st.session_state.logged_in_user}**")
    else:
        st.warning("🔒 Not logged in")

    st.divider()

    if st.button("▶ Score All Transactions", use_container_width=True, type="primary"):
        df = load_dataset()
        with st.spinner("Scoring transactions…"):
            results = engine.batch_score(df)
            st.session_state.results_df = pd.DataFrame(results)
            st.session_state.scored = True
        st.rerun()

    if st.button("🔄 Reset System", use_container_width=True):
        st.session_state.engine = FraudEngine()
        st.session_state.scored = False
        st.session_state.results_df = None
        st.session_state.verif_step = "idle"
        st.session_state.login_step = "idle"
        st.session_state.logged_in_user = None
        st.rerun()

    st.divider()
    st.caption(f"Small Txn Limit / Day: **{SMALL_TXN_LIMIT}**")
    st.caption(f"Total Txn Limit / Day: **{TOTAL_TXN_LIMIT}**")
    st.caption("OTP validity: **60 seconds**")
    st.caption("Max OTP attempts: **3**")


# ─────────────────────────────────────────────────────────────────────────────
# Main Title
# ─────────────────────────────────────────────────────────────────────────────
st.title("🛡️ SentinelPay — Real-Time Fraud Detection Dashboard")
st.caption("Rule-based fraud scoring engine · Unified OTP · 2-Step verification · Daily limit enforcement")

# ─────────────────────────────────────────────────────────────────────────────
# Tabs
# ─────────────────────────────────────────────────────────────────────────────
tab0, tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "� Login",
    "�📊 Overview",
    "📋 Transaction Log",
    "⚡ Live Simulation",
    "🔐 2-Step Verification",
    "👤 Account Status",
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 0: Login
# ══════════════════════════════════════════════════════════════════════════════
with tab0:
    st.subheader("🔑 Phone Number Login")
    st.caption("Enter your registered phone number to receive an OTP.")

    if st.session_state.login_step == "done" and st.session_state.logged_in_user:
        st.success(f"✅ You are logged in as **{st.session_state.logged_in_user}**")
        st.balloons()
        if st.button("🚪 Logout"):
            st.session_state.login_step = "idle"
            st.session_state.logged_in_user = None
            st.session_state.login_phone = ""
            st.session_state.login_message = ""
            st.rerun()

    elif st.session_state.login_step == "idle":
        with st.form("login_form"):
            phone_input = st.text_input(
                "Phone Number",
                placeholder="+91 9876543210",
                help="Enter the phone number registered with SentinelPay",
            )
            send_btn = st.form_submit_button("📱 Send OTP", type="primary", use_container_width=True)

        if send_btn:
            phone_clean = phone_input.strip()
            if len(phone_clean) < 10:
                st.error("Please enter a valid phone number (min 10 digits).")
            else:
                otp_service.generate_otp(phone_clean, purpose="login")
                st.session_state.login_phone = phone_clean
                st.session_state.login_step = "otp"
                st.session_state.login_message = ""
                st.rerun()

    elif st.session_state.login_step == "otp":
        st.info(f"🔐 OTP generated for **{st.session_state.login_phone}** — read the captcha below and enter it above.")
        if st.session_state.login_message:
            st.error(st.session_state.login_message)

        _otp_modal(
            phone=st.session_state.login_phone,
            purpose="login",
            success_key="login_success",
            message_key="login_message",
            step_key="login_step",
            done_step="done",
            form_key="login_otp_form",
        )

        # After successful OTP, set logged-in user
        if st.session_state.login_step == "done" and st.session_state.login_success:
            st.session_state.logged_in_user = st.session_state.login_phone
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: Overview
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    if not st.session_state.scored:
        st.info("Click **▶ Score All Transactions** in the sidebar to begin.")
    else:
        stats = engine.summary_stats()
        c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
        with c1:  st.markdown(_card("Total Transactions", stats["total"]), unsafe_allow_html=True)
        with c2:  st.markdown(_card("Suspicious", stats["suspicious"], "risk-medium"), unsafe_allow_html=True)
        with c3:  st.markdown(_card("High Risk", stats["high_risk"], "risk-high"), unsafe_allow_html=True)
        with c4:  st.markdown(_card("Blocked", stats["blocked"], "risk-block"), unsafe_allow_html=True)
        with c5:  st.markdown(_card("2FA Triggered", stats["two_fa_triggered"], "risk-medium"), unsafe_allow_html=True)
        with c6:  st.markdown(_card("Approved", stats["approved"], "risk-low"), unsafe_allow_html=True)
        with c7:  st.markdown(_card("Limit Violations", stats["limit_violations"], "risk-high"), unsafe_allow_html=True)

        st.divider()

        rdf = st.session_state.results_df
        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Risk Level Distribution")
            risk_counts = rdf["risk_level"].value_counts()
            st.bar_chart(risk_counts, color=["#d29922"])

        with col_right:
            st.subheader("Decision Breakdown")
            dec_counts = rdf["decision"].value_counts()
            st.bar_chart(dec_counts, color=["#3fb950"])

        st.subheader("Fraud Score Distribution (Last 200 Txns)")
        score_data = rdf["fraud_score"].tail(200)
        st.area_chart(score_data, color="#a371f7")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: Transaction Log
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    if not st.session_state.scored:
        st.info("Score transactions first using the sidebar button.")
    else:
        rdf = st.session_state.results_df

        # Filters
        f1, f2, f3 = st.columns(3)
        with f1:
            risk_filter = st.multiselect("Risk Level", ["Low", "Medium", "High"], default=["Medium", "High"])
        with f2:
            dec_filter = st.multiselect("Decision", ["APPROVED", "2FA_REQUIRED", "BLOCKED"], default=["2FA_REQUIRED", "BLOCKED"])
        with f3:
            search = st.text_input("Search User ID / TXN ID")

        filtered = rdf.copy()
        if risk_filter:
            filtered = filtered[filtered["risk_level"].isin(risk_filter)]
        if dec_filter:
            filtered = filtered[filtered["decision"].isin(dec_filter)]
        if search:
            filtered = filtered[
                filtered["user_id"].str.contains(search, case=False, na=False) |
                filtered["txn_id"].str.contains(search, case=False, na=False)
            ]

        st.caption(f"Showing **{len(filtered)}** transactions")

        for _, row in filtered.head(80).iterrows():
            with st.container():
                cols = st.columns([2, 1.2, 1, 1, 1.5, 3])
                cols[0].markdown(f"**{row['txn_id']}**  \n`{row['user_id']}`")
                cols[1].markdown(f"₹{row['amount']:,.0f}")
                cols[2].markdown(_risk_badge(row["risk_level"]), unsafe_allow_html=True)
                cols[3].markdown(f"**{row['fraud_score']}**")
                cols[3].markdown(_score_gauge(row['fraud_score']), unsafe_allow_html=True)

                dec = row["decision"]
                dec_color = {"APPROVED": "#3fb950", "2FA_REQUIRED": "#d29922", "BLOCKED": "#f85149"}.get(dec, "#8b949e")
                cols[4].markdown(f"<span style='color:{dec_color};font-weight:700'>{dec}</span>", unsafe_allow_html=True)
                cols[4].markdown(_status_chip(row["account_status"]), unsafe_allow_html=True)

                reasons_str = " · ".join(row["reasons"]) if row["reasons"] else "—"
                cols[5].caption(reasons_str)
            st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: Live Simulation
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("⚡ Live Transaction Simulation")
    st.caption("Enter transaction details below and instantly see the fraud score and decision.")

    with st.form("live_sim"):
        c1, c2, c3 = st.columns(3)
        with c1:
            sim_uid    = st.text_input("User ID", value=st.session_state.logged_in_user or "USER_42")
            sim_amount = st.number_input("Amount (₹)", min_value=1, max_value=500000, value=75000)
            sim_failed = st.slider("Failed Attempts (last 10 min)", 0, 10, 0)
        with c2:
            sim_intl = st.selectbox("International IP?", ["No", "Yes"])
            sim_receiver_risk = st.selectbox("Receiver Risk Category", ["Low", "Medium", "High"])
            sim_merchant = st.selectbox("Merchant Category", [
                "Electronics", "Travel", "Food", "Utilities", "Entertainment", "Gaming", "Crypto", "ATM"
            ])
        with c3:
            sim_channel = st.selectbox("Payment Channel", ["UPI", "NEFT", "RTGS", "IMPS", "Collect", "QR", "Intent"])
            sim_hour    = st.slider("Transaction Hour (0-23)", 0, 23, 14)
            sim_txn_id  = st.text_input("TXN ID (optional)", value=f"SIM_{int(time.time())}")
            # Phone number for OTP (pre-filled from logged-in user)
            sim_phone   = st.text_input(
                "Phone for OTP",
                value=st.session_state.login_phone or "+91 9999999999",
                help="OTP will be sent here if 2FA is required",
            )

        submitted = st.form_submit_button("🔍 Score This Transaction", type="primary", use_container_width=True)

    if submitted:
        sim_txn = {
            "transaction_id": sim_txn_id,
            "user_id": sim_uid,
            "amount": sim_amount,
            "failed_attempts_last_10_min": sim_failed,
            "is_international_ip": sim_intl,
            "receiver_risk_category": sim_receiver_risk,
            "merchant_category": sim_merchant,
            "payment_channel": sim_channel,
            "hour": sim_hour,
            "timestamp": f"2026-02-21 {sim_hour:02d}:00:00",
            "account_status": engine.get_account_status(sim_uid),
        }
        result = engine.score_transaction(sim_txn)

        st.divider()
        cs1, cs2, cs3, cs4 = st.columns(4)
        score = result["fraud_score"]
        risk  = result["risk_level"]
        cs1.metric("Fraud Score", score)
        cs2.markdown(_risk_badge(risk), unsafe_allow_html=True)
        cs3.markdown(f"**Decision:** `{result['decision']}`")
        cs4.markdown(_status_chip(result["account_status"]), unsafe_allow_html=True)

        st.markdown(_score_gauge(score), unsafe_allow_html=True)

        if result["reasons"]:
            st.warning("**Fraud Signals Detected:**\n" + "\n".join(f"- {r}" for r in result["reasons"]))
        else:
            st.success("No fraud signals detected. Transaction appears clean.")

        if result["decision"] == "2FA_REQUIRED":
            st.info("� OTP verification required for this transaction.")
            # Store context and generate OTP immediately
            phone_key = sim_phone.strip() or sim_uid
            st.session_state.verif_uid   = sim_uid
            st.session_state.verif_txn   = sim_txn_id
            st.session_state.verif_phone = phone_key
            st.session_state.verif_step  = "passkey"
            st.session_state.otp_message = ""
            engine.start_verification(sim_uid, sim_txn_id, phone=phone_key)
            # Auto-pass passkey for demo and generate OTP
            engine.verify_passkey(sim_uid)
            st.session_state.verif_step = "otp"

            st.divider()
            st.markdown("### � Inline OTP Verification")
            _otp_modal(
                phone=phone_key,
                purpose="transaction",
                success_key="otp_success",
                message_key="otp_message",
                step_key="verif_step",
                done_step="done",
                form_key="inline_otp_form",
            )
            if st.session_state.verif_step == "done" and st.session_state.otp_success:
                engine.verify_otp(sim_uid, otp_service.get_otp_display(phone_key) or "")
                st.success("✅ Transaction approved after OTP verification!")

        if result["decision"] == "BLOCKED":
            st.error("🚫 This account is hard-blocked.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4: 2-Step Verification
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🔐 2-Step Verification Flow")
    st.caption("Passkey biometric → OTP confirmation. Simulates WebAuthn + SMS/email OTP.")

    verif_uid = st.text_input("User ID to Verify", value=st.session_state.verif_uid, key="v_uid_input")
    verif_phone_input = st.text_input(
        "Phone for OTP",
        value=st.session_state.verif_phone or st.session_state.login_phone or "+91 9999999999",
        key="v_phone_input",
        help="OTP will be dispatched to this number",
    )

    if verif_uid != st.session_state.verif_uid:
        st.session_state.verif_uid   = verif_uid
        st.session_state.verif_step  = "passkey"
        st.session_state.verif_phone = verif_phone_input.strip()

    step = st.session_state.verif_step

    st.divider()
    prog_cols = st.columns(3)
    prog_cols[0].markdown(
        f"**Step 1 — Passkey** {'✅' if step in ('otp','done') else ('🔵' if step == 'passkey' else '⬜')}"
    )
    prog_cols[1].markdown(
        f"**Step 2 — OTP** {'✅' if step == 'done' else ('🔵' if step == 'otp' else '⬜')}"
    )
    prog_cols[2].markdown(
        f"**Result** {'✅ Verified' if step == 'done' else '⬜ Pending'}"
    )
    st.divider()

    if step == "idle" or not verif_uid:
        st.info("Run a simulation in **⚡ Live Simulation** tab first, or enter a User ID above.")

    elif step == "passkey":
        st.markdown("### Step 1 — Passkey / Biometric Authentication")
        st.markdown("""
> **Simulated WebAuthn flow** — In production, the browser triggers the device's biometric
> authenticator (Face ID, fingerprint, Windows Hello). For this demo, clicking the button
> simulates a successful biometric match.
        """)
        if st.button("🔑 Authenticate with Passkey", type="primary", use_container_width=True):
            phone_key = verif_phone_input.strip() or verif_uid
            st.session_state.verif_phone = phone_key
            engine.start_verification(verif_uid, st.session_state.verif_txn, phone=phone_key)
            engine.verify_passkey(verif_uid)   # generates OTP via otp_service
            st.session_state.verif_step = "otp"
            st.session_state.otp_message = ""
            st.rerun()

    elif step == "otp":
        st.markdown("### Step 2 — OTP Verification")
        phone_key = st.session_state.verif_phone or verif_uid

        _otp_modal(
            phone=phone_key,
            purpose="transaction",
            success_key="otp_success",
            message_key="otp_message",
            step_key="verif_step",
            done_step="done",
            form_key="tab4_otp_form",
        )

        # If OTP verified via modal, also update engine account status
        if st.session_state.verif_step == "done" and st.session_state.otp_success:
            engine._account_status[verif_uid] = STATUS_ACTIVE
            daily = engine._user_state[verif_uid]
            daily.total_txn_count = max(0, daily.total_txn_count - 5)

    elif step == "done":
        st.success("✅ **Verification Complete!** Transaction approved and risk counter reset.")
        st.balloons()
        if st.button("🔄 Start New Verification"):
            st.session_state.verif_step = "idle"
            st.session_state.otp_message = ""
            st.session_state.otp_success = False
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5: Account Status
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("👤 Account Status Viewer")
    if not st.session_state.scored:
        st.info("Score transactions first to see account statuses.")
    else:
        rdf = st.session_state.results_df

        # Aggregate per user: last status, max score, txn count
        summary = (
            rdf.groupby("user_id")
            .agg(
                txn_count=("txn_id", "count"),
                max_score=("fraud_score", "max"),
                avg_score=("fraud_score", "mean"),
                last_status=("account_status", "last"),
                high_risk_count=("risk_level", lambda x: int((pd.Series(x) == "High").sum())),
            )
            .reset_index()
        )

        # Filter controls
        sa, sb = st.columns(2)
        status_filter = sa.multiselect(
            "Filter by Status",
            [STATUS_ACTIVE, STATUS_UNDER_REVIEW, STATUS_HARD_BLOCKED, STATUS_ADMIN_REVIEW],
            default=[STATUS_UNDER_REVIEW, STATUS_HARD_BLOCKED, STATUS_ADMIN_REVIEW],
        )
        user_search = sb.text_input("Search User ID", key="acct_search")

        filtered_summary = summary.copy()
        if status_filter:
            filtered_summary = filtered_summary[filtered_summary["last_status"].isin(status_filter)]
        if user_search:
            filtered_summary = filtered_summary[
                filtered_summary["user_id"].str.contains(user_search, case=False, na=False)
            ]

        st.caption(f"Showing **{len(filtered_summary)}** accounts")

        for _, row in filtered_summary.iterrows():
            c1, c2, c3, c4, c5 = st.columns([2, 1, 1, 1, 2])
            c1.markdown(f"**{row['user_id']}**")
            c2.metric("Transactions", int(row["txn_count"]))
            c3.metric("Max Score", int(row["max_score"]))
            c4.metric("High Risk", int(row["high_risk_count"]))
            c5.markdown(_status_chip(row["last_status"]), unsafe_allow_html=True)
            st.divider()

        st.subheader("Status Summary")
        status_dist = summary["last_status"].value_counts()
        st.bar_chart(status_dist, color=["#d29922"])
