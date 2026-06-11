"""
SentinelPay — Data Pipeline
Loads SampleDataSet-1.csv (User Master) + SampleDataSet-2.csv (Transactions),
merges on user_id, engineers features, and saves final_dashboard_dataset.csv.
"""

import pandas as pd
import os
from typing import Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Standardise column names: lowercase, spaces → underscores."""
    df.columns = (
        df.columns.str.strip()
        .str.lower()
        .str.replace(" ", "_", regex=False)
        .str.replace("-", "_", regex=False)
    )
    return df


def run_pipeline(
    txn_path: Optional[str] = None,
    user_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> pd.DataFrame:
    """
    Full pipeline:
    1. Load both CSVs
    2. Standardise column names
    3. LEFT JOIN transactions ← user master on user_id
    4. Feature engineering
    5. Save final_dashboard_dataset.csv
    Returns the processed DataFrame.
    """
    txn_path = txn_path or os.path.join(BASE_DIR, "SampleDataSet-2.csv")
    user_path = user_path or os.path.join(BASE_DIR, "SampleDataSet-1.csv")
    output_path = output_path or os.path.join(BASE_DIR, "final_dashboard_dataset.csv")

    # ── 1. Load ──────────────────────────────────────────────────────
    print("[Pipeline] Loading datasets...")
    txn_df = pd.read_csv(txn_path, encoding="utf-8-sig")
    user_df = pd.read_csv(user_path, encoding="utf-8-sig")

    # ── 2. Clean column names ────────────────────────────────────────
    txn_df = _clean_columns(txn_df)
    user_df = _clean_columns(user_df)

    print(f"  Transactions : {len(txn_df):,} rows, cols: {list(txn_df.columns)}")
    print(f"  Users        : {len(user_df):,} rows, cols: {list(user_df.columns)}")

    # ── 3. LEFT JOIN on user_id ──────────────────────────────────────
    # Avoid duplicate columns (e.g. if both sides share non-key columns)
    extra_user_cols: list[str] = [
        str(c) for c in user_df.columns
        if c not in txn_df.columns or c == "user_id"
    ]
    if "user_id" not in extra_user_cols:
        extra_user_cols.insert(0, "user_id")
    user_cols: list[str] = extra_user_cols
    merged = txn_df.merge(user_df[user_cols], on="user_id", how="left")
    print(f"  Merged shape : {merged.shape}")

    # ── 4. Feature Engineering ───────────────────────────────────────
    # timestamp → datetime
    merged["timestamp"] = pd.to_datetime(merged["timestamp"], errors="coerce")
    merged["hour"] = merged["timestamp"].dt.hour

    # Boolean flags
    merged["is_night"] = merged["hour"].between(0, 5)
    merged["high_amount"] = merged["amount"].astype(float) > 10_000
    merged["small_transaction"] = merged["amount"].astype(float) < 2_000

    # Ensure numeric fields are correct dtype
    merged["amount"] = pd.to_numeric(merged["amount"], errors="coerce").fillna(0)
    merged["failed_attempts_last_10_min"] = pd.to_numeric(
        merged.get("failed_attempts_last_10_min", 0), errors="coerce"
    ).fillna(0)

    # Handle NaN in key categorical columns
    for col in ["is_international_ip", "receiver_risk_category",
                 "risk_category", "kyc_status", "account_status",
                 "payment_channel", "merchant_category"]:
        if col in merged.columns:
            merged[col] = merged[col].fillna("Unknown")

    # ── 5. Save ──────────────────────────────────────────────────────
    merged.to_csv(output_path, index=False)
    print(f"  Saved → {output_path}")
    print(f"  Columns in output: {list(merged.columns)}")

    fraud_preview = (merged["amount"] > 50_000).sum()
    print(f"  Transactions with amount > 50k: {fraud_preview:,}")

    return merged


if __name__ == "__main__":
    df = run_pipeline()
    print("\n[Pipeline] Done.")
    print(df.head(3).to_string())
