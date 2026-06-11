"""
SentinelPay — Geo-Risk Engine
Flags physically impossible travel between consecutive transactions.
"""

import math


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance in km between two GPS points."""
    R = 6371.0  # Earth radius in km
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(d_lon / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def geo_risk(txn: dict, user_history) -> int:
    """
    Score geographic risk based on implied travel speed.

    Returns
    -------
    int  — 0, 10, or 20
    """
    if not user_history:
        return 0

    prev = user_history[-1]
    dist_km = _haversine(prev["lat"], prev["lon"], txn["lat"], txn["lon"])
    time_diff_hrs = (txn["timestamp"] - prev["timestamp"]) / 3600

    if time_diff_hrs <= 0:
        return 20 if dist_km > 0 else 0

    speed_kmph = dist_km / time_diff_hrs

    if speed_kmph > 1000:
        return 20
    if speed_kmph > 500:
        return 10
    return 0
