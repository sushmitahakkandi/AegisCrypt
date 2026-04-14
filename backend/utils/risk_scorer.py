"""
Risk Scoring Engine
Calculates a 0-100 risk score on every login attempt.
Factors (simplified — no keystroke dynamics):
  - Failed attempts in last 10 min:  25 points
  - New IP address:                  20 points
  - Unusual hour (00:00–06:00):      15 points
  - New device fingerprint:          20 points
  - Country mismatch:                20 points
                              Total: 100 points

Graduated response:
  0–30   → Allow
  31–60  → Require OTP verification
  61–100 → Block and alert
"""

from datetime import datetime, timedelta
from models import get_connection


def calculate_risk_score(user_id, ip_address, device_fingerprint, country=None):
    """Calculate risk score for a login attempt. Returns (score, breakdown)."""
    score = 0
    breakdown = {}
    conn = get_connection()
    cur = conn.cursor()

    try:
        # Factor 1: Failed attempts in last 10 minutes (0-25 pts)
        ten_min_ago = datetime.utcnow() - timedelta(minutes=10)
        cur.execute(
            "SELECT COUNT(*) as cnt FROM login_attempts WHERE email = (SELECT email FROM users WHERE id=%s) "
            "AND success = FALSE AND attempted_at > %s",
            (user_id, ten_min_ago)
        )
        row = cur.fetchone()
        failed = row['cnt'] if row else 0
        failed_pts = min(int(failed) * 5, 25)
        score += failed_pts
        breakdown['failed_attempts'] = {'count': int(failed), 'points': failed_pts}

        # Factor 2: New IP address (0-20 pts)
        cur.execute(
            "SELECT COUNT(*) as cnt FROM login_attempts WHERE user_id=%s AND ip_address=%s AND success=TRUE",
            (user_id, ip_address)
        )
        row = cur.fetchone()
        seen_ip = (row['cnt'] if row else 0) > 0
        ip_pts = 0 if seen_ip else 20
        score += ip_pts
        breakdown['new_ip'] = {'is_new': not seen_ip, 'points': ip_pts}

        # Factor 3: Unusual hour (0-15 pts)
        current_hour = datetime.utcnow().hour
        unusual = current_hour < 6
        hour_pts = 15 if unusual else 0
        score += hour_pts
        breakdown['unusual_hour'] = {'hour': current_hour, 'unusual': unusual, 'points': hour_pts}

        # Factor 4: New device fingerprint (0-20 pts)
        cur.execute(
            "SELECT COUNT(*) as cnt FROM login_attempts WHERE user_id=%s AND device_fingerprint=%s AND success=TRUE",
            (user_id, device_fingerprint or 'unknown')
        )
        row = cur.fetchone()
        seen_device = (row['cnt'] if row else 0) > 0
        device_pts = 0 if seen_device else 20
        score += device_pts
        breakdown['new_device'] = {'is_new': not seen_device, 'points': device_pts}

        # Factor 5: Country mismatch (0-20 pts)
        if country:
            cur.execute(
                "SELECT country FROM login_attempts WHERE user_id=%s AND success=TRUE ORDER BY attempted_at DESC LIMIT 1",
                (user_id,)
            )
            row = cur.fetchone()
            last_country = row['country'] if row else None
            mismatch = last_country is not None and last_country != country
            country_pts = 20 if mismatch else 0
            score += country_pts
            breakdown['country_mismatch'] = {
                'current': country, 'last': last_country, 'mismatch': mismatch, 'points': country_pts
            }
        else:
            breakdown['country_mismatch'] = {'current': None, 'points': 0}

    finally:
        cur.close()
        conn.close()

    score = min(score, 100)
    return score, breakdown


def get_risk_action(score):
    """Return action based on risk score."""
    if score <= 30:
        return 'allow'
    elif score <= 60:
        return 'otp_required'
    else:
        return 'blocked'
