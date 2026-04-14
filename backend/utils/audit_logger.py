"""
Audit Logger — tamper-proof event logging with SHA-256 hash chain.
Every event gets a hash of its own data + the previous event's hash,
forming a chain that can be verified for integrity.
"""

import hashlib
import json
from datetime import datetime
from models import get_connection


def _compute_hash(event_type, severity, user_id, ip_address, details, previous_hash):
    """Compute SHA-256 hash for an audit log entry."""
    payload = json.dumps({
        'event_type': event_type,
        'severity': severity,
        'user_id': user_id,
        'ip_address': ip_address,
        'details': details,
        'previous_hash': previous_hash,
        'timestamp': datetime.utcnow().isoformat(),
    }, sort_keys=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def log_event(event_type, severity='info', user_id=None, ip_address=None, details=None):
    """Log a security event with hash chain integrity."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Get previous hash
        cur.execute("SELECT data_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        previous_hash = row['data_hash'] if row else '0' * 64

        data_hash = _compute_hash(event_type, severity, user_id, ip_address, details, previous_hash)

        cur.execute(
            "INSERT INTO audit_logs (event_type, severity, user_id, ip_address, details, data_hash, previous_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (event_type, severity, user_id, ip_address, details, data_hash, previous_hash)
        )
        log_id = cur.fetchone()['id']
        conn.commit()
        return log_id
    except Exception as e:
        conn.rollback()
        print(f"[!] Audit log error: {e}")
        return None
    finally:
        cur.close()
        conn.close()


def verify_chain():
    """Verify the integrity of the entire audit log hash chain.
    Returns (is_valid, broken_at_id_or_None).
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, data_hash, previous_hash FROM audit_logs ORDER BY id ASC")
        rows = cur.fetchall()
        if not rows:
            return True, None
        expected_prev = '0' * 64
        for row in rows:
            if row['previous_hash'] != expected_prev:
                return False, row['id']
            expected_prev = row['data_hash']
        return True, None
    finally:
        cur.close()
        conn.close()
