"""
Dashboard Routes — stats and recent events.
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from datetime import datetime, timedelta
from models import get_connection

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')


@dashboard_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    conn = get_connection()
    cur = conn.cursor()
    try:
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

        # Total login attempts today
        cur.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE attempted_at >= %s", (today_start,))
        login_attempts_today = cur.fetchone()['cnt']

        # Failed login attempts today
        cur.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE attempted_at >= %s AND success=FALSE",
                    (today_start,))
        failed_today = cur.fetchone()['cnt']

        # Blocked IPs count
        cur.execute("SELECT COUNT(*) as cnt FROM blocked_ips")
        blocked_ips = cur.fetchone()['cnt']

        # Encryption sessions today
        cur.execute("SELECT COUNT(*) as cnt FROM encryption_sessions WHERE created_at >= %s", (today_start,))
        encryption_sessions = cur.fetchone()['cnt']

        # Unresolved alerts
        cur.execute("SELECT COUNT(*) as cnt FROM security_alerts WHERE resolved=FALSE")
        unresolved_alerts = cur.fetchone()['cnt']

        # Critical alerts today
        cur.execute(
            "SELECT COUNT(*) as cnt FROM security_alerts WHERE severity='critical' AND created_at >= %s",
            (today_start,)
        )
        critical_today = cur.fetchone()['cnt']

        # Threat level calculation
        if critical_today > 5 or blocked_ips > 20:
            threat_level = 'critical'
        elif critical_today > 2 or failed_today > 20:
            threat_level = 'high'
        elif failed_today > 10 or unresolved_alerts > 5:
            threat_level = 'medium'
        else:
            threat_level = 'low'

        # Total users
        cur.execute("SELECT COUNT(*) as cnt FROM users")
        total_users = cur.fetchone()['cnt']

        # Login attempts per hour (last 24h)
        cur.execute("""
            SELECT EXTRACT(HOUR FROM attempted_at)::int as hour, COUNT(*) as cnt
            FROM login_attempts
            WHERE attempted_at >= %s
            GROUP BY hour ORDER BY hour
        """, (datetime.utcnow() - timedelta(hours=24),))
        hourly = {str(r['hour']): r['cnt'] for r in cur.fetchall()}

        return jsonify({
            'login_attempts_today': login_attempts_today,
            'failed_attempts_today': failed_today,
            'blocked_ips': blocked_ips,
            'encryption_sessions_today': encryption_sessions,
            'unresolved_alerts': unresolved_alerts,
            'critical_alerts_today': critical_today,
            'threat_level': threat_level,
            'total_users': total_users,
            'hourly_attempts': hourly,
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@dashboard_bp.route('/events', methods=['GET'])
@jwt_required()
def get_events():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, event_type, severity, ip_address, details,
                   TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at
            FROM audit_logs
            ORDER BY id DESC LIMIT 20
        """)
        events = cur.fetchall()
        return jsonify({'events': events}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()
