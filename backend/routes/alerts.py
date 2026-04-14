"""
Alerts Routes — list alerts, mark as resolved.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from models import get_connection
from utils.audit_logger import log_event
from ml.anomaly_detector import retrain_model

alerts_bp = Blueprint('alerts', __name__, url_prefix='/api/alerts')


@alerts_bp.route('', methods=['GET'])
@jwt_required()
def get_alerts():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, alert_type, severity, message, source_ip, user_id, resolved,
                   TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at,
                   TO_CHAR(resolved_at, 'YYYY-MM-DD HH24:MI:SS') as resolved_at
            FROM security_alerts
            ORDER BY created_at DESC
        """)
        alerts = cur.fetchall()
        return jsonify({'alerts': alerts}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@alerts_bp.route('/<int:alert_id>/resolve', methods=['PATCH'])
@jwt_required()
def resolve_alert(alert_id):
    user_id = int(get_jwt_identity())
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE security_alerts SET resolved=TRUE, resolved_at=%s WHERE id=%s RETURNING id",
            (datetime.utcnow(), alert_id)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Alert not found'}), 404
        conn.commit()

        log_event('alert_resolved', 'info', user_id, request.remote_addr,
                  f'Alert {alert_id} resolved')

        return jsonify({'message': 'Alert resolved', 'alert_id': alert_id}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@alerts_bp.route('/retrain', methods=['POST'])
@jwt_required()
def retrain_anomaly_model():
    """Endpoint to trigger anomaly detection model retraining manually."""
    user_id = int(get_jwt_identity())
    # In a real app, you might check if user is admin here
    
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Fetch last 30 days of attempts
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        cur.execute(
            """
            SELECT email, attempted_at, success, device_fingerprint, ip_address
            FROM login_attempts
            WHERE attempted_at > %s
            ORDER BY attempted_at ASC
            """, (thirty_days_ago,)
        )
        attempts = cur.fetchall()
        
        if len(attempts) < 10:
            return jsonify({'message': 'Not enough data to retrain', 'records': len(attempts)}), 400
            
        # Process raw attempts into features required by retrain_model
        # We need hour_of_day, day_of_week, failed_attempts (recent), ip_novelty, device_novelty
        # To do this correctly in DB is optimal, but here we approximate for simplicity
        
        # We will iterate and build 'real_data' dictionary list
        real_data = []
        for att in attempts:
            hour_of_day = att['attempted_at'].hour
            day_of_week = att['attempted_at'].weekday()
            
            # Simple approximation for historical feature representation
            is_unknown_ip = not bool(att['ip_address'])
            is_unknown_device = att['device_fingerprint'] == 'unknown'
            
            real_data.append({
                'hour_of_day': hour_of_day,
                'day_of_week': day_of_week,
                'failed_attempts': 0 if att['success'] else 1, # Simplified
                'ip_novelty': 0.8 if is_unknown_ip else 0.1,
                'device_novelty': 0.5 if is_unknown_device else 0.1
            })
            
        # Call the retrain function
        selected_model = retrain_model(real_data)
        
        log_event('model_retrained', 'info', user_id, request.remote_addr, 
                 f'Anomaly model retrained on {len(real_data)} records')
                 
        return jsonify({'message': 'Model retrained successfully', 'records_used': len(real_data)}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()
