"""
Auth Routes — register, login (JWT), OTP verification, logout.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from datetime import datetime
import bcrypt

from models import get_connection
from utils.risk_scorer import calculate_risk_score, get_risk_action
from utils.email_service import generate_otp, send_otp, store_otp
from utils.audit_logger import log_event
from ml.anomaly_detector import predict_anomaly

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'username, email, and password are required'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_connection()
    cur = conn.cursor()
    try:
        # Check existing
        cur.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
        if cur.fetchone():
            return jsonify({'error': 'Email or username already taken'}), 409

        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (username, email, password_hash)
        )
        user_id = cur.fetchone()['id']
        conn.commit()

        log_event('user_registered', 'info', user_id, request.remote_addr,
                  f'User {username} registered')

        return jsonify({'message': 'Registration successful', 'user_id': user_id}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    device_fingerprint = data.get('device_fingerprint', 'unknown')
    ip_address = request.remote_addr

    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Log failed attempt
            cur.execute(
                "INSERT INTO login_attempts (email, ip_address, device_fingerprint, success, attempted_at) "
                "VALUES (%s, %s, %s, FALSE, %s)",
                (email, ip_address, device_fingerprint, datetime.utcnow())
            )
            conn.commit()
            log_event('login_failed', 'warning', None, ip_address, f'Failed login for {email}')
            return jsonify({'error': 'Invalid email or password'}), 401

        # Run anomaly detection
        now = datetime.utcnow()
        # Count recent failures
        cur.execute(
            "SELECT COUNT(*) as cnt FROM login_attempts WHERE email=%s AND success=FALSE "
            "AND attempted_at > NOW() - INTERVAL '10 minutes'",
            (email,)
        )
        recent_fails = cur.fetchone()['cnt']

        is_anomaly, anomaly_score = predict_anomaly(
            hour_of_day=now.hour,
            day_of_week=now.weekday(),
            failed_attempts=min(recent_fails, 10),
            ip_novelty=0.8 if device_fingerprint == 'unknown' else 0.1,
            device_novelty=0.5 if device_fingerprint == 'unknown' else 0.1,
        )

        # Calculate risk score
        risk_score, risk_breakdown = calculate_risk_score(
            user['id'], ip_address, device_fingerprint
        )
        risk_action = get_risk_action(risk_score)

        # Log the attempt
        cur.execute(
            "INSERT INTO login_attempts (user_id, email, ip_address, device_fingerprint, success, "
            "risk_score, anomaly_score, attempted_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (user['id'], email, ip_address, device_fingerprint,
             risk_action == 'allow', risk_score, anomaly_score, now)
        )
        conn.commit()

        # Handle based on risk
        if risk_action == 'blocked':
            # Create alert
            alert_message = f'Login blocked for {email} — risk score {risk_score}'
            cur.execute(
                "INSERT INTO security_alerts (alert_type, severity, message, source_ip, user_id) "
                "VALUES ('high_risk_login', 'critical', %s, %s, %s) RETURNING id, created_at",
                (alert_message, ip_address, user['id'])
            )
            alert_record = cur.fetchone()
            conn.commit()
            
            # Emit Real-Time WebSocket alert to connected dashboards
            from extensions import socketio
            alert_data = {
                'id': alert_record['id'],
                'alert_type': 'high_risk_login',
                'severity': 'critical',
                'message': alert_message,
                'source_ip': ip_address,
                'user_id': user['id'],
                'created_at': alert_record['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            }
            socketio.emit('new_alert', alert_data, namespace='/alerts')

            log_event('login_blocked', 'critical', user['id'], ip_address,
                      f'Risk score {risk_score}')
            return jsonify({
                'error': 'Login blocked due to high risk',
                'risk_score': risk_score,
                'action': 'blocked'
            }), 403

        # Allow — issue full token
        access_token = create_access_token(
            identity=str(user['id']),
            additional_claims={'role': user['role'], 'username': user['username']}
        )

        # Update last login
        cur.execute("UPDATE users SET last_login_ip=%s, last_login_at=%s WHERE id=%s",
                    (ip_address, now, user['id']))
        conn.commit()

        log_event('login_success', 'info', user['id'], ip_address, f'Successful login, risk {risk_score}')

        return jsonify({
            'message': 'Login successful',
            'action': 'allow',
            'token': access_token,
            'risk_score': risk_score,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
            }
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@auth_bp.route('/verify-otp', methods=['POST'])
@jwt_required()
def verify_otp_route():
    claims = get_jwt()
    if not claims.get('otp_pending'):
        return jsonify({'error': 'OTP not required for this session'}), 400

    data = request.get_json()
    otp_code = data.get('otp_code', '')
    user_id = int(get_jwt_identity())

    if verify_otp(user_id, otp_code):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, email, role FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Issue full access token
        access_token = create_access_token(
            identity=str(user_id),
            additional_claims={'role': user['role'], 'username': user['username']}
        )
        log_event('otp_verified', 'info', user_id, request.remote_addr, 'OTP verified successfully')
        return jsonify({
            'message': 'OTP verified',
            'token': access_token,
            'user': {'id': user_id, 'username': user['username'], 'email': user['email'], 'role': user['role']}
        }), 200
    else:
        log_event('otp_failed', 'warning', user_id, request.remote_addr, 'Invalid OTP code')
        return jsonify({'error': 'Invalid or expired OTP code'}), 401


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    from app import jwt_blocklist
    jti = get_jwt()['jti']
    jwt_blocklist.add(jti)
    user_id = int(get_jwt_identity())
    log_event('logout', 'info', user_id, request.remote_addr, 'User logged out')
    return jsonify({'message': 'Logged out successfully'}), 200


