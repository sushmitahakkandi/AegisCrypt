"""
Audit Log Routes — paginated logs, CSV export, integrity verification.
"""

import csv
import io
from flask import Blueprint, jsonify, request, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import get_connection
from utils.audit_logger import verify_chain

audit_bp = Blueprint('audit', __name__, url_prefix='/api/audit-logs')


@audit_bp.route('', methods=['GET'])
@jwt_required()
def get_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    severity = request.args.get('severity', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    per_page = min(per_page, 100)
    offset = (page - 1) * per_page

    conn = get_connection()
    cur = conn.cursor()
    try:
        query = "SELECT id, event_type, severity, user_id, ip_address, details, data_hash, " \
                "TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at FROM audit_logs WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = %s"
            params.append(severity)
        if date_from:
            query += " AND created_at >= %s"
            params.append(date_from)
        if date_to:
            query += " AND created_at <= %s"
            params.append(date_to + ' 23:59:59')

        # Count total
        count_query = query.replace(
            "SELECT id, event_type, severity, user_id, ip_address, details, data_hash, "
            "TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at",
            "SELECT COUNT(*) as cnt"
        )
        cur.execute(count_query, params)
        total = cur.fetchone()['cnt']

        query += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params.extend([per_page, offset])

        cur.execute(query, params)
        logs = cur.fetchall()

        return jsonify({
            'logs': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page if per_page else 1,
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@audit_bp.route('/export/csv', methods=['GET'])
@jwt_required()
def export_csv():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, event_type, severity, user_id, ip_address, details, data_hash,
                   TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at
            FROM audit_logs ORDER BY id DESC
        """)
        rows = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Event Type', 'Severity', 'User ID', 'IP Address', 'Details', 'Hash', 'Timestamp'])
        for row in rows:
            writer.writerow([
                row['id'], row['event_type'], row['severity'], row['user_id'],
                row['ip_address'], row['details'], row['data_hash'], row['created_at']
            ])

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=audit_logs.csv'}
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@audit_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_integrity():
    is_valid, broken_at = verify_chain()
    return jsonify({
        'integrity_valid': is_valid,
        'broken_at_id': broken_at,
        'message': 'Audit log chain is intact' if is_valid else f'Chain broken at log ID {broken_at}'
    }), 200
