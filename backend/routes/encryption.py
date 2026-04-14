"""
Encryption Routes — encrypt, decrypt, benchmark.
Strictly accepts .txt and .csv files or plain text only.
"""

import mimetypes
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import get_connection
from utils.encryption_engine import (
    aes_encrypt, aes_decrypt,
    rsa_encrypt, rsa_decrypt,
    xor_caesar_encrypt, xor_caesar_decrypt,
    encrypt_csv_cells, decrypt_csv_cells,
    sha256_hash, calculate_accuracy, benchmark_algorithms,
)
from utils.audit_logger import log_event

encryption_bp = Blueprint('encryption', __name__, url_prefix='/api/encryption')

ALLOWED_MIMETYPES = {
    'text/plain', 'text/csv', 'text/markdown', 'application/json', 
    'application/csv', 'text/comma-separated-values', 'application/xml', 
    'text/xml', 'application/vnd.ms-excel', 'application/rtf'
}
ALLOWED_EXTENSIONS = {'txt', 'csv', 'md', 'json', 'xml', 'log', 'rtf'}


def _validate_file(file):
    """Validate uploaded file is a text-based file."""
    if not file or not file.filename:
        return None, 'No file provided'
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return None, f'Only text files are allowed (got .{ext})'
    mime = mimetypes.guess_type(file.filename)[0] or ''
    if mime and mime not in ALLOWED_MIMETYPES:
        return None, f'Invalid MIME type: {mime}'
    content = file.read().decode('utf-8', errors='replace')
    return content, None


@encryption_bp.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt():
    user_id = int(get_jwt_identity())
    algorithm = request.form.get('algorithm', 'aes').lower()

    if algorithm not in ('aes', 'rsa', 'xor'):
        return jsonify({'error': 'Algorithm must be aes, rsa, or xor'}), 400

    # Get input: either text or file
    text = request.form.get('text', '')
    file = request.files.get('file')
    input_type = 'text'

    if file:
        content, err = _validate_file(file)
        if err:
            return jsonify({'error': err}), 400
        text = content
        input_type = 'file'

    if not text:
        return jsonify({'error': 'No input provided. Send text or upload a valid text file'}), 400

    is_csv = input_type == 'file' and file.filename.endswith('.csv')
    input_hash = sha256_hash(text)

    try:
        if is_csv:
            encrypted, keys, accuracy = encrypt_csv_cells(text, algorithm)
            output_hash = sha256_hash(encrypted)
            result = {
                'encrypted': encrypted,
                'keys': keys,
                'algorithm': algorithm,
                'input_type': 'csv',
                'accuracy': accuracy,
                'input_hash': input_hash,
                'output_hash': output_hash,
                'original_preview': text[:500],
            }
        else:
            if algorithm == 'aes':
                ct, key_b64, iv_b64 = aes_encrypt(text)
                keys = {'key': key_b64, 'iv': iv_b64}
            elif algorithm == 'rsa':
                ct, priv_b64, pub_b64 = rsa_encrypt(text)
                keys = {'private_key': priv_b64, 'public_key': pub_b64}
            elif algorithm == 'xor':
                ct, xor_key = xor_caesar_encrypt(text)
                keys = {'key': xor_key}

            output_hash = sha256_hash(ct)
            result = {
                'encrypted': ct,
                'keys': keys,
                'algorithm': algorithm,
                'input_type': 'text',
                'accuracy': 100.0,
                'input_hash': input_hash,
                'output_hash': output_hash,
                'original_preview': text[:500],
            }

        # Store session
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO encryption_sessions (user_id, algorithm, operation, input_type, "
            "input_size, output_size, accuracy, input_hash, output_hash) "
            "VALUES (%s, %s, 'encrypt', %s, %s, %s, %s, %s, %s)",
            (user_id, algorithm, input_type, len(text), len(result['encrypted']),
             result['accuracy'], input_hash, output_hash)
        )
        conn.commit()
        cur.close()
        conn.close()

        log_event('encryption', 'info', user_id, request.remote_addr,
                  f'{algorithm} encryption on {input_type}')

        return jsonify(result), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@encryption_bp.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    algorithm = data.get('algorithm', 'aes').lower()
    encrypted = data.get('encrypted', '')
    keys = data.get('keys', {})
    input_type = data.get('input_type', 'text')

    if not encrypted:
        return jsonify({'error': 'No encrypted content provided'}), 400

    try:
        if input_type == 'csv':
            decrypted, accuracy = decrypt_csv_cells(encrypted, algorithm, keys)
        else:
            if algorithm == 'aes':
                decrypted = aes_decrypt(encrypted, keys.get('key', ''), keys.get('iv', ''))
            elif algorithm == 'rsa':
                decrypted = rsa_decrypt(encrypted, keys.get('private_key', ''))
            elif algorithm == 'xor':
                decrypted = xor_caesar_decrypt(encrypted, keys.get('key', 0))
            else:
                return jsonify({'error': 'Unknown algorithm'}), 400
            accuracy = 100.0

        output_hash = sha256_hash(decrypted)

        # Store session
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO encryption_sessions (user_id, algorithm, operation, input_type, "
            "input_size, output_size, accuracy, output_hash) "
            "VALUES (%s, %s, 'decrypt', %s, %s, %s, %s, %s)",
            (user_id, algorithm, input_type, len(encrypted), len(decrypted), accuracy, output_hash)
        )
        conn.commit()
        cur.close()
        conn.close()

        log_event('decryption', 'info', user_id, request.remote_addr,
                  f'{algorithm} decryption on {input_type}')

        return jsonify({
            'decrypted': decrypted,
            'algorithm': algorithm,
            'accuracy': accuracy,
            'output_hash': output_hash,
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@encryption_bp.route('/benchmark', methods=['POST'])
@jwt_required()
def run_benchmark():
    user_id = int(get_jwt_identity())
    file = request.files.get('file')

    if not file:
        return jsonify({'error': 'CSV file required'}), 400

    content, err = _validate_file(file)
    if err:
        return jsonify({'error': err}), 400

    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Only .csv files allowed for benchmarking'}), 400

    try:
        results = benchmark_algorithms(content)

        # Store results
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO benchmark_results (user_id, filename, file_size, "
            "aes_encrypt_time, aes_decrypt_time, aes_accuracy, aes_output_size, "
            "rsa_encrypt_time, rsa_decrypt_time, rsa_accuracy, rsa_output_size, "
            "xor_encrypt_time, xor_decrypt_time, xor_accuracy, xor_output_size) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                user_id, file.filename, len(content.encode('utf-8')),
                results['AES-256']['encrypt_time'], results['AES-256']['decrypt_time'],
                results['AES-256']['accuracy'], results['AES-256']['encrypted_size'],
                results['RSA-2048']['encrypt_time'], results['RSA-2048']['decrypt_time'],
                results['RSA-2048']['accuracy'], results['RSA-2048']['encrypted_size'],
                results['XOR+Caesar']['encrypt_time'], results['XOR+Caesar']['decrypt_time'],
                results['XOR+Caesar']['accuracy'], results['XOR+Caesar']['encrypted_size'],
            )
        )
        conn.commit()
        cur.close()
        conn.close()

        log_event('benchmark', 'info', user_id, request.remote_addr,
                  f'Benchmark on {file.filename}')

        return jsonify({'results': results, 'filename': file.filename}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
