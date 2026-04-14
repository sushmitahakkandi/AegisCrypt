import os
import csv
import io
import time
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# --------------- AES-256-CBC ---------------

def aes_generate_key():
    """Generate a random 256-bit AES key and 128-bit IV."""
    key = os.urandom(32)
    iv = os.urandom(16)
    return key, iv


def aes_encrypt(plaintext, key=None, iv=None):
    """Encrypt plaintext string with AES-256-CBC. Returns (ciphertext_b64, key_b64, iv_b64)."""
    if key is None or iv is None:
        key, iv = aes_generate_key()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return (
        base64.b64encode(ct).decode('utf-8'),
        base64.b64encode(key).decode('utf-8'),
        base64.b64encode(iv).decode('utf-8'),
    )


def aes_decrypt(ciphertext_b64, key_b64, iv_b64):
    """Decrypt AES-256-CBC ciphertext. Returns plaintext string."""
    ct = base64.b64decode(ciphertext_b64)
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode('utf-8')


# --------------- RSA-2048 ---------------

def rsa_generate_keys():
    """Generate RSA-2048 key pair. Returns (private_pem_b64, public_pem_b64)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(priv_pem).decode(), base64.b64encode(pub_pem).decode()


def _rsa_load_public(pub_pem_b64):
    return serialization.load_pem_public_key(base64.b64decode(pub_pem_b64), backend=default_backend())


def _rsa_load_private(priv_pem_b64):
    return serialization.load_pem_private_key(base64.b64decode(priv_pem_b64), password=None, backend=default_backend())


def rsa_encrypt(plaintext, pub_pem_b64=None, priv_pem_b64=None):
    """RSA-2048 encrypt. For text longer than ~190 bytes, chunks it. Returns (ciphertext_b64, priv_key_b64, pub_key_b64)."""
    if pub_pem_b64 is None:
        priv_pem_b64, pub_pem_b64 = rsa_generate_keys()
    pub_key = _rsa_load_public(pub_pem_b64)
    data = plaintext.encode('utf-8')
    chunk_size = 190  # safe for RSA-2048
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    encrypted_chunks = []
    for chunk in chunks:
        ct = pub_key.encrypt(chunk, asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ))
        encrypted_chunks.append(base64.b64encode(ct).decode())
    ciphertext = '|'.join(encrypted_chunks)
    return ciphertext, priv_pem_b64, pub_pem_b64


def rsa_decrypt(ciphertext, priv_pem_b64):
    """RSA-2048 decrypt chunked ciphertext."""
    priv_key = _rsa_load_private(priv_pem_b64)
    chunks = ciphertext.split('|')
    decrypted = b''
    for chunk in chunks:
        ct = base64.b64decode(chunk)
        pt = priv_key.decrypt(ct, asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ))
        decrypted += pt
    return decrypted.decode('utf-8')


# --------------- XOR + Caesar Hybrid ---------------

def xor_caesar_encrypt(plaintext, key=None):
    """XOR with a random key byte then Caesar shift by key value. Returns (ciphertext_b64, key_int)."""
    if key is None:
        key = int.from_bytes(os.urandom(1), 'big') or 42
    result = []
    for ch in plaintext.encode('utf-8'):
        xored = ch ^ key
        shifted = (xored + key) % 256
        result.append(shifted)
    return base64.b64encode(bytes(result)).decode('utf-8'), key


def xor_caesar_decrypt(ciphertext_b64, key):
    """Reverse XOR+Caesar."""
    data = base64.b64decode(ciphertext_b64)
    result = []
    for byte in data:
        unshifted = (byte - key) % 256
        unxored = unshifted ^ key
        result.append(unxored)
    return bytes(result).decode('utf-8')


# --------------- CSV Cell-Level Encryption ---------------

def encrypt_csv_cells(csv_text, algorithm='aes'):
    """Encrypt each data cell in a CSV while keeping headers readable.
    Returns (encrypted_csv_text, keys_dict, accuracy).
    """
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    if not rows:
        return csv_text, {}, 100.0

    headers = rows[0]
    encrypted_rows = [headers]
    keys = {}

    if algorithm == 'aes':
        key, iv = aes_generate_key()
        keys = {'key': base64.b64encode(key).decode(), 'iv': base64.b64encode(iv).decode()}
        for row in rows[1:]:
            enc_row = []
            for cell in row:
                if cell.strip():
                    ct, _, _ = aes_encrypt(cell, key, iv)
                    enc_row.append(ct)
                else:
                    enc_row.append('')
            encrypted_rows.append(enc_row)

    elif algorithm == 'rsa':
        priv_b64, pub_b64 = rsa_generate_keys()
        keys = {'private_key': priv_b64, 'public_key': pub_b64}
        for row in rows[1:]:
            enc_row = []
            for cell in row:
                if cell.strip():
                    ct, _, _ = rsa_encrypt(cell, pub_b64, priv_b64)
                    enc_row.append(ct)
                else:
                    enc_row.append('')
            encrypted_rows.append(enc_row)

    elif algorithm == 'xor':
        xor_key = int.from_bytes(os.urandom(1), 'big') or 42
        keys = {'key': xor_key}
        for row in rows[1:]:
            enc_row = []
            for cell in row:
                if cell.strip():
                    ct, _ = xor_caesar_encrypt(cell, xor_key)
                    enc_row.append(ct)
                else:
                    enc_row.append('')
            encrypted_rows.append(enc_row)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerows(encrypted_rows)
    return output.getvalue(), keys, 100.0


def decrypt_csv_cells(encrypted_csv_text, algorithm, keys):
    """Decrypt each data cell in a CSV. Returns (decrypted_csv_text, accuracy)."""
    reader = csv.reader(io.StringIO(encrypted_csv_text))
    rows = list(reader)
    if not rows:
        return encrypted_csv_text, 100.0

    headers = rows[0]
    decrypted_rows = [headers]
    total_cells = 0
    correct_cells = 0

    for row in rows[1:]:
        dec_row = []
        for cell in row:
            if cell.strip():
                total_cells += 1
                try:
                    if algorithm == 'aes':
                        pt = aes_decrypt(cell, keys['key'], keys['iv'])
                    elif algorithm == 'rsa':
                        pt = rsa_decrypt(cell, keys['private_key'])
                    elif algorithm == 'xor':
                        pt = xor_caesar_decrypt(cell, keys['key'])
                    else:
                        pt = cell
                    dec_row.append(pt)
                    correct_cells += 1
                except Exception:
                    dec_row.append('[DECRYPTION_ERROR]')
            else:
                dec_row.append('')
        decrypted_rows.append(dec_row)

    accuracy = (correct_cells / total_cells * 100) if total_cells > 0 else 100.0
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerows(decrypted_rows)
    return output.getvalue(), accuracy


# --------------- Helpers ---------------

def sha256_hash(text):
    """SHA-256 hash of a string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def calculate_accuracy(original, recovered):
    """Character-level accuracy between original and recovered text."""
    if not original:
        return 100.0
    matches = sum(1 for a, b in zip(original, recovered) if a == b)
    return round(matches / max(len(original), len(recovered)) * 100, 2)


def benchmark_algorithms(csv_text):
    """Run all 3 algorithms on the same CSV and measure performance."""
    results = {}
    file_size = len(csv_text.encode('utf-8'))

    for algo_name, enc_fn, dec_fn_info in [
        ('AES-256', 'aes', None),
        ('RSA-2048', 'rsa', None),
        ('XOR+Caesar', 'xor', None),
    ]:
        start = time.time()
        encrypted_csv, keys, _ = encrypt_csv_cells(csv_text, algo_name.split('-')[0].split('+')[0].lower()
            if algo_name != 'XOR+Caesar' else 'xor')
        encrypt_time = time.time() - start

        enc_size = len(encrypted_csv.encode('utf-8'))

        start = time.time()
        algo_key = algo_name.split('-')[0].split('+')[0].lower() if algo_name != 'XOR+Caesar' else 'xor'
        decrypted_csv, accuracy = decrypt_csv_cells(encrypted_csv, algo_key, keys)
        decrypt_time = time.time() - start

        results[algo_name] = {
            'encrypt_time': round(encrypt_time, 4),
            'decrypt_time': round(decrypt_time, 4),
            'original_size': file_size,
            'encrypted_size': enc_size,
            'accuracy': accuracy,
        }

    return results
