import psycopg2
from psycopg2.extras import RealDictCursor
from config import Config


def get_connection():
    """Get a new database connection."""
    return psycopg2.connect(Config.DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    """Create all database tables."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(80) UNIQUE NOT NULL,
        email VARCHAR(120) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        security_question VARCHAR(255),
        security_answer_hash VARCHAR(255),
        otp_code VARCHAR(6),
        otp_expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login_ip VARCHAR(45),
        last_login_at TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        email VARCHAR(120),
        ip_address VARCHAR(45),
        device_fingerprint VARCHAR(255),
        success BOOLEAN DEFAULT FALSE,
        risk_score INTEGER DEFAULT 0,
        anomaly_score FLOAT DEFAULT 0,
        country VARCHAR(80),
        city VARCHAR(80),
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id SERIAL PRIMARY KEY,
        ip_address VARCHAR(45) UNIQUE NOT NULL,
        reason VARCHAR(255),
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS encryption_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        algorithm VARCHAR(30) NOT NULL,
        operation VARCHAR(10) NOT NULL,
        input_type VARCHAR(10) NOT NULL,
        input_size INTEGER,
        output_size INTEGER,
        accuracy FLOAT DEFAULT 100.0,
        input_hash VARCHAR(64),
        output_hash VARCHAR(64),
        encryption_time FLOAT,
        decryption_time FLOAT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS benchmark_results (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        filename VARCHAR(255),
        file_size INTEGER,
        aes_encrypt_time FLOAT,
        aes_decrypt_time FLOAT,
        aes_accuracy FLOAT,
        aes_output_size INTEGER,
        rsa_encrypt_time FLOAT,
        rsa_decrypt_time FLOAT,
        rsa_accuracy FLOAT,
        rsa_output_size INTEGER,
        xor_encrypt_time FLOAT,
        xor_decrypt_time FLOAT,
        xor_accuracy FLOAT,
        xor_output_size INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id SERIAL PRIMARY KEY,
        alert_type VARCHAR(50) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        source_ip VARCHAR(45),
        user_id INTEGER,
        resolved BOOLEAN DEFAULT FALSE,
        resolved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        severity VARCHAR(20) DEFAULT 'info',
        user_id INTEGER,
        ip_address VARCHAR(45),
        details TEXT,
        data_hash VARCHAR(64) NOT NULL,
        previous_hash VARCHAR(64),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("[+] Database tables initialized successfully.")


if __name__ == '__main__':
    init_db()
