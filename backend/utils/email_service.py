"""
Email Service — OTP and alert email sender via smtplib.
Falls back to console logging if SMTP is not configured.
"""

import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from config import Config
from models import get_connection


def generate_otp():
    """Generate a 6-digit OTP code."""
    return ''.join(random.choices(string.digits, k=6))


def send_otp(email, otp_code):
    """Send OTP via email or log to console."""
    subject = "AegisCrypt — Your Verification Code"
    body = f"Your OTP verification code is: {otp_code}\n\nThis code expires in 5 minutes."

    if Config.SMTP_SERVER and Config.SMTP_USER:
        try:
            msg = MIMEMultipart()
            msg['From'] = Config.SMTP_FROM
            msg['To'] = email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
                server.starttls()
                server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
                server.send_message(msg)
            print(f"[+] OTP sent to {email}")
            return True
        except Exception as e:
            print(f"[!] SMTP error: {e}")

    # Fallback: console
    print(f"\n{'='*40}")
    print(f"  OTP for {email}: {otp_code}")
    print(f"{'='*40}\n")
    return True


def store_otp(user_id, otp_code):
    """Store OTP in the database with 5-minute expiry."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        expires = datetime.utcnow() + timedelta(minutes=5)
        cur.execute(
            "UPDATE users SET otp_code=%s, otp_expires_at=%s WHERE id=%s",
            (otp_code, expires, user_id)
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def verify_otp(user_id, otp_code):
    """Verify OTP code for a user. Returns True if valid."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT otp_code, otp_expires_at FROM users WHERE id=%s",
            (user_id,)
        )
        row = cur.fetchone()
        if not row or not row['otp_code']:
            return False
        if row['otp_code'] != otp_code:
            return False
        if row['otp_expires_at'] and row['otp_expires_at'] < datetime.utcnow():
            return False
        # Clear OTP after successful verification
        cur.execute("UPDATE users SET otp_code=NULL, otp_expires_at=NULL WHERE id=%s", (user_id,))
        conn.commit()
        return True
    finally:
        cur.close()
        conn.close()
