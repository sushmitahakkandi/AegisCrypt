import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # PostgreSQL
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '5432')
    DB_NAME = os.getenv('DB_NAME', 'aegiscrypt')
    DB_USER = os.getenv('DB_USER', 'postgres')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'postgres')
    DATABASE_URL = os.getenv(
        'DATABASE_URL',
        f'host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD}'
    )
    
    # JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)
    JWT_BLOCKLIST_ENABLED = True
    
    # SMTP (optional — falls back to console logging)
    SMTP_SERVER = os.getenv('SMTP_SERVER', '')
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USER = os.getenv('SMTP_USER', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
    SMTP_FROM = os.getenv('SMTP_FROM', 'aegiscrypt@example.com')
    
    # File uploads
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'md', 'json', 'xml', 'log', 'rtf'}
    ALLOWED_MIMETYPES = {'text/plain', 'text/csv', 'text/markdown', 'application/json', 'application/csv', 'application/xml', 'text/xml', 'application/vnd.ms-excel', 'application/rtf'}
    
    # AbuseIPDB (optional)
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
