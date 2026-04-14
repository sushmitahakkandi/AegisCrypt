"""
AegisCrypt — Flask REST API Application Factory
"""

import os
import sys
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from extensions import socketio

# JWT token blocklist (in-memory; use Redis in production)
jwt_blocklist = set()


def create_app():
    app = Flask(
        __name__,
        static_folder=os.path.join(os.path.dirname(__file__), '..', 'web', 'static'),
        template_folder=os.path.join(os.path.dirname(__file__), '..', 'web', 'templates'),
    )
    app.config.from_object(Config)

    # CORS — allow web frontend strictly on localhost
    CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5000", "http://127.0.0.1:5000"]}}, supports_credentials=True)

    # Initialize SocketIO
    socketio.init_app(app)

    # JWT
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_blocklist(jwt_header, jwt_payload):
        return jwt_payload['jti'] in jwt_blocklist

    @jwt.expired_token_loader
    def expired_token(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has expired', 'code': 'token_expired'}), 401

    @jwt.invalid_token_loader
    def invalid_token(error):
        return jsonify({'error': 'Invalid token', 'code': 'invalid_token'}), 401

    @jwt.unauthorized_loader
    def missing_token(error):
        return jsonify({'error': 'Authorization token required', 'code': 'missing_token'}), 401

    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.encryption import encryption_bp
    from routes.alerts import alerts_bp
    from routes.audit import audit_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(encryption_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(audit_bp)

    # Web frontend routes (serve HTML pages)
    from flask import render_template

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register')
    def register_page():
        return render_template('register.html')

    @app.route('/dashboard')
    def dashboard_page():
        return render_template('dashboard.html')

    @app.route('/encryption')
    def encryption_page():
        return render_template('encryption.html')

    @app.route('/alerts')
    def alerts_page():
        return render_template('alerts.html')

    @app.route('/audit')
    def audit_page():
        return render_template('audit.html')

    # Health check
    @app.route('/api/health')
    def health():
        return jsonify({'status': 'ok', 'app': 'AegisCrypt'}), 200

    # Initialize database tables
    try:
        from models import init_db
        with app.app_context():
            init_db()
    except Exception as e:
        print(f"[!] Database initialization warning: {e}")
        print("    Make sure PostgreSQL is running and 'aegiscrypt' database exists.")

    # Train ML model on startup
    try:
        from ml.anomaly_detector import load_model
        load_model()
        print("[+] Anomaly detection model loaded.")
    except Exception as e:
        print(f"[!] ML model warning: {e}")

    return app


if __name__ == '__main__':
    app = create_app()
    print("\n" + "=" * 50)
    print("  AegisCrypt API Server")
    print("  http://localhost:5000")
    print("  API: http://localhost:5000/api/health")
    print("=" * 50 + "\n")
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)
