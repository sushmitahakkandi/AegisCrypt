from flask_socketio import SocketIO

# Initialize socketio without app
socketio = SocketIO(cors_allowed_origins="*")
