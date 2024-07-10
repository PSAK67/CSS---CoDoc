from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
from core.config import Config
from core.database import db

# Initialize SocketIO and CORS extensions
socket = SocketIO()
cors = CORS()

def create_app():
    """
    Create and configure the Flask application.

    This function sets up the Flask app, initializes extensions,
    creates database tables, and registers blueprints.

    :return: A tuple containing the configured Flask app and SocketIO instance
    """

    app = Flask(__name__)

    app.config.from_object(Config)

    db.init_app(app)

    socket.init_app(app, cors_allowed_origins="*")

    cors.init_app(app)

    with app.app_context():
        db.create_all()

        # Import and register blueprints
        from .views import views
        app.register_blueprint(views)

    return app, socket