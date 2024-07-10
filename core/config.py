import os

class Config:
    """
    Configuration settings for the Flask application.

    This class defines configuration variables used throughout the application.
    It uses environment variables when available, falling back to default values
    if not set.
    """

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key_here'

    # Database URI for SQLAlchemy
    # Use environment variable if set, otherwise use a local SQLite database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False