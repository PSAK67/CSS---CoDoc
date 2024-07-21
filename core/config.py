import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL') or 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get(
        'MAIL_USERNAME') or "hamzatera007@gmail.com"  # Your Gmail address
    MAIL_PASSWORD = os.environ.get(
        'MAIL_PASSWORD') or "hcfp qdiz tymv amne"  # Your Gmail app password
    MAIL_DEFAULT_SENDER = os.environ.get(
        'MAIL_DEFAULT_SENDER') or "hamzatera007@gmail.com"  # Your default sender address
    SECURITY_PASSWORD_SALT = os.environ.get(
        'SECURITY_PASSWORD_SALT') or "your_password_salt"
