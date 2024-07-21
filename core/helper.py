import random
from itsdangerous import URLSafeTimedSerializer
from flask import current_app


def generate_otp():
    return str(random.randint(000000, 999999))


def generate_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=9600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except Exception as e:
        return False
    return email
