from flask import render_template
from flask_mail import Message
from core import mail  # Ensure mail is initialized in your __init__.py


def send_verification_email(email, username, otp):
    SUBJECT = "Your OTP Code"

    # Render the HTML template with the provided context
    html_content = render_template('signup.html', first_name=username, otp=otp)

    # Create a simple text version (you might want to create a separate text template if needed)
    text_content = f"Hello {username},\n\nYour OTP code is {otp}."

    msg = Message(
        subject=SUBJECT,
        recipients=[email],
        html=html_content,
        body=text_content
    )

    try:
        mail.send(msg)
        print("Email sent!")
    except Exception as e:
        print(f"Failed to send email: {e}")


def send_forget_email(email, link):
    SUBJECT = "Reset Your Password"

    html_content = render_template(
        'reset_password.html', link=link)

    msg = Message(
        subject=SUBJECT,
        recipients=[email],
        html=html_content
    )

    try:
        mail.send(msg)
        print("Email sent!")
    except Exception as e:
        print(f"Failed to send email: {e}")
