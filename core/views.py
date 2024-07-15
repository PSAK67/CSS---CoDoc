from flask import Blueprint, render_template, request, url_for, redirect, session, flash, jsonify
from core.database import *
from functools import wraps
import pandas as pd
import matplotlib.pyplot as plt
from core import socket
from core.helper import generate_otp
from core.email_helper import send_verification_email

views = Blueprint('views', __name__, static_folder='static',
                  template_folder='templates')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("views.login"))
        return f(*args, **kwargs)
    return decorated


@views.route("/", methods=["GET", "POST"])
def index():
    """Redirects to the login/register page."""
    return redirect(url_for("views.login"))


@views.route("/register", methods=["GET", "POST"])
def register():
    """Handles new user registration and OTP email sending."""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("User already exists with that username.")
            return redirect(url_for("views.register"))

        otp = generate_otp()
        new_user = User(username=username, email=email,
                        password=password, otp=otp, is_verified=False)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        send_verification_email(email, username, otp)
        flash("Registration successful. An OTP has been sent to your email.")
        return redirect(url_for("views.verify_otp"))

    return render_template("auth.html")


@views.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    """Verifies the OTP entered by the user."""
    if request.method == "POST":
        otp = request.form["otp"].strip()
        user = User.query.filter_by(otp=otp).first()
        if user:
            user.is_verified = True
            user.otp = None
            db.session.commit()
            flash("OTP verified successfully. You can now log in.")
            return redirect(url_for("views.login"))
        else:
            flash("Invalid OTP. Please try again.")
            return redirect(url_for("views.verify_otp"))

    return render_template("verify_otp.html")


@views.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login and session creation."""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["user"] = {"id": user.id,
                               "username": user.username, "email": user.email}
            return redirect(url_for("views.chat"))
        else:
            flash("Invalid login credentials. Please try again.")
            return redirect(url_for("views.login"))

    return render_template("auth.html")


@views.route("/new-chat", methods=["POST"])
@login_required
def new_chat():
    """Creates a new chat room and adds users to the chat list."""
    user_id = session["user"]["id"]
    new_chat_email = request.form["email"].strip().lower()

    if new_chat_email == session["user"]["email"]:
        return redirect(url_for("views.chat"))

    recipient_user = User.query.filter_by(email=new_chat_email).first()
    if not recipient_user:
        return redirect(url_for("views.chat"))

    existing_chat = Chat.query.filter_by(user_id=user_id).first()

    if recipient_user.id not in [user_chat["user_id"] for user_chat in existing_chat.chat_list]:
        room_id = str(int(recipient_user.id) + int(user_id))[-4:]

        # Update current user's chat list
        updated_chat_list = existing_chat.chat_list + \
            [{"user_id": recipient_user.id, "room_id": room_id}]
        existing_chat.chat_list = updated_chat_list
        existing_chat.save_to_db()

        # Update recipient's chat list
        recipient_chat = Chat.query.filter_by(
            user_id=recipient_user.id).first()
        if not recipient_chat:
            recipient_chat = Chat(user_id=recipient_user.id, chat_list=[])
            db.session.add(recipient_chat)
            db.session.commit()

        updated_chat_list = recipient_chat.chat_list + \
            [{"user_id": user_id, "room_id": room_id}]
        recipient_chat.chat_list = updated_chat_list
        recipient_chat.save_to_db()

        new_message = Message(room_id=room_id)
        db.session.add(new_message)
        db.session.commit()

    return redirect(url_for("views.chat"))


@views.route("/chat/", methods=["GET", "POST"])
@login_required
def chat():
    """Renders the chat interface and displays chat messages."""
    room_id = request.args.get("rid", None)

    current_user_id = session["user"]["id"]
    current_user_chats = Chat.query.filter_by(user_id=current_user_id).first()
    chat_list = current_user_chats.chat_list if current_user_chats else []

    data = []

    for chat in chat_list:
        username = User.query.get(chat["user_id"]).username
        is_active = room_id == chat["room_id"]

        try:
            message = Message.query.filter_by(room_id=chat["room_id"]).first()
            last_message = message.messages[-1]
            last_message_content = last_message.content
        except (AttributeError, IndexError):
            last_message_content = "This place is empty. No messages ..."

        data.append({
            "username": username,
            "room_id": chat["room_id"],
            "is_active": is_active,
            "last_message": last_message_content,
        })

    messages = Message.query.filter_by(
        room_id=room_id).first().messages if room_id else []

    return render_template(
        "chat_template.html",
        user_data=session["user"],
        room_id=room_id,
        data=data,
        messages=messages,
    )
