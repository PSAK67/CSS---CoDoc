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