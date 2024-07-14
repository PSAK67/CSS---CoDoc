from flask import Blueprint, render_template, request, url_for, redirect, session, flash, jsonify
from core.database import *
from functools import wraps
from decorators import login_required
import pandas as pd
import matplotlib.pyplot as plt
from core import socket

views = Blueprint('views', __name__, static_folder='static', template_folder='templates')



# Index route, this route redirects to login/register page
@views.route("/", methods=["GET", "POST"])
def index():
    """
    Redirects to the login/register page.

    Returns:
        Response: Flask response object.
    """
    return redirect(url_for("views.login"))


# Register a new user and hash password
@views.route("/register", methods=["GET", "POST"])
def register():
    """
    Handles user registration and password hashing.

    Returns:
        Response: Flask response object.
    """
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("User already exists with that username.")
            return redirect(url_for("views.login"))

        # Create a new user
        new_user = User(username=username, email=email, password=password)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Create a new chat list for the newly registered user
        new_chat = Chat(user_id=new_user.id, chat_list=[])
        db.session.add(new_chat)
        db.session.commit()

        flash("Registration successful.")
        return redirect(url_for("views.login"))

    return render_template("authentication.html")

@views.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles user login and session creation.

    Returns:
        Response: Flask response object.
    """
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        # Query the database for the inputted email address
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            # Create a new session for the newly logged-in user
            session["user"] = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
            return redirect(url_for("views.chat"))
        else:
            flash("Invalid login credentials. Please try again.")
            return redirect(url_for("views.login"))

    return render_template("auth.html")