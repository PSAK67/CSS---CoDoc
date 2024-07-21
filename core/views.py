from flask import Blueprint, render_template, request, url_for, redirect, session, flash, jsonify
from core.database import *
from core import socket
from core.helper import generate_otp, generate_token, confirm_token
from core.email_helper import send_verification_email, send_forget_email
from core.decorators import login_required

views = Blueprint('views', __name__, static_folder='static',
                  template_folder='templates')



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

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if not existing_user.is_verified:
                # Resend OTP
                otp = generate_otp()
                existing_user.otp = otp
                db.session.commit()
                send_verification_email(email, existing_user.username, otp)
                flash(
                    "User already exists but is not verified. OTP has been resent to your email.")
                return redirect(url_for("views.verify_otp"))
            flash("User already exists with that email.")
            return redirect(url_for("views.login"))

        # Generate OTP and create new user
        otp = generate_otp()
        print("OTP  ----", otp)
        new_user = User(username=username, email=email,
                        password=password, otp=otp, is_verified=False)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        send_verification_email(email, username, otp)
        flash("Registration successful. An OTP has been sent to your email.")
        return redirect(url_for("views.verify_otp"))

    return render_template("authentication.html")


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

    return render_template("authentication.html")


@views.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip()
        user = User.query.filter_by(email=email).first()
        domain = request.host
        if user:
            token = generate_token(user.email)
            link = f"http://{domain}/reset-password/{token}"
            print(link)
            send_forget_email(email, link=link)
            flash("Password reset link has been sent to your email.")
            return redirect(url_for("views.login"))
        else:
            flash("Email not found. Please try again.")
            return redirect(url_for("forgot_password"))

    return render_template("forget_password.html")


@views.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = confirm_token(token)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('views.forgot_password'))

    if request.method == "POST":
        password = request.form["password"].strip()
        confirm_password = request.form["confirm_password"].strip()

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return redirect(url_for('views.set_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash("Your password has been updated!")
            return redirect(url_for("views.login"))
        else:
            flash("User not found. Please try again.")
            return redirect(url_for("views.forgot_password"))

    return render_template("set_password.html", token=token)


@views.route("/new-chat", methods=["POST"])
@login_required
def new_chat():
    """
    Creates a new chat room and adds users to the chat list.

    Returns:
        Response: Flask response object.
    """
    user_id = session["user"]["id"]
    new_chat_email = request.form["email"].strip().lower()

    # If user is trying to add themselves, do nothing
    if new_chat_email == session["user"]["email"]:
        return redirect(url_for("views.chat"))

    # Check if the recipient user exists
    recipient_user = User.query.filter_by(email=new_chat_email).first()
    if not recipient_user:
        return redirect(url_for("views.chat"))

    # Check if the chat already exists
    existing_chat = Chat.query.filter_by(user_id=user_id).first()
    if not existing_chat:
        existing_chat = Chat(user_id=user_id, chat_list=[])
        db.session.add(existing_chat)
        db.session.commit()

    # Check if the new chat is already in the chat list
    if recipient_user.id not in [user_chat["user_id"] for user_chat in existing_chat.chat_list]:
        # Generate a room_id (you may use your logic to generate it)
        room_id = str(int(recipient_user.id) + int(user_id))[-4:]

        # Add the new chat to the chat list of the current user
        updated_chat_list = existing_chat.chat_list + \
            [{"user_id": recipient_user.id, "room_id": room_id}]
        existing_chat.chat_list = updated_chat_list

        # Save the changes to the database
        existing_chat.save_to_db()

        # Create a new chat list for the recipient user if it doesn't exist
        recipient_chat = Chat.query.filter_by(
            user_id=recipient_user.id).first()
        if not recipient_chat:
            recipient_chat = Chat(user_id=recipient_user.id, chat_list=[])
            db.session.add(recipient_chat)
            db.session.commit()

        # Add the new chat to the chat list of the recipient user
        updated_chat_list = recipient_chat.chat_list + \
            [{"user_id": user_id, "room_id": room_id}]
        recipient_chat.chat_list = updated_chat_list
        recipient_chat.save_to_db()

        # Create a new message entry for the chat room
        new_message = Message(room_id=room_id)
        db.session.add(new_message)
        db.session.commit()

    return redirect(url_for("views.chat"))


@views.route("/chat/", methods=["GET", "POST"])
@login_required
def chat():
    """
    Renders the chat interface and displays chat messages.

    Returns:
        Response: Flask response object.
    """
    # Get the room id in the URL or set to None
    room_id = request.args.get("rid", None)

    # Get the chat list for the user
    current_user_id = session["user"]["id"]
    current_user_chats = Chat.query.filter_by(user_id=current_user_id).first()
    chat_list = current_user_chats.chat_list if current_user_chats else []

    # Initialize context that contains information about the chat room
    data = []

    for chat in chat_list:
        # Query the database to get the username of users in a user's chat list
        username = User.query.get(chat["user_id"]).username
        is_active = room_id == chat["room_id"]

        try:
            # Get the Message object for the chat room
            message = Message.query.filter_by(room_id=chat["room_id"]).first()

            # Get the last ChatMessage object in the Message's messages relationship
            last_message = message.messages[-1]

            # Get the message content of the last ChatMessage object
            last_message_content = last_message.content
        except (AttributeError, IndexError):
            # Set variable to this when no messages have been sent to the room
            last_message_content = "This place is empty. No messages ..."

        data.append({
            "username": username,
            "room_id": chat["room_id"],
            "is_active": is_active,
            "last_message": last_message_content,
        })

    # Get all the message history in a certain room
    messages = Message.query.filter_by(
        room_id=room_id).first().messages if room_id else []

    return render_template(
        "chat_template.html",
        user_data=session["user"],
        room_id=room_id,
        data=data,
        messages=messages,
    )


# Custom time filter to be used in the jinja template
@views.app_template_filter("ftime")
def ftime(date):
    dt = datetime.fromtimestamp(int(date))
    time_format = "%I:%M %p"  # Use  %I for 12-hour clock format and %p for AM/PM

    formatted_time = dt.strftime("%d %B")

    formatted_time += "  " + dt.strftime(time_format)
    return formatted_time


@views.route('/visualize')
def visualize():
    """
    TODO: Utilize pandas and matplotlib to analyze the number of users registered to the app.
    Create a chart of the analysis and convert it to base64 encoding for display in the template.

    Returns:
        Response: Flask response object.
    """
    pass


@views.route('/get_name')
def get_name():
    """
    :return: json object with username
    """
    data = {'name': ''}
    if 'username' in session:
        data = {'name': session['username']}

    return jsonify(data)


@views.route('/get_messages')
def get_messages():
    """
    query the database for messages o in a particular room id
    :return: all messages
    """
    pass


@views.route('/leave')
def leave():
    """
    Emits a 'disconnect' event and redirects to the home page.

    Returns:
        Response: Flask response object.
    """
    socket.emit('disconnect')
    return redirect(url_for('views.home'))
