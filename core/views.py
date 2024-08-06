from flask import Blueprint, render_template, request, url_for, redirect, session, flash, jsonify
from core.database import *
from core import socket
from core.helper import generate_otp, generate_token, confirm_token
from core.email_helper import send_verification_email, send_forget_email
from core.decorators import login_required
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

views = Blueprint('views', __name__, static_folder='static', template_folder='templates')

@views.route("/", methods=["GET", "POST"])
def index():
    return redirect(url_for("views.login"))

@views.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if not existing_user.is_verified:
                otp = generate_otp()
                print("OTP", otp)
                existing_user.otp = otp
                db.session.commit()
                send_verification_email(email, existing_user.username, otp)
                flash("User already exists but is not verified. OTP has been resent to your email.")
                return redirect(url_for("views.verify_otp"))
            flash("User already exists with that email.")
            return redirect(url_for("views.login"))

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        otp = generate_otp()
        new_user = User(username=username, email=email,
                        password=password, otp=otp, is_verified=False,
                        public_key=pem_public_key.decode('utf-8'),
                        private_key=pem_private_key.decode('utf-8'))
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        send_verification_email(email, username, otp)
        flash("Registration successful. An OTP has been sent to your email.")
        return redirect(url_for("views.verify_otp"))

    return render_template("authentication.html")

@views.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
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
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["user"] = {"id": user.id, "username": user.username, "email": user.email}
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
    user_id = session["user"]["id"]
    new_chat_email = request.form["email"].strip().lower()

    if new_chat_email == session["user"]["email"]:
        return redirect(url_for("views.chat"))

    recipient_user = User.query.filter_by(email=new_chat_email).first()
    if not recipient_user:
        return redirect(url_for("views.chat"))

    existing_chat = Chat.query.filter_by(user_id=user_id).first()
    if not existing_chat:
        existing_chat = Chat(user_id=user_id, chat_list=[])
        db.session.add(existing_chat)
        db.session.commit()

    if recipient_user.id not in [user_chat["user_id"] for user_chat in existing_chat.chat_list]:
        room_id = str(int(recipient_user.id) + int(user_id))[-4:]

        updated_chat_list = existing_chat.chat_list + [{"user_id": recipient_user.id, "room_id": room_id}]
        existing_chat.chat_list = updated_chat_list
        existing_chat.save_to_db()

        recipient_chat = Chat.query.filter_by(user_id=recipient_user.id).first()
        if not recipient_chat:
            recipient_chat = Chat(user_id=recipient_user.id, chat_list=[])
            db.session.add(recipient_chat)
            db.session.commit()

        updated_chat_list = recipient_chat.chat_list + [{"user_id": user_id, "room_id": room_id}]
        recipient_chat.chat_list = updated_chat_list
        recipient_chat.save_to_db()

        new_message = Message(room_id=room_id)
        db.session.add(new_message)
        db.session.commit()

    return redirect(url_for("views.chat", rid=room_id))

@views.route("/chat/", methods=["GET", "POST"])
@login_required
def chat():
    room_id = request.args.get("rid", None)

    current_user_id = session["user"]["id"]
    current_user_chats = Chat.query.filter_by(user_id=current_user_id).first()
    chat_list = current_user_chats.chat_list if current_user_chats else []

    data = []

    current_user = User.query.get(current_user_id)
    current_user_private_key = serialization.load_pem_private_key(
        current_user.private_key.encode('utf-8'),
        password=None,
    )

    for chat in chat_list:
        username = User.query.get(chat["user_id"]).username
        is_active = room_id == chat["room_id"]

        try:
            message = Message.query.filter_by(room_id=chat["room_id"]).first()
            last_message = message.messages[-1]
            # Determine which user's private key to use for decryption
            if last_message.sender_id == current_user_id:
                recipient_user = User.query.get(chat["user_id"])
                if recipient_user and recipient_user.private_key:
                    recipient_private_key = serialization.load_pem_private_key(
                        recipient_user.private_key.encode('utf-8'),
                        password=None,
                    )
                    last_message_content = decrypt_message(last_message.content, recipient_private_key)
                else:
                    last_message_content = "Decryption failed: Recipient user not found or missing private key."
            else:
                last_message_content = decrypt_message(last_message.content, current_user_private_key)
        except (AttributeError, IndexError):
            last_message_content = "This place is empty. No messages ..."

        data.append({
            "username": username,
            "room_id": chat["room_id"],
            "is_active": is_active,
            "last_message": last_message_content,
            "recipient_id": chat["user_id"] if room_id == chat["room_id"] else None
        })

    # Fetch all messages in the room
    messages = []
    if room_id:
        message_entry = Message.query.filter_by(room_id=room_id).first()
        if message_entry:
            messages = message_entry.messages

    # Debugging output: Check how many messages were fetched
    print(f"Fetched {len(messages)} messages for room ID {room_id}")

    # Identify the recipient (the other user in the chat room)
    recipient_id = None
    for chat in chat_list:
        if chat["room_id"] == room_id:
            recipient_id = chat["user_id"]
            break

    recipient_user = User.query.get(recipient_id)
    if recipient_user and recipient_user.private_key:
        recipient_private_key = serialization.load_pem_private_key(
            recipient_user.private_key.encode('utf-8'),
            password=None,
        )
    else:
        recipient_private_key = None

    decrypted_messages = []
    for msg in messages:
        try:
            if msg.sender_id == current_user_id:
                # Sent message, decrypt using recipient's private key if available
                if recipient_private_key:
                    decrypted_message = recipient_private_key.decrypt(
                        base64.b64decode(msg.content.encode('utf-8')),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    decrypted_messages.append({
                        "sender_username": msg.sender_username,
                        "content": decrypted_message.decode('utf-8'),
                        "timestamp": msg.timestamp,
                        "is_sent": True
                    })
                else:
                    decrypted_messages.append({
                        "sender_username": msg.sender_username,
                        "content": "Decryption failed: Recipient user not found or missing private key.",
                        "timestamp": msg.timestamp,
                        "is_sent": True
                    })
            else:
                # Received message, decrypt using current user's private key
                decrypted_message = current_user_private_key.decrypt(
                    base64.b64decode(msg.content.encode('utf-8')),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_messages.append({
                    "sender_username": msg.sender_username,
                    "content": decrypted_message.decode('utf-8'),
                    "timestamp": msg.timestamp,
                    "is_sent": False
                })
        except ValueError as e:
            print(f"Decryption failed for message ID {msg.id}: {e}")
            continue

    # Debugging output: Check decrypted messages
    for msg in decrypted_messages:
        print(f"Decrypted message from {msg['sender_username']}: {msg['content']} (Sent: {msg['is_sent']})")

    return render_template(
        "chat_template.html",
        user_data=session["user"],
        room_id=room_id,
        data=data,
        messages=decrypted_messages,
    )

def decrypt_message(encrypted_message, private_key):
    try:
        decrypted_message = private_key.decrypt(
            base64.b64decode(encrypted_message.encode('utf-8')),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode('utf-8')
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return "Decryption failed"


@views.app_template_filter("ftime")
def ftime(date):
    try:
        dt = datetime.fromtimestamp(int(date)/1000)  # Divide by 1000 if timestamp is in milliseconds
        return dt.strftime("%d %B %I:%M %p")
    except (ValueError, OSError) as e:
        print(f"Error formatting date: {e}")
        return "Invalid Date"

@views.route('/visualize')
def visualize():
    pass

@views.route('/get_name')
def get_name():
    data = {'name': ''}
    if 'username' in session:
        data = {'name': session['username']}
    return jsonify(data)

@views.route('/get_messages')
def get_messages():
    pass

@views.route('/leave')
def leave():
    socket.emit('disconnect')
    return redirect(url_for('views.home'))
