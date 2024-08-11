from core import create_app
from core.database import db, Message, ChatMessage, User
from flask_socketio import emit, join_room, leave_room
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import base64

app, socket = create_app()

@socket.on("join-chat")
def join_private_chat(data):
    room = data["rid"]
    join_room(room)
    emit("joined-chat", {"msg": f"{room} is now online."}, room=room)

@socket.on("outgoing")
def chatting_event(json, methods=["GET", "POST"]):
    room_id = json["rid"]
    timestamp = json["timestamp"]
    message = json["message"]
    sender_id = json["sender_id"]
    sender_username = json["sender_username"]
    recipient_id = json["recipient_id"]

    recipient = User.query.get(recipient_id)
    recipient_public_key = serialization.load_pem_public_key(recipient.public_key.encode('utf-8'))

    encrypted_message = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')

    message_entry = Message.query.filter_by(room_id=room_id).first()

    chat_message = ChatMessage(
        content=encrypted_message_base64,
        timestamp=timestamp,
        sender_id=sender_id,
        sender_username=sender_username,
        room_id=room_id,
    )
    message_entry.messages.append(chat_message)

    try:
        chat_message.save_to_db()
        message_entry.save_to_db()
    except Exception as e:
        print(f"Error saving message to the database: {str(e)}")
        db.session.rollback()

    emit("message", {
        "message": message,
        "timestamp": timestamp,
        "sender_id": sender_id,
        "sender_username": sender_username,
        "room_id": room_id
    }, room=room_id, include_self=False)

    emit("message_sent", {
        "message": message,
        "timestamp": timestamp,
        "sender_id": sender_id,
        "sender_username": sender_username,
        "room_id": room_id
    })

if __name__ == "__main__":
    # socket.run(app, allow_unsafe_werkzeug=True, debug=True)
    # app.run()
    socket.run(app, host='0.0.0.0', port=5000)
