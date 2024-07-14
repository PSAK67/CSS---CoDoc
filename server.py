from core import create_app
from core.database import db, Message, ChatMessage
from flask_socketio import emit, join_room, leave_room

app, socket = create_app()

# COMMUNICATION ARCHITECTURE

@socket.on("join-chat")
def join_private_chat(data):
    """
    Handle the 'join-chat' event.
    
    This function is triggered when a user joins a chat room. It adds the user
    to the specified room and notifies other users in the room.

    :param data: A dictionary containing the room ID ('rid')
    """
    room = data["rid"]
    join_room(room=room)
    socket.emit(
        "joined-chat",
        {"msg": f"{room} is now online."},
        room=room,
        # include_self=False,
    )

@socket.on("outgoing")
def chatting_event(json, methods=["GET", "POST"]):
    """
    Handle outgoing chat messages.
    
    This function is responsible for saving messages to the database and
    broadcasting them to all clients in the room.

    :param json: A dictionary containing message details
    :param methods: HTTP methods allowed for this event (default: ["GET", "POST"])
    """
    room_id = json["rid"]
    timestamp = json["timestamp"]
    message = json["message"]
    sender_id = json["sender_id"]
    sender_username = json["sender_username"]

    # Retrieve the message entry for the chat room
    message_entry = Message.query.filter_by(room_id=room_id).first()

    # Create a new chat message
    chat_message = ChatMessage(
        content=message,
        timestamp=timestamp,
        sender_id=sender_id,
        sender_username=sender_username,
        room_id=room_id,
    )

    # Add the new chat message to the messages relationship
    message_entry.messages.append(chat_message)

    # Save the new message to the database
    try:
        chat_message.save_to_db()
        message_entry.save_to_db()
    except Exception as e:
        # Log the error and rollback the database session
        print(f"Error saving message to the database: {str(e)}")
        db.session.rollback()

    # Broadcast the message to other users in the room
    socket.emit(
        "message",
        json,
        room=room_id,
        include_self=False,
    )

if __name__ == "__main__":
    socket.run(app, allow_unsafe_werkzeug=True, debug=True)