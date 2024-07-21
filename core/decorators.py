# Login decorator to ensure user is logged in before accessing certain routes
from flask import url_for, redirect, session
from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("views.login"))
        return f(*args, **kwargs)

    return decorated