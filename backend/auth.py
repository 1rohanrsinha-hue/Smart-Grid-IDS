"""
auth.py
========
Minimal DEMO login: a username + role selector, no password, no
hashing, no real authentication. Just gates access and stores the
chosen role in a Flask session cookie so app.py routes can check it.

Roles:
  operator - can view everything + trigger manual attacks/scenarios
  admin    - operator privileges + model switching + report export +
             model-comparison panel visibility
"""

from functools import wraps
from flask import session, jsonify

VALID_ROLES = ("operator", "admin")


def login(username, role):
    role = (role or "").lower().strip()
    if role not in VALID_ROLES:
        return {"ok": False, "reason": f"Invalid role. Must be one of {VALID_ROLES}."}
    if not username or not username.strip():
        return {"ok": False, "reason": "Username is required."}
    session["username"] = username.strip()
    session["role"] = role
    return {"ok": True, "username": session["username"], "role": role}


def logout():
    session.clear()
    return {"ok": True}


def current_session():
    if "role" not in session:
        return None
    return {"username": session.get("username", "guest"), "role": session["role"]}


def require_role(*allowed_roles):
    """Decorator for Flask routes: 403s if not logged in with an
    allowed role. Since this is a demo, an unauthenticated request is
    treated as a read-only 'operator' by default for GET-only status
    endpoints elsewhere; this decorator is used only on routes that
    should be gated (admin-only actions)."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            sess = current_session()
            if sess is None or sess["role"] not in allowed_roles:
                return jsonify({
                    "ok": False,
                    "reason": f"This action requires one of roles {allowed_roles}. "
                              f"Please log in at /login.html.",
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
