import hashlib
import uuid
import time

# Store sessions in memory
SESSIONS = {}

SESSION_EXPIRY_SECONDS = 3600  # 1 hour

def hash_password(password):
    # Add salt for better security
    salt = "veriq_secure_salt"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def create_session(user_id, role):
    token = str(uuid.uuid4())
    SESSIONS[token] = {
        "user_id": user_id,
        "role": role,
        "created": time.time()
    }
    return token

def verify_session(token):
    session = SESSIONS.get(token)

    if not session:
        return None

    # Expiry check
    if time.time() - session["created"] > SESSION_EXPIRY_SECONDS:
        del SESSIONS[token]
        return None

    return session

def destroy_session(token):
    if token in SESSIONS:
        del SESSIONS[token]