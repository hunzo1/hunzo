import bcrypt
import re
from database import create_user, get_user_by_email

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> tuple:
    """Returns (is_valid, error_message)"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, ""

def register_user(email: str, password: str) -> tuple:
    """Returns (success, user_or_error)"""
    if not validate_email(email):
        return False, "Invalid email address"

    valid, error = validate_password(password)
    if not valid:
        return False, error

    if get_user_by_email(email):
        return False, "An account with this email already exists"

    password_hash = hash_password(password)
    user = create_user(email, password_hash)

    if not user:
        return False, "Could not create account. Please try again."

    return True, user

def login_user(email: str, password: str) -> tuple:
    """Returns (success, user_or_error)"""
    if not email or not password:
        return False, "Email and password are required"

    user = get_user_by_email(email)
    if not user:
        return False, "Invalid email or password"

    if not verify_password(password, user["password_hash"]):
        return False, "Invalid email or password"

    return True, user
