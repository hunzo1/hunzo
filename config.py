import os
import secrets
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Security
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY") or None
    
    # Database
    DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hunzo.db")
    
    # App
    APP_NAME = "Hunzo"
    VERSION = "1.0.0"
    
    # Rate limiting
    FREE_DAILY_CHECKS = 10
    
    # Session
    SESSION_COOKIE_SECURE = False  # True in production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 30  # 30 days
