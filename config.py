import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or 'mysql+pymysql://root:@localhost/cyber'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Encryption settings
    AES_KEY_SIZE = 32  # 256 bits
    RSA_KEY_SIZE = 2048
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour in seconds
    
    # Security settings
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 300  # 5 minutes in seconds