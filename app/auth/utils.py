from flask import current_app
from app.models import User
# from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
from flask_login import current_user
from flask_bcrypt import check_password_hash
from app import db

def validate_login(username, password):
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return False, "User not found"
    
    if user.locked_until and user.locked_until > datetime.utcnow():
        return False, f"Account locked until {user.locked_until.strftime('%Y-%m-%d %H:%M:%S')}"
    
    if not check_password_hash(user.password_hash, password):
        user.login_attempts += 1
        if user.login_attempts >= current_app.config['MAX_LOGIN_ATTEMPTS']:
            user.locked_until = datetime.utcnow() + timedelta(seconds=current_app.config['LOCKOUT_TIME'])
        db.session.commit()
        
        attempts_left = current_app.config['MAX_LOGIN_ATTEMPTS'] - user.login_attempts
        if attempts_left > 0:
            return False, f"Invalid password. {attempts_left} attempts remaining."
        else:
            return False, "Account locked due to too many failed attempts. Try again later."
    
    # Reset login attempts on successful login
    user.login_attempts = 0
    user.locked_until = None
    db.session.commit()
    
    return True, "Login successful"