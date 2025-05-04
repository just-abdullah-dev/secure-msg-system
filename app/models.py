from app import db, bcrypt
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    rsa_public_key = db.Column(db.Text)
    rsa_private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text)  # Initialization vector for AES
    encrypted_aes_key = db.Column(db.Text)  # AES key encrypted with recipient's RSA public key
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_file = db.Column(db.Boolean, default=False)
    file_name = db.Column(db.String(100))
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    hash_value = db.Column(db.String(64))  # SHA-256 hash of original content
    
    def __repr__(self):
        return f"Message('{self.content[:20]}...', '{self.timestamp}')"