from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_required, current_user
from app import db
from app.models import User, Message
from datetime import datetime
from .utils import (
    generate_aes_key, encrypt_message_aes, decrypt_message_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa,
    generate_hash, encrypt_file, decrypt_file
)
from werkzeug.utils import secure_filename
import os
import base64
from io import BytesIO

messaging_bp = Blueprint('messaging', __name__)

@messaging_bp.route('/dashboard')
@login_required
def dashboard():
    users = User.query.filter(User.id != current_user.id).all()
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) | 
        (Message.recipient_id == current_user.id)
    ).order_by(Message.timestamp.desc()).limit(10).all()
    
    return render_template('messaging/dashboard.html', users=users, messages=messages)

@messaging_bp.route('/send_message', methods=['POST'])
@login_required
def send_message():
    recipient_id = request.form.get('recipient_id')
    message_content = request.form.get('message')
    
    if not recipient_id or not message_content:
        flash('Recipient and message are required', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    recipient = User.query.get(recipient_id)
    if not recipient:
        flash('Recipient not found', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    # Generate AES key for this message
    aes_key = generate_aes_key()
    
    # Encrypt the message with AES
    iv, encrypted_message = encrypt_message_aes(message_content, aes_key)
    
    # Encrypt the AES key with recipient's RSA public key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, recipient.rsa_public_key)
    
    # Generate hash of the original message for integrity check
    message_hash = generate_hash(message_content)
    
    # Create and save the message
    message = Message(
        content=message_content,
        encrypted_content=base64.b64encode(encrypted_message).decode('utf-8'),
        iv=base64.b64encode(iv).decode('utf-8'),
        encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode('utf-8'),
        sender_id=current_user.id,
        recipient_id=recipient.id,
        hash_value=message_hash,
        is_file=False
    )
    
    db.session.add(message)
    db.session.commit()
    
    flash('Message sent successfully!', 'success')
    return redirect(url_for('messaging.dashboard'))

@messaging_bp.route('/decrypt_message/<int:message_id>', methods=['GET'])
@login_required
def decrypt_message(message_id):
    message = Message.query.get_or_404(message_id)
    
    if message.recipient_id != current_user.id and message.sender_id != current_user.id:
        flash('You are not authorized to view this message', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    try:
        # Decrypt the AES key with recipient's private key
        encrypted_aes_key = base64.b64decode(message.encrypted_aes_key.encode('utf-8'))
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, current_user.rsa_private_key)
        
        # Decrypt the message with AES
        iv = base64.b64decode(message.iv.encode('utf-8'))
        encrypted_message = base64.b64decode(message.encrypted_content.encode('utf-8'))
        decrypted_message = decrypt_message_aes(encrypted_message, iv, aes_key)
        
        if not decrypted_message:
            flash('Failed to decrypt the message. It may have been tampered with.', 'danger')
            return redirect(url_for('messaging.dashboard'))
        
        # Verify the hash
        if not generate_hash(decrypted_message) == message.hash_value:
            flash('Message integrity check failed. The message may have been altered.', 'warning')
        
        return render_template('messaging/decrypt.html', 
                            message=message, 
                            decrypted_content=decrypted_message)
    
    except Exception as e:
        flash(f'Error decrypting message: {str(e)}', 'danger')
        return redirect(url_for('messaging.dashboard'))

@messaging_bp.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    file = request.files['file']
    recipient_id = request.form.get('recipient_id')
    
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    if not recipient_id:
        flash('Recipient is required', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    recipient = User.query.get(recipient_id)
    if not recipient:
        flash('Recipient not found', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    # Read file data
    file_data = file.read()
    file_name = secure_filename(file.filename)
    
    # Generate AES key for this file
    aes_key = generate_aes_key()
    
    # Encrypt the file with AES
    iv, encrypted_file_data = encrypt_file(file_data, aes_key)
    
    # Encrypt the AES key with recipient's RSA public key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, recipient.rsa_public_key)
    
    # Generate hash of the original file for integrity check
    file_hash = generate_hash(file_data)
    
    # Create and save the message
    message = Message(
        content="File: " + file_name,
        encrypted_content=base64.b64encode(encrypted_file_data).decode('utf-8'),
        iv=base64.b64encode(iv).decode('utf-8'),
        encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode('utf-8'),
        sender_id=current_user.id,
        recipient_id=recipient.id,
        hash_value=file_hash,
        is_file=True,
        file_name=file_name,
        file_type=file.content_type,
        file_size=len(file_data)
    )
    
    db.session.add(message)
    db.session.commit()
    
    flash('File uploaded and encrypted successfully!', 'success')
    return redirect(url_for('messaging.dashboard'))

@messaging_bp.route('/download_file/<int:message_id>', methods=['GET'])
@login_required
def download_file(message_id):
    message = Message.query.get_or_404(message_id)
    
    if message.recipient_id != current_user.id and message.sender_id != current_user.id:
        flash('You are not authorized to download this file', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    if not message.is_file:
        flash('This message is not a file', 'danger')
        return redirect(url_for('messaging.dashboard'))
    
    try:
        # Decrypt the AES key with recipient's private key
        encrypted_aes_key = base64.b64decode(message.encrypted_aes_key.encode('utf-8'))
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, current_user.rsa_private_key)
        
        # Decrypt the file with AES
        iv = base64.b64decode(message.iv.encode('utf-8'))
        encrypted_file_data = base64.b64decode(message.encrypted_content.encode('utf-8'))
        decrypted_file_data = decrypt_file(encrypted_file_data, iv, aes_key)
        
        if not decrypted_file_data:
            flash('Failed to decrypt the file. It may have been tampered with.', 'danger')
            return redirect(url_for('messaging.dashboard'))
        
        # Verify the hash
        if not generate_hash(decrypted_file_data) == message.hash_value:
            flash('File integrity check failed. The file may have been altered.', 'warning')
        
        # Create a file-like object in memory
        file_obj = BytesIO(decrypted_file_data)
        
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=message.file_name,
            mimetype=message.file_type
        )
    
    except Exception as e:
        flash(f'Error decrypting file: {str(e)}', 'danger')
        return redirect(url_for('messaging.dashboard'))

@messaging_bp.route('/messages')
@login_required
def view_messages():
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) | 
        (Message.recipient_id == current_user.id)
    ).order_by(Message.timestamp.desc()).all()
    
    return render_template('messaging/messages.html', messages=messages)