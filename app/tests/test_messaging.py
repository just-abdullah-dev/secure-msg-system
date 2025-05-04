import pytest
from app.models import User, Message
from app.messaging.utils import (
    generate_aes_key, encrypt_message_aes, decrypt_message_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa,
    generate_hash
)

def test_encryption_decryption_cycle():
    # Test AES encryption/decryption
    original_message = "This is a secret message"
    aes_key = generate_aes_key()
    iv, encrypted = encrypt_message_aes(original_message, aes_key)
    decrypted = decrypt_message_aes(encrypted, iv, aes_key)
    assert decrypted == original_message

    # Test RSA encryption/decryption
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)
    encrypted_key = encrypt_aes_key_with_rsa(aes_key, key.publickey().export_key())
    decrypted_key = decrypt_aes_key_with_rsa(encrypted_key, key.export_key())
    assert decrypted_key == aes_key

def test_hash_verification():
    data = "Test data for hashing"
    hash_value = generate_hash(data)
    assert verify_hash(data, hash_value) is True
    assert verify_hash(data + "tampered", hash_value) is False

def test_message_sending(client, app):
    # First register and login a test user
    client.post('/register', data={
        'username': 'sender',
        'email': 'sender@example.com',
        'password': 'TestPassword123!',
        'confirm_password': 'TestPassword123!'
    })
    client.post('/register', data={
        'username': 'recipient',
        'email': 'recipient@example.com',
        'password': 'TestPassword123!',
        'confirm_password': 'TestPassword123!'
    })
    
    # Login as sender
    client.post('/login', data={
        'username': 'sender',
        'password': 'TestPassword123!'
    })
    
    # Send a message
    with app.app_context():
        recipient = User.query.filter_by(username='recipient').first()
        response = client.post('/send_message', data={
            'recipient_id': recipient.id,
            'message': 'Hello, this is a test message'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Message sent successfully' in response.data
        
        message = Message.query.first()
        assert message is not None
        assert message.sender_id == User.query.filter_by(username='sender').first().id
        assert message.recipient_id == recipient.id