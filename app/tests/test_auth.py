import pytest
from app.auth.forms import RegistrationForm, LoginForm
from app.models import User

def test_registration_form_validation(app):
    with app.app_context():
        # Test valid data
        form = RegistrationForm(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!',
            confirm_password='TestPassword123!'
        )
        assert form.validate() is True

        # Test invalid email
        form.email = 'invalid-email'
        assert form.validate() is False
        assert 'email' in form.errors

        # Test password mismatch
        form.email = 'test@example.com'
        form.confirm_password = 'DifferentPassword123!'
        assert form.validate() is False
        assert 'confirm_password' in form.errors

def test_login_form_validation(app):
    # Test valid data
    form = LoginForm(
        username='testuser',
        password='TestPassword123!'
    )
    assert form.validate() is True

    # Test missing username
    form.username = ''
    assert form.validate() is False
    assert 'username' in form.errors

def test_user_registration(client, app):
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'TestPassword123!',
        'confirm_password': 'TestPassword123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Your account has been created' in response.data

    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.email == 'test@example.com'