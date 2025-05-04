from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from app import db, bcrypt
from app.models import User
from app.auth.utils import validate_login
from .forms import RegistrationForm, LoginForm
from datetime import datetime
from Crypto.PublicKey import RSA

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('messaging.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Generate RSA key pair for the user
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            rsa_public_key=public_key,
            rsa_private_key=private_key
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', title='Register', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('messaging.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        is_valid, message = validate_login(form.username.data, form.password.data)
        if is_valid:
            user = User.query.filter_by(username=form.username.data).first()
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('You have been logged in!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('messaging.dashboard'))
        else:
            flash(message, 'danger')
    
    return render_template('auth/login.html', title='Login', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))