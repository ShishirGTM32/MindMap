from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
import os
from db import *
from forms import *
from urllib.parse import urlparse, urljoin

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = False  # Set to True in production
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

# Initialize database
init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            user = User(
                first_name=form.first_name.data,  
                last_name=form.last_name.data,    
                username=form.username.data,      
                email=form.email.data             
            )
            user.set_password(form.password.data) 
            db.session.add(user)
            db.session.commit() 

            print(f"User registered successfully: {user.username} (ID: {user.id})")
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        print("User already authenticated, redirecting to dashboard")
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        print(f"Form validated. Username: {form.username.data}")
        
        try:
            user = User.query.filter_by(username=form.username.data).first()
            
            if user:
                print(f"User found: {user.username}, ID: {user.id}, Active: {user.is_active}")
                
                if user.check_password(form.password.data):
                    print("Password correct, attempting login")
                    
                    # Refresh user from database to ensure it's properly attached to session
                    db.session.refresh(user)
                    
                    # Attempt login
                    login_result = login_user(user, remember=form.remember.data)
                    print(f"login_user returned: {login_result}")
                    print(f"After login_user - Authenticated: {current_user.is_authenticated}")
                    
                    if current_user.is_authenticated:
                        print(f"Current user ID: {current_user.get_id()}")
                        print(f"Current user username: {current_user.username}")
                        flash('Login successful!', 'success')
                        
                        # Handle next parameter safely
                        next_page = request.args.get('next')
                        if next_page:
                            parsed_url = urlparse(next_page)
                            # Only allow internal redirects
                            if parsed_url.netloc == '' or parsed_url.netloc == request.host:
                                print(f"Redirecting to: {next_page}")
                                return redirect(next_page)
                        
                        return redirect(url_for('dashboard'))
                    else:
                        print("ERROR: login_user was called but user is not authenticated")
                        flash('Login failed. Please try again.', 'danger')
                else:
                    print("Password incorrect")
                    flash('Login failed. Check your username and/or password.', 'danger')
            else:
                print("User not found")
                flash('Login failed. Check your username and/or password.', 'danger')
        
        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    username = current_user.username
    logout_user()
    print(f"User {username} logged out")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    print(f"Dashboard accessed by: {current_user.username} (ID: {current_user.id})")
    return render_template('account.html', user=current_user)

@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    """Change username"""
    new_username = request.form.get('username')
    
    if not new_username:
        flash('Username cannot be empty!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if username is already taken
    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user and existing_user.id != current_user.id:
        flash('Username is already taken!', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        current_user.username = new_username
        db.session.commit()
        print(f"Username changed to: {new_username}")
        flash('Username updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error changing username: {e}")
        flash('An error occurred while updating username.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    old_password = request.form.get('old_password')
    new_password1 = request.form.get('new_password1')
    new_password2 = request.form.get('new_password2')

    # Validation
    if not all([old_password, new_password1, new_password2]):
        flash('All password fields are required!', 'danger')
        return redirect(url_for('dashboard'))

    # Check if old password is correct
    if not current_user.check_password(old_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('dashboard'))

    # Check if new passwords match
    if new_password1 != new_password2:
        flash('New passwords do not match!', 'danger')
        return redirect(url_for('dashboard'))

    # Check password length
    if len(new_password1) < 6:
        flash('Password must be at least 6 characters long!', 'danger')
        return redirect(url_for('dashboard'))

    # Update the password
    try:
        current_user.set_password(new_password1)
        db.session.commit()
        print(f"Password changed for user: {current_user.username}")
        flash('Password updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error changing password: {e}")
        flash('An error occurred while updating password.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    """Change user email"""
    new_email = request.form.get('email')

    if not new_email:
        flash('Email cannot be empty!', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the new email is already taken
    existing_user = User.query.filter_by(email=new_email).first()
    if existing_user and existing_user.id != current_user.id:
        flash('Email is already taken!', 'danger')
        return redirect(url_for('dashboard'))

    try:
        current_user.email = new_email
        db.session.commit()
        print(f"Email changed for user: {current_user.username} to {new_email}")
        flash('Email updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error changing email: {e}")
        flash('An error occurred while updating email.', 'danger')

    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return jsonify(error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return jsonify(error="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=True)