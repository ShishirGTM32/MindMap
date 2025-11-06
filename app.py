from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
from flask import send_from_directory, current_app
from werkzeug.utils import secure_filename
from flask_mail import Message
import mimetypes
from datetime import datetime
import os
from db import *
from forms import *
from urllib.parse import urlparse, urljoin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = False 
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_HOST_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_HOST_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_HOST_USER')

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

mail = Mail(app) 
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY']) 



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
    return render_template('index.html')

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

@app.route('/files')
@login_required
def files_list():
    """List all files - user's own files and files shared with them"""
    user_files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).all()
    shared_file_ids = db.session.query(Share_File.file_id).filter_by(email=current_user.email).all()
    shared_file_ids = [id[0] for id in shared_file_ids]
    other_files = File.query.filter(File.id.in_(shared_file_ids)).order_by(File.upload_date.desc()).all()
    
    return render_template('files_list.html', 
                         user_files=user_files, 
                         other_files=other_files)

@app.route('/files/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Upload a new file"""
    form = FileUploadForm()
    
    if form.validate_on_submit():
        file = form.file.data
        
        if file:
            original_filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{original_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            file_size = os.path.getsize(file_path)
            mime_type = mimetypes.guess_type(file_path)[0]
            new_file = File(
                filename=filename,
                original_filename=original_filename,
                description=form.description.data,
                file_path=file_path,
                file_size=file_size,
                mime_type=mime_type,
                user_id=current_user.id
            )
            
            try:
                db.session.add(new_file)
                db.session.commit()
                flash('File uploaded successfully!', 'success')
                return redirect(url_for('files_list'))
            except Exception as e:
                db.session.rollback()
                if os.path.exists(file_path):
                    os.remove(file_path)
                print(f"Error uploading file: {e}")
                flash('An error occurred while uploading the file.', 'danger')
    
    return render_template('upload_file.html', form=form)

@app.route('/files/view/<int:file_id>')
@login_required
def view_file(file_id):
    """View a specific file"""
    file = File.query.get_or_404(file_id)
    
    # Check if user is owner or file is shared with them
    is_owner = file.user_id == current_user.id
    is_shared = Share_File.query.filter_by(
        file_id=file_id, 
        email=current_user.email
    ).first() is not None
    
    if not (is_owner or is_shared):
        flash('You do not have permission to view this file.', 'danger')
        return redirect(url_for('files_list'))
    
    return render_template('view_file.html', file=file, is_owner=is_owner)


@app.route('/files/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Download a file"""
    file = File.query.get_or_404(file_id)
    
    # Check if user is owner or file is shared with them
    is_owner = file.user_id == current_user.id
    is_shared = Share_File.query.filter_by(
        file_id=file_id, 
        email=current_user.email
    ).first() is not None
    
    if not (is_owner or is_shared):
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('files_list'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    
    if not os.path.exists(file_path):
        flash('File not found on server.', 'danger')
        return redirect(url_for('files_list'))
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file.original_filename
    )


@app.route('/files/serve/<int:file_id>')
@login_required
def serve_file(file_id):
    """Serve a file for preview (inline display)"""
    file = File.query.get_or_404(file_id)
    
    # Check if user is owner or file is shared with them
    is_owner = file.user_id == current_user.id
    is_shared = Share_File.query.filter_by(
        file_id=file_id, 
        email=current_user.email
    ).first() is not None
    
    if not (is_owner or is_shared):
        abort(403)  # Forbidden
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    
    if not os.path.exists(file_path):
        abort(404)  # Not found
    
    return send_file(
        file_path,
        mimetype=file.mime_type,
        as_attachment=False,
        download_name=file.original_filename
    )

@app.route('/files/<int:file_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    """Edit file details (owner only)"""
    file = File.query.get_or_404(file_id)
    
    # Check if current user is the owner
    if file.user_id != current_user.id:
        flash('You do not have permission to edit this file.', 'danger')
        return redirect(url_for('view_file', file_id=file_id))
    
    form = FileEditForm()
    
    if form.validate_on_submit():
        try:
            # Update filename if changed
            new_filename = secure_filename(form.filename.data)
            if new_filename != file.original_filename:
                # Create new filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                new_full_filename = f"{timestamp}_{new_filename}"
                
                # Rename the physical file
                new_path = os.path.join(app.config['UPLOAD_FOLDER'], new_full_filename)
                if os.path.exists(file.file_path):
                    os.rename(file.file_path, new_path)
                    file.file_path = new_path
                    file.filename = new_full_filename
                
                file.original_filename = new_filename
            
            file.description = form.description.data
            db.session.commit()
            
            flash('File updated successfully!', 'success')
            return redirect(url_for('view_file', file_id=file.id))
        except Exception as e:
            db.session.rollback()
            print(f"Error editing file: {e}")
            flash('An error occurred while updating the file.', 'danger')
    
    # Pre-populate form
    if request.method == 'GET':
        form.filename.data = file.original_filename
        form.description.data = file.description
    
    return render_template('edit_file.html', form=form, file=file)

@app.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file (owner only)"""
    file = File.query.get_or_404(file_id)
    
    # Check if current user is the owner
    if file.user_id != current_user.id:
        flash('You do not have permission to delete this file.', 'danger')
        return redirect(url_for('view_file', file_id=file_id))
    
    try:
        # Delete physical file
        if os.path.exists(file.file_path):
            os.remove(file.file_path)
        
        # Delete database entry
        db.session.delete(file)
        db.session.commit()
        
        flash('File deleted successfully!', 'success')
        return redirect(url_for('files_list'))
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting file: {e}")
        flash('An error occurred while deleting the file.', 'danger')
        return redirect(url_for('view_file', file_id=file_id))

@app.route('/files/<int:file_id>/share', methods=['POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'You do not have permission to share this file.'}), 403
    email_data = request.json.get('email')
    if not email_data:
        return jsonify({'success': False, 'message': 'Email is required.'}), 400
    user = User.query.filter_by(email=email_data).first()
    if not user:
        return jsonify({'success': False, 'message': 'This email is not registered in the system.'}), 400
    if email_data == current_user.email:
        return jsonify({'success': False, 'message': 'You cannot share a file with yourself.'}), 400

    #Checking if file already shared
    existing_share = Share_File.query.filter_by(
        email=email_data, 
        file_id=file_id
    ).first()
    
    if existing_share:
        return jsonify({'success': False, 'message': 'File is already shared with this user.'}), 400
    
    try:
        share = Share_File(
            email=email_data,
            file_id=file_id
        )
        db.session.add(share)
        db.session.commit()
        return jsonify({'success': True, 'message': f'File shared successfully with {email_data}!'})
    except Exception as e:
        db.session.rollback()
        print(f"Error sharing file: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while sharing the file.'}), 500

@app.route('/files/<int:file_id>/get-shares', methods=['GET'])
@login_required
def get_shares(file_id):
    """Get list of shares for a file"""
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'You do not have permission to view shares.'}), 403
    
    shares = Share_File.query.filter_by(file_id=file_id).all()
    
    shares_data = [{
        'id': share.id,
        'email': share.email,
        'shared_at': share.shared_at.isoformat()
    } for share in shares]
    
    return jsonify({'success': True, 'shares': shares_data})

@app.route('/files/<int:file_id>/manage-shares', methods=['GET'])
@login_required
def manage_shares(file_id):
    """View and manage who has access to a file"""
    file = File.query.get_or_404(file_id)
    
    # Check if current user is the owner
    if file.user_id != current_user.id:
        flash('You do not have permission to manage shares for this file.', 'danger')
        return redirect(url_for('files_list'))
    
    # Get all shares for this file
    shares = Share_File.query.filter_by(file_id=file_id).all()
    
    return render_template('manage_shares.html', file=file, shares=shares)


@app.route('/files/<int:file_id>/remove-share/<int:share_id>', methods=['POST'])
@login_required
def remove_share(file_id, share_id):
    """Remove a share from a file"""
    file = File.query.get_or_404(file_id)
    share = Share_File.query.get_or_404(share_id)
    
    if file.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'You do not have permission to remove this share.'}), 403
    
    if share.file_id != file_id:
        return jsonify({'success': False, 'message': 'Invalid share.'}), 400
    
    try:
        email = share.email
        db.session.delete(share)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Removed access for {email}'})
    except Exception as e:
        db.session.rollback()
        print(f"Error removing share: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while removing the share.'}), 500

#password reset routes
def send_reset_email(user_email, token):
    """Send password reset email"""
    reset_url = url_for('reset_password_confirm', token=token, _external=True)
    
    msg = Message('Password Reset Request',
                  recipients=[user_email])
    
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.

This link will expire in 1 hour.
'''
    
    msg.html = f'''
    <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #667eea;">Password Reset Request</h2>
        <p>You requested to reset your password. Click the button below to proceed:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" 
               style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                      color: white; 
                      padding: 12px 30px; 
                      text-decoration: none; 
                      border-radius: 25px;
                      display: inline-block;">
                Reset Password
            </a>
        </div>
        <p style="color: #666;">Or copy and paste this link:</p>
        <p style="background: #f5f5f5; padding: 10px; word-break: break-all;">{reset_url}</p>
        <p style="color: #999; font-size: 12px; margin-top: 30px;">
            If you did not request this, please ignore this email. This link will expire in 1 hour.
        </p>
    </div>
    '''
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    """Request password reset"""
    if current_user.is_authenticated:
        return redirect(url_for('files_list'))
    
    form = ResetPasswordRequestForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            # Generate token
            token = serializer.dumps(user.email, salt='password-reset-salt')
            
            # Send email
            if send_reset_email(user.email, token):
                flash('A password reset link has been sent to your email.', 'success')
            else:
                flash('Failed to send reset email. Please try again.', 'danger')
        else:
            # Don't reveal if user exists or not for security
            flash('If that email exists, a reset link has been sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('reset_password_request.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    """Confirm password reset with token"""
    if current_user.is_authenticated:
        return redirect(url_for('files_list'))
    
    try:
        # Verify token (expires after 1 hour = 3600 seconds)
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('reset_password_request'))
    except BadSignature:
        flash('Invalid password reset link.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('reset_password_request'))
    
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        # Use set_password method instead of direct assignment
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password_confirm.html', form=form, token=token)

if __name__ == '__main__':
    app.run(debug=True)