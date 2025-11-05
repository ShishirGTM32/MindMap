from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
from flask import send_from_directory, current_app
from werkzeug.utils import secure_filename
import mimetypes
from datetime import datetime
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

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024



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
    """List all files - user's own files and others' files"""
    user_files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).all()
    other_files = File.query.filter(File.user_id != current_user.id).order_by(File.upload_date.desc()).all()
    
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
            # Secure the filename
            original_filename = secure_filename(file.filename)
            
            # Create unique filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{original_filename}"
            
            # Save file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Get file info
            file_size = os.path.getsize(file_path)
            mime_type = mimetypes.guess_type(file_path)[0]
            
            # Create database entry
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
                # Delete the file if database insertion fails
                if os.path.exists(file_path):
                    os.remove(file_path)
                print(f"Error uploading file: {e}")
                flash('An error occurred while uploading the file.', 'danger')
    
    return render_template('upload_file.html', form=form)

# @app.route('/files/<int:file_id>')
# @login_required
# def view_file(file_id):
#     """View file details"""
#     file = File.query.get_or_404(file_id)
#     is_owner = file.user_id == current_user.id
    
#     return render_template('view_file.html', file=file, is_owner=is_owner)

# @app.route('/files/<int:file_id>')
# @login_required
# def view_file(file_id):
#     """View file details"""
#     file = File.query.get_or_404(file_id)
#     is_owner = file.user_id == current_user.id

#     # Assuming 'file_path' is a column in your 'File' model that stores the relative file path
#     file_path = file.file_path  # Replace 'file_path' with your actual column name
#     file_name = os.path.basename(file_path)
#     file_directory = os.path.dirname(file_path)

#     # Optionally, you can check the file type and display it accordingly
#     file_extension = file_name.split('.')[-1].lower()

#     # You could add some logic to handle different file types (e.g., images, PDFs)
#     if file_extension in ['jpg', 'jpeg', 'png', 'gif']:
#         return send_from_directory(file_directory, file_name, as_attachment=False)
#     elif file_extension in ['pdf', 'txt', 'docx']:
#         return send_from_directory(file_directory, file_name, as_attachment=False)
#     else:
#         # For unsupported file types, offer a download
#         return send_from_directory(file_directory, file_name, as_attachment=True)

#     return render_template('view_file.html', file=file, is_owner=is_owner)

@app.route('/files/<int:file_id>')
@login_required
def view_file(file_id):
    """View file details"""
    file = File.query.get_or_404(file_id)
    is_owner = file.user_id == current_user.id

    # Read the content of text files
    file_content = None
    if file.mime_type == 'text/plain':
        try:
            with open(file.file_path, 'r') as f:
                file_content = f.read()
        except Exception as e:
            file_content = f"Error reading file: {e}"

    # Pass file content to the template
    return render_template('view_file.html', file=file, is_owner=is_owner, file_content=file_content)


@app.route('/files/serve/<int:file_id>')
@login_required
def serve_file(file_id):
    """Serve the file for viewing (not downloading)"""
    file = File.query.get_or_404(file_id)
    
    # Check permission
    if file.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to access this file.', 'danger')
        return redirect(url_for('files_list'))
    
    try:
        # Serve file without forcing download
        return send_from_directory(
            directory=os.path.dirname(file.file_path),
            path=os.path.basename(file.file_path),
            as_attachment=False  # This allows viewing in browser
        )
    except FileNotFoundError:
        flash('File not found!', 'danger')
        return redirect(url_for('files_list'))

@app.route('/files/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Serve the file for download"""
    file = File.query.get_or_404(file_id)
    
    # Check permission
    if file.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to access this file.', 'danger')
        return redirect(url_for('files_list'))
    
    try:
        # Force download
        return send_from_directory(
            directory=os.path.dirname(file.file_path),
            path=os.path.basename(file.file_path),
            as_attachment=True  # Forces the download
        )
    except FileNotFoundError:
        flash('File not found!', 'danger')
        return redirect(url_for('files_list'))


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

if __name__ == '__main__':
    app.run(debug=True)