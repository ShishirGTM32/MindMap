from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, BooleanField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from db import User
from flask_wtf.file import FileField, FileRequired, FileAllowed
import re


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(message="First name is required"),
        Length(min=2, max=50, message="First name must be between 2 and 50 characters")
    ])
    
    last_name = StringField('Last Name', validators=[
        DataRequired(message="Last name is required"),
        Length(min=2, max=50, message="Last name must be between 2 and 50 characters")
    ])
    
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=10, message="Username must be between 3 and 10 characters")
    ])
    
    email = EmailField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, max=20, message="Password must be between 8 and 20 characters"),
        Regexp(
            r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$',
            message="Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character (@$!%*?&)"
        )
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])
    
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        from db import User  # Import here to avoid circular imports
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already taken. Please choose another one.")
        
    def validate_email(self, email):
        from db import User  # Import here to avoid circular imports
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered. Please use another email or login.")

    def validate_password(self, password):
        """Custom validation for password requirements"""
        pwd = password.data
        
        if not re.search(r'[A-Z]', pwd):
            raise ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', pwd):
            raise ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', pwd):
            raise ValidationError("Password must contain at least one number")
        
        if not re.search(r'[@$!%*?&]', pwd):
            raise ValidationError("Password must contain at least one special character (@$!%*?&)")   

class LoginForm(FlaskForm):
    csrf_enabled = False 
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password1 = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    new_password2 = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password1')])
    submit = SubmitField('Update Password')

class ChangeEmailForm(FlaskForm):
    email = EmailField('New Email Address', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Email')

class FileUploadForm(FlaskForm):
    file = FileField('File', validators=[
        FileRequired(),
        FileAllowed(
            ['pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'csv', 'xlsx'],
            'Only PDF, DOC, DOCX, TXT, PNG, JPG, JPEG, GIF, ZIP, CSV, and XLSX files are allowed!')
    ])
    description = TextAreaField('Description', validators=[Length(max=500)])
    submit = SubmitField('Upload File')

class FileEditForm(FlaskForm):
    filename = StringField('Filename', validators=[DataRequired(), Length(min=1, max=255)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    submit = SubmitField('Update File')

class FileShareForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Share File')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if not user:
            raise ValidationError("This email is not registered in the system.")

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')