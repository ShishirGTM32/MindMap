from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, BooleanField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from db import User
from flask_wtf.file import FileField, FileRequired, FileAllowed


class RegistrationForm(FlaskForm):
    first_name =  StringField('first_name',
                           validators=[DataRequired()])
    last_name =  StringField('last_name',
                           validators=[DataRequired()])
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=3, max=10)])
    email = EmailField('Email',
                            validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                            validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password',
                            validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        if User.query.filter_by(username=username).first():
            raise ValidationError("Username Already Taken.")
        
    def validate_email(self, email):
        if User.query.filter_by(email=email).first():
            raise ValidationError("Email Already Taken.")
        
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