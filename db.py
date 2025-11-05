from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_login import UserMixin
from datetime import datetime
from flask_migrate import Migrate
import os
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import quote_plus

# Install pymysql to act as MySQLdb
pymysql.install_as_MySQLdb()

# Load environment variables from .env file
load_dotenv()

# Initialize the database object
db = SQLAlchemy()
migrate = Migrate()
# Database configuration function
def init_app(app):
    # Get environment variables
    mysql_user = os.getenv('MYSQL_USER')
    mysql_password = os.getenv('MYSQL_PASSWORD')
    mysql_host = os.getenv('MYSQL_HOST')
    mysql_db = os.getenv('MYSQL_DB')

    encoded_password = quote_plus(mysql_password)

    # Check if any environment variables are missing
    if not mysql_user or not encoded_password or not mysql_host or not mysql_db:
        raise ValueError("Missing one or more required environment variables: MYSQL_USER, MYSQL_PASSWORD, MYSQL_HOST, MYSQL_DB")

    # Set Flask app's database URI
    app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{mysql_user}:{encoded_password}@{mysql_host}/{mysql_db}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking to save resources

    # Initialize the SQLAlchemy object with the app
    db.init_app(app)
    migrate.init_app(app, db)

class User(UserMixin,db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    username = db.Column(db.String(10), nullable=False, unique = True)
    email = db.Column(db.String(80), nullable=False, unique = True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def __init__(self, first_name, last_name, username, email):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.email = email

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f"User(name='{self.username}', email='{self.email}')"
    
class File(db.Model):
    __tablename__ = "files"
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)  # in bytes
    mime_type = db.Column(db.String(100))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationship
    owner = db.relationship('User', backref=db.backref('files', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f"File('{self.filename}', owner='{self.owner.username}')"

