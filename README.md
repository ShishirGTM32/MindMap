# File Manager

A secure, feature-rich **file management system** built with Flask, enabling users to upload, share, and manage files with cloud storage integration via Backblaze B2.

## Overview

MindMap is a web-based file management platform that allows users to securely store, organize, and share files. With robust authentication, file sharing capabilities, and cloud storage integration, MindMap provides a complete solution for personal and collaborative file management.

## Key Features

### User Management
- **Secure Authentication**: User registration and login with Flask-Login
- **Password Security**: Bcrypt password hashing with secure password reset via email
- **Account Management**: Change username, email, and password
- **Rate Limiting**: Protection against brute force attacks (5 login attempts per minute)

### File Management
- **Cloud Storage**: Seamless integration with Backblaze B2 for reliable file storage
- **File Upload**: Support for multiple file types (up to 16MB per file)
- **File Organization**: List, search, and organize your files with descriptions
- **File Preview**: In-browser preview for images, PDFs, and text files
- **File Operations**: Rename, delete, and edit file metadata
- **Download Control**: Secure file downloads with authorization tokens

### Sharing & Collaboration
- **Email-Based Sharing**: Share files with registered users via email
- **Permission Management**: Control who has access to your files
- **Share Management**: View and revoke file access anytime
- **Shared Files View**: Access files shared with you in a dedicated section

### Security Features
- **Rate Limiting**: Per-user and per-IP rate limits on sensitive operations
- **Secure Sessions**: HTTP-only cookies with CSRF protection
- **File Authorization**: Time-limited, secure download URLs
- **Permission Checks**: Comprehensive access control on all file operations

## Getting Started

### Prerequisites

- Python 3.8+
- MySQL Database
- Backblaze B2 Account (for cloud storage)
- Gmail Account (for password reset emails)

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/ShishirGTM32/MindMap.git
cd MindMap
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**:
Create a `.env` file in the root directory:
```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=mysql://username:password@localhost/mindmap_db
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
B2_APPLICATION_KEY_ID=your-b2-key-id
B2_APPLICATION_KEY=your-b2-application-key
B2_BUCKET_NAME=your-bucket-name
```

5. **Initialize the database**:
```bash
flask db init
flask db migrate
flask db upgrade
```

6. **Run the application**:
```bash
export FLASK_APP=app.py
flask run
```

7. Open your browser and navigate to `http://localhost:5000`

## Usage Guide

### Getting Started

1. **Register**: Create an account with your email, username, and password
2. **Login**: Access your dashboard with your credentials
3. **Upload Files**: Click "Upload File" and select files from your device
4. **Manage Files**: View, rename, download, or delete your files

### Sharing Files

1. Navigate to your files list
2. Click the share icon next to any file
3. Enter the recipient's registered email address
4. The recipient will see the file in their "Shared with Me" section

### Managing Shared Access

1. Click "Manage Shares" on any of your files
2. View all users with access
3. Remove access by clicking "Remove" next to any user

### File Preview

- Click on any file to preview it (supports images, PDFs, and text files)
- Download files directly to your local storage
- View file details including size, type, and upload date

## Technical Stack

**Backend**:
- Flask 2.x
- Flask-Login (Authentication)
- Flask-SQLAlchemy (ORM)
- Flask-Mail (Email notifications)
- Flask-Limiter (Rate limiting)
- Flask-WTF (Forms and CSRF protection)

**Database**:
- MySQL / SQLite

**Cloud Storage**:
- Backblaze B2

**Security**:
- Werkzeug (Password hashing)
- itsdangerous (Token generation)

## Project Structure

```
MindMap/
├── app.py              # Main application file
├── db.py               # Database models
├── forms.py            # WTForms definitions
├── cloud.py            # Backblaze B2 integration
├── templates/          # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── files_list.html
│   ├── upload_file.html
│   └── manage_shares.html
├── static/             # CSS, JS, images
├── uploads/            # Temporary file storage
└── requirements.txt    # Python dependencies
```

## Key Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home page |
| `/register` | GET, POST | User registration |
| `/login` | GET, POST | User login |
| `/dashboard` | GET | User dashboard |
| `/files` | GET | List all files |
| `/files/upload` | GET, POST | Upload new file |
| `/files/download/<id>` | GET | Download file |
| `/files/<id>/share` | POST | Share file with user |
| `/files/<id>/delete` | POST | Delete file |
| `/reset-password` | GET, POST | Request password reset |

## Rate Limits

- **Registration**: 10 per hour
- **Login**: 5 per minute
- **File Upload**: 10 per hour
- **Password Change**: 5 per hour
- **Global**: 200 per day, 50 per hour

## Email Configuration

MindMap uses Gmail SMTP for sending password reset emails. To set up:

1. Enable 2-factor authentication on your Gmail account
2. Generate an App Password
3. Add credentials to your `.env` file

## Error Handling

The application includes comprehensive error handling:
- **404 errors**: Custom not found page
- **500 errors**: Internal server error handling with database rollback
- **Permission errors**: 403 Forbidden for unauthorized access
- **Validation errors**: Form validation with user-friendly messages

## Deployment Tips

1. **Use Production WSGI Server**: Deploy with Gunicorn or uWSGI
2. **Enable HTTPS**: Use SSL/TLS certificates (Let's Encrypt)
3. **Use Production Database**: PostgreSQL or MySQL
4. **Configure Environment Variables**: Never commit secrets to version control
5. **Set Up Logging**: Configure proper logging for production
6. **Use Redis for Rate Limiting**: Replace memory storage with Redis

## Future Enhancements

- [ ] Folder organization system
- [ ] Advanced file search and filtering
- [ ] File versioning
- [ ] Bulk file operations
- [ ] User storage quotas
- [ ] File compression
- [ ] Two-factor authentication
- [ ] Activity logs and audit trails
- [ ] Mobile app integration
- [ ] Real-time notifications

## Developer

**Shishir Gautam**
- GitHub: [@ShishirGTM32](https://github.com/ShishirGTM32)
- Email: shishirgautam3232@gmail.com

## Acknowledgments

- Flask documentation and community
- Backblaze B2 for cloud storage
- Bootstrap for UI components

---

If you find this project useful, please consider giving it a star on GitHub!
