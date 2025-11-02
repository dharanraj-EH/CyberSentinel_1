# CyberSentinel Authentication System

## Overview

CyberSentinel now includes a complete user authentication system with registration and login functionality. The system uses SQLite database for secure user storage with password hashing and salting.

## Features

- **User Registration**: Create new user accounts with username, email, full name, and password
- **User Login**: Authenticate with username/email and password
- **Password Security**: Passwords are hashed with SHA-256 and unique salts
- **Database Storage**: SQLite database for persistent user data
- **Session Management**: Track logged-in users and session validation
- **Modern UI**: Clean, responsive authentication dialogs

## Database Schema

The user database includes the following fields:
- `id`: Unique user identifier (auto-increment)
- `username`: Unique username (3+ characters)
- `email`: Unique email address
- `full_name`: User's full name
- `password_hash`: SHA-256 hashed password
- `salt`: Unique salt for password hashing
- `created_at`: Account creation timestamp
- `last_login`: Last login timestamp
- `is_active`: Account status (active/inactive)
- `role`: User role (user/admin)

## Usage

### Running the Application

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the main application:
   ```bash
   python main.py
   ```

3. The login dialog will appear automatically. You can:
   - Click "Create Account" to register a new user
   - Enter existing credentials to log in
   - Cancel to exit the application

### Testing Authentication

Run the authentication test script:
```bash
python test_auth.py
```

This will allow you to test both registration and login functionality.

## Database Location

The user database is stored at:
- Windows: `C:\Users\[username]\.cybersentinel\users.db`
- Linux/Mac: `~/.cybersentinel/users.db`

## Security Features

1. **Password Hashing**: All passwords are hashed using SHA-256 with unique salts
2. **Input Validation**: Username, email, and password validation with real-time feedback
3. **Unique Constraints**: Usernames and emails must be unique
4. **Session Management**: Secure session handling with user state tracking

## UI Improvements

The authentication dialogs feature:
- Modern, clean design with proper spacing and alignment
- Real-time input validation with visual feedback
- Responsive layout that adapts to content
- Consistent styling with the main application
- Progress indicators for authentication operations

## File Structure

```
cybersentinel/
├── cybersentinel/
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── auth_manager.py    # Main authentication logic
│   │   ├── database.py        # Database operations
│   │   └── models.py          # User data model
│   └── gui/
│       └── auth_dialogs.py    # Authentication UI dialogs
├── main.py                    # Updated main application entry point
├── test_auth.py              # Authentication testing script
└── requirements.txt          # Dependencies
```

## Troubleshooting

### Database Issues
- If you encounter database errors, delete the `users.db` file to reset
- Check file permissions in the `.cybersentinel` directory

### UI Layout Issues
- Ensure PyQt5 is properly installed
- Check that all required modules are imported correctly

### Authentication Failures
- Verify username/email and password are correct
- Check the application logs for detailed error messages

## Future Enhancements

Planned improvements include:
- Password reset functionality
- Two-factor authentication
- User profile management
- Admin user management interface
- Session timeout and automatic logout
- Password strength requirements
- Account lockout after failed attempts
