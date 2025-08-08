Data Access Tracker
An internal web application built with Flask for logging and tracking data access. This tool helps with data governance and accountability for audits by recording who accessed which dataset, when, and for what purpose.

Features
User Authentication: Secure user registration and login using Flask-Login and password hashing with werkzeug.security.

Role-Based Access Control (RBA): A foundation for managing user roles (admin, data_entry) and departments.

Data Access Logging: A form for authenticated users to log their access to specific datasets.

Access History View: A page to display all logged access entries.

Database Integration: Uses Flask-SQLAlchemy to manage a SQLite database for both user accounts and access logs.

Project Structure
├── app.py                     # Main application entry point
├── config.py                  # App configuration settings (e.g., SECRET_KEY)
├── requirements.txt           # All necessary Python packages
├── /templates/                # HTML files
│   ├── layout.html            # Base template with common layout
│   ├── index.html             # Home page
│   ├── login.html             # Login form
│   ├── register.html          # Registration form
│   ├── log_access.html        # Form to log access
│   └── access_history.html    # View of all access logs
├── /static/                   # CSS, JS, images
│   └── style.css              # Custom styles
└── site.db                    # SQLite database file (created on first run)

Setup and Running the Application
Prerequisites
Python 3.8+

Installation
Clone this repository or navigate to your project directory.

Create and activate a virtual environment:

macOS/Linux:

python3 -m venv venv
source venv/bin/activate

Windows (Command Prompt):

py -m venv venv
venv\Scripts\activate.bat

Windows (PowerShell):

py -m venv venv
.\venv\Scripts\Activate.ps1

Install the required Python packages:

pip install Flask Flask-SQLAlchemy Werkzeug Flask-Login Flask-Bootstrap5

Create a config.py file in your root directory.

import os

SECRET_KEY = os.urandom(24)
SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

Running the Application
Ensure your virtual environment is active.

Run the Flask application:

python app.py

Open your web browser and go to http://127.0.0.1:5000/.

A default admin user with the password adminpassword is created on the first run. It is highly recommended to change this in a production environment.

Next Steps
Implement full Role-Based Access Control.

Add a user management page for administrators.

Filter and search access history by user, dataset, and date range.

Re-enable CSRF protection properly on all forms.
