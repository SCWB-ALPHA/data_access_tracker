import os

# Configuration for Flask
SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-that-you-should-change'

# Configuration for Flask-SQLAlchemy
# Change the database filename to bypass the persistent file lock
SQLALCHEMY_DATABASE_URI = 'sqlite:///new_data_access_tracker.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False