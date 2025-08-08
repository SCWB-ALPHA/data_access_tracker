# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, Response, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import uuid
from functools import wraps
from flask_bootstrap import Bootstrap5
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from sqlalchemy import func
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from sqlalchemy.inspection import inspect
import csv
import io

# --- Load environment variables at the start of the app ---
load_dotenv()

# --- App Setup ---
app = Flask(__name__)
app.config.from_pyfile('config.py')

# Ensure the upload folder exists
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
bootstrap = Bootstrap5(app)

# --- Flask-Mail Setup ---
mail = Mail(app)

# --- Token Serializer Setup ---
token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Custom Decorator for Admin-Only Access ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Models ---
class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    dataset_name = db.Column(db.String(120), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dataset_name = db.Column(db.String(120), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending', nullable=False)

    user = db.relationship('User', backref='access_requests')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), default='data_entry', nullable=False)
    department = db.Column(db.String(100), default='general', nullable=False)
    password_reset_token = db.Column(db.String(128), unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Dataset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    content = db.Column(db.Text, nullable=True)

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        user_by_username = User.query.filter_by(username=username).first()
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_username:
            flash('Username already exists!', 'danger')
        elif user_by_email:
            flash('Email address already in use!', 'danger')
        else:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            new_user.role = 'data_entry'
            new_user.department = 'Data Entry'
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Both username and password are required.', 'danger')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been disabled. Please contact an administrator.', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            flash(f'Welcome, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = token_serializer.dumps(user.email, salt='password-reset-salt')
            msg = Message("Password Reset Request", recipients=[user.email])
            msg.body = render_template('email/reset_password.txt', user=user, token=token)
            msg.html = render_template('email/reset_password.html', user=user, token=token)
            mail.send(msg)
        flash('If an account with that email exists, a password reset email has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    try:
        email = token_serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('That is an invalid password reset token.', 'danger')
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('That is an invalid password reset token.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if not new_password:
            flash('New password is required.', 'danger')
            return redirect(url_for('reset_password', token=token))
        user.set_password(new_password)
        db.session.commit()
        flash('Your password has been reset successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/accessibility_coming_soon')
def accessibility_coming_soon():
    return render_template('accessibility_coming_soon.html')
    
@app.route('/learning_and_resources')
@login_required
def learning_and_resources():
    return render_template('learning_and_resources.html')

@app.route('/export_logs')
@login_required
@admin_required
def export_logs():
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Username', 'Dataset Name', 'Purpose', 'Timestamp'])
    for log in logs:
        cw.writerow([log.id, log.username, log.dataset_name, log.purpose, log.timestamp.isoformat()])
    output = si.getvalue()
    response = Response(output, mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=access_logs.csv'
    return response

@app.route('/log', methods=['GET', 'POST'])
@login_required
def log_access():
    # This route is now a placeholder and redirects to the view_data page
    return redirect(url_for('view_data'))

@app.route('/view_data', methods=['GET', 'POST'])
@login_required
def view_data():
    dataset_name = request.args.get('dataset_name')
    datasets = Dataset.query.all()
    has_access = False
    data_content = None
    selected_dataset = None

    if dataset_name:
        selected_dataset = Dataset.query.filter_by(name=dataset_name).first()
        if not selected_dataset:
            flash(f"The dataset '{dataset_name}' does not exist.", 'danger')
            return redirect(url_for('view_data'))
        
        approved_request = AccessRequest.query.filter_by(
            user_id=current_user.id,
            dataset_name=dataset_name,
            status='approved'
        ).first()

        if approved_request or current_user.role == 'admin':
            has_access = True
            
            new_log = AccessLog(
                username=current_user.username,
                dataset_name=dataset_name,
                purpose='Viewing data after approved request'
            )
            db.session.add(new_log)
            db.session.commit()

            if selected_dataset.file_path:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], selected_dataset.file_path)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data_content = f.read()
                except FileNotFoundError:
                    data_content = f"Error: The file for '{dataset_name}' was not found on the server."
                    flash(data_content, 'danger')
            else:
                data_content = selected_dataset.content
                
            flash(f"Access to '{dataset_name}' granted and logged successfully.", 'success')
        else:
            flash(f"You do not have approved access to '{dataset_name}'. Please submit a request.", 'warning')

    return render_template('view_data.html', datasets=datasets, dataset_name=dataset_name, has_access=has_access, data_content=data_content, selected_dataset=selected_dataset)

@app.route('/download_dataset/<dataset_name>')
@login_required
def download_dataset(dataset_name):
    selected_dataset = Dataset.query.filter_by(name=dataset_name).first_or_404()

    # Check for an approved access request
    approved_request = AccessRequest.query.filter_by(
        user_id=current_user.id,
        dataset_name=dataset_name,
        status='approved'
    ).first()

    # Admins can also download files
    if not approved_request and current_user.role != 'admin':
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('view_data', dataset_name=dataset_name))

    if selected_dataset.file_path:
        # Log the download action
        new_log = AccessLog(
            username=current_user.username,
            dataset_name=dataset_name,
            purpose='Downloaded dataset file'
        )
        db.session.add(new_log)
        db.session.commit()
        
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            selected_dataset.file_path,
            as_attachment=True
        )
    else:
        flash('This dataset does not have a downloadable file.', 'warning')
        return redirect(url_for('view_data', dataset_name=dataset_name))

@app.route('/history')
@login_required
@admin_required
def access_history():
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    logs_query = AccessLog.query.order_by(AccessLog.timestamp.desc())
    if query:
        search_term = f"%{query}%"
        logs_query = logs_query.filter(
            db.or_(
                AccessLog.username.like(search_term),
                AccessLog.dataset_name.like(search_term),
                AccessLog.purpose.like(search_term)
            )
        )
    logs = logs_query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('access_history.html', logs=logs, query=query)

@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    role_filter = request.args.get('role')
    dept_filter = request.args.get('department')
    search_query = request.args.get('q', '').strip()
    users_query = User.query.order_by(User.username)
    if role_filter:
        users_query = users_query.filter_by(role=role_filter)
    if dept_filter:
        users_query = users_query.filter_by(department=dept_filter)
    if search_query:
        search_term = f"%{search_query}%"
        users_query = users_query.filter(
            db.or_(
                User.username.like(search_term),
                User.email.like(search_term)
            )
        )
    users = users_query.all()
    total_users = User.query.count()
    total_logs = AccessLog.query.count()
    users_by_dept = db.session.query(User.department, func.count(User.id)).group_by(User.department).all()
    dept_labels = [row[0] for row in users_by_dept]
    dept_counts = [row[1] for row in users_by_dept]
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    logs_by_day = db.session.query(
        func.date(AccessLog.timestamp),
        func.count(AccessLog.id)
    ).filter(
        AccessLog.timestamp > seven_days_ago
    ).group_by(
        func.date(AccessLog.timestamp)
    ).order_by(
        func.date(AccessLog.timestamp)
    ).all()
    log_dates = [row[0].strftime('%Y-%m-%d') for row in logs_by_day]
    log_counts = [row[1] for row in logs_by_day]
    pending_requests_count = AccessRequest.query.filter_by(status='pending').count()
    roles = db.session.query(User.role.distinct()).all()
    departments = db.session.query(User.department.distinct()).all()
    return render_template('admin_dashboard.html', 
                           users=users, 
                           roles=[r[0] for r in roles], 
                           departments=[d[0] for d in departments],
                           selected_role=role_filter,
                           selected_dept=dept_filter,
                           search_query=search_query,
                           total_users=total_users,
                           total_logs=total_logs,
                           dept_labels=dept_labels,
                           dept_counts=dept_counts,
                           log_dates=log_dates,
                           log_counts=log_counts,
                           pending_requests_count=pending_requests_count
                           )

# --- New Route for User Dashboard ---
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    # Only regular users should see this. Admins have their own dashboard.
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    # Fetch all access requests for the current user
    user_requests = AccessRequest.query.filter_by(user_id=current_user.id).order_by(AccessRequest.request_date.desc()).all()
    
    # Fetch all access logs for the current user
    user_logs = AccessLog.query.filter_by(username=current_user.username).order_by(AccessLog.timestamp.desc()).all()

    return render_template('user_dashboard.html', user_requests=user_requests, user_logs=user_logs)

@app.route('/request_access', methods=['GET', 'POST'])
@login_required
def request_access():
    if request.method == 'POST':
        dataset_name = request.form.get('dataset_name')
        purpose = request.form.get('purpose')
        if not dataset_name or not purpose:
            flash('Dataset Name and Purpose are required!', 'danger')
            return redirect(url_for('request_access'))
        existing_request = AccessRequest.query.filter_by(
            user_id=current_user.id,
            dataset_name=dataset_name,
            status='pending'
        ).first()
        if existing_request:
            flash('You already have a pending request for this dataset. Please wait for an administrator to review it.', 'warning')
            return redirect(url_for('request_access'))
        new_request = AccessRequest(
            user_id=current_user.id,
            dataset_name=dataset_name,
            purpose=purpose,
            status='pending'
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Your access request has been submitted and is pending administrator approval.', 'success')
        return redirect(url_for('index'))
    datasets = Dataset.query.all()
    return render_template('request_access.html', datasets=datasets)

@app.route('/manage_requests')
@login_required
@admin_required
def manage_requests():
    pending_requests = AccessRequest.query.filter_by(status='pending').order_by(AccessRequest.request_date.desc()).all()
    return render_template('manage_requests.html', pending_requests=pending_requests)

@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_request(request_id):
    request_to_approve = AccessRequest.query.get_or_404(request_id)
    request_to_approve.status = 'approved'
    db.session.commit()
    new_log = AccessLog(
        username=request_to_approve.user.username,
        dataset_name=request_to_approve.dataset_name,
        purpose=request_to_approve.purpose
    )
    db.session.add(new_log)
    db.session.commit()
    flash(f'Request for "{request_to_approve.dataset_name}" by {request_to_approve.user.username} approved and logged successfully.', 'success')
    return redirect(url_for('manage_requests'))

@app.route('/deny_request/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def deny_request(request_id):
    request_to_deny = AccessRequest.query.get_or_404(request_id)
    request_to_deny.status = 'denied'
    db.session.commit()
    flash(f'Request for "{request_to_deny.dataset_name}" by {request_to_deny.user.username} denied.', 'warning')
    return redirect(url_for('manage_requests'))

@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    user.role = request.form.get('role')
    user.department = request.form.get('department')
    db.session.commit()
    flash(f'User "{user.username}" updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('admin_dashboard'))
    AccessLog.query.filter_by(username=user.username).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" and associated logs deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot disable your own account.', 'warning')
    else:
        user.is_active = not user.is_active
        db.session.commit()
        status = 'enabled' if user.is_active else 'disabled'
        flash(f'Account for user "{user.username}" has been {status}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_reset_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = 'Password123!'
    user.set_password(new_password)
    db.session.commit()
    flash(f'Password for user "{user.username}" has been reset to a temporary password. Please advise them to change it immediately.', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/manage_datasets')
@login_required
@admin_required
def manage_datasets():
    datasets = Dataset.query.all()
    return render_template('manage_datasets.html', datasets=datasets)

@app.route('/upload_dataset', methods=['GET', 'POST'])
@login_required
@admin_required
def upload_dataset():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file:
            dataset_name = request.form.get('name')
            description = request.form.get('description')
            existing_dataset = Dataset.query.filter_by(name=dataset_name).first()
            if existing_dataset:
                flash(f'A dataset with the name "{dataset_name}" already exists. Please use a different name.', 'danger')
                return redirect(request.url)
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_dataset = Dataset(
                name=dataset_name,
                description=description,
                file_path=filename
            )
            db.session.add(new_dataset)
            db.session.commit()
            flash(f'Dataset "{dataset_name}" uploaded and saved successfully!', 'success')
            return redirect(url_for('manage_datasets'))
    return render_template('upload_dataset.html')

@app.route('/api/datasets')
@login_required
def get_datasets_api():
    """API endpoint to return a list of all dataset names."""
    datasets = Dataset.query.with_entities(Dataset.name).all()
    dataset_names = [dataset.name for dataset in datasets]
    return jsonify(dataset_names)

if __name__ == '__main__':
    with app.app_context():
        inspector = inspect(db.engine)
        db.create_all()
        user_columns = [c['name'] for c in inspector.get_columns('user')]
        if 'is_active' not in user_columns:
            with db.engine.connect() as connection:
                connection.execute(db.text('ALTER TABLE user ADD COLUMN is_active BOOLEAN'))
            print("Added 'is_active' column to the user table.")
        dataset_columns = [c['name'] for c in inspector.get_columns('dataset')]
        if 'file_path' not in dataset_columns:
            with db.engine.connect() as connection:
                connection.execute(db.text('ALTER TABLE dataset ADD COLUMN file_path VARCHAR(255)'))
            print("Added 'file_path' column to the dataset table.")
        if not User.query.filter_by(username='admin').first():
            admin_password = os.environ.get('ADMIN_PASSWORD') or 'adminpassword'
            admin_user = User(username='admin', role='admin', department='Administration', email='admin@example.com')
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print("Default 'admin' user created. Please change the password!")
        if not Dataset.query.first():
            print("Populating 'dataset' table with sample data...")
            sample_data = [
                Dataset(name='Q1_Sales_Data', description='Quarter 1 sales figures and analysis.', content='**Q1 Sales Data:**\n- Total Revenue: $500,000\n- Units Sold: 2,500\n- Top Selling Product: Product A'),
                Dataset(name='HR_Employee_Info', description='Confidential employee information for human resources.', content='**HR Employee Info:**\n- Employee ID: 12345\n- Name: John Doe\n- Department: Sales\n- Salary: $60,000'),
                Dataset(name='Marketing_Campaign_Results', description='Performance metrics for the latest marketing campaign.', content='**Marketing Campaign Results:**\n- Campaign Name: Spring 2023 Launch\n- Impressions: 1,200,000\n- Click-through Rate: 1.5%')
            ]
            db.session.bulk_save_objects(sample_data)
            db.session.commit()
        app.run(debug=True)
