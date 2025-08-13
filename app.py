from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    Response, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os, csv, io
from functools import wraps

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from sqlalchemy import or_, and_, func

# ------------------------------
# App & Config
# ------------------------------
app = Flask(__name__)
app.config.from_pyfile('config.py')

# uploads/
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# extensions
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ------------------------------
# Helpers / Guards
# ------------------------------
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


# ------------------------------
# Models
# ------------------------------
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
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending/approved/denied
    user = db.relationship('User', backref='access_requests')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), default='data_entry', nullable=False)
    department = db.Column(db.String(100), default='general', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Dataset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(255))   # relative path under uploads/
    content = db.Column(db.Text)            # inline text content (optional)


# ------------------------------
# Flask-Login
# ------------------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ------------------------------
# Template context (navbar flags)
# ------------------------------
@app.context_processor
def inject_nav_flags():
    return {
        'is_authenticated': current_user.is_authenticated,
        'is_admin': (current_user.is_authenticated and current_user.role == 'admin')
    }


# ------------------------------
# Routes: Core
# ------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# ---- Auth ----
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email address already in use!', 'danger')
        else:
            u = User(username=username, email=email, role='data_entry', department='Data Entry')
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.role == 'admin' else 'user_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
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
            return redirect(next_page or url_for('admin_dashboard' if user.role == 'admin' else 'user_dashboard'))

        flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# ------------------------------
# Static information pages (linked in base)
# ------------------------------
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


# ------------------------------
# Datasets / Viewing
# ------------------------------
@app.route('/view_data', methods=['GET'])
@login_required
def view_data():
    """
    View datasets; when a dataset is selected and the user has access,
    log the event and show content. Success is flashed only after success.
    """
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

        # check access (approved or admin)
        approved_request = AccessRequest.query.filter_by(
            user_id=current_user.id,
            dataset_name=dataset_name,
            status='approved'
        ).first()

        if approved_request or current_user.role == 'admin':
            # Try reading first; only log + flash on success
            if selected_dataset.file_path:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], selected_dataset.file_path)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data_content = f.read()
                except FileNotFoundError:
                    err = f"Error: The file for '{dataset_name}' was not found on the server."
                    flash(err, 'danger')
                    data_content = err
                    return render_template('view_data.html',
                                           datasets=datasets, dataset_name=dataset_name,
                                           has_access=False, data_content=data_content,
                                           selected_dataset=selected_dataset)
            else:
                data_content = selected_dataset.content or '(No inline content)'

            # success → log it
            new_log = AccessLog(
                username=current_user.username,
                dataset_name=dataset_name,
                purpose='Viewing data after approved request'
            )
            db.session.add(new_log)
            db.session.commit()
            has_access = True
            flash(f"Access to '{dataset_name}' granted and logged successfully.", 'success')
        else:
            flash(f"You do not have approved access to '{dataset_name}'. Please submit a request.", 'warning')

    return render_template('view_data.html',
                           datasets=datasets, dataset_name=dataset_name,
                           has_access=has_access, data_content=data_content,
                           selected_dataset=selected_dataset)


@app.route('/download_dataset/<dataset_name>')
@login_required
def download_dataset(dataset_name):
    selected_dataset = Dataset.query.filter_by(name=dataset_name).first_or_404()

    approved_request = AccessRequest.query.filter_by(
        user_id=current_user.id,
        dataset_name=dataset_name,
        status='approved'
    ).first()

    if not approved_request and current_user.role != 'admin':
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('view_data', dataset_name=dataset_name))

    if selected_dataset.file_path:
        new_log = AccessLog(
            username=current_user.username,
            dataset_name=dataset_name,
            purpose='Downloaded dataset file'
        )
        db.session.add(new_log)
        db.session.commit()

        return send_from_directory(app.config['UPLOAD_FOLDER'],
                                   selected_dataset.file_path,
                                   as_attachment=True)
    else:
        flash('This dataset does not have a downloadable file.', 'warning')
        return redirect(url_for('view_data', dataset_name=dataset_name))


# ------------------------------
# Logs / History / Export
# ------------------------------
@app.route('/history')
@login_required
@admin_required
def access_history():
    """
    Admin: searchable + filterable access log history.
    Query params: q (text), start, end (YYYY-MM-DD), page
    """
    query = request.args.get('q', '').strip()
    start = request.args.get('start', '').strip()
    end = request.args.get('end', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 20

    logs_query = AccessLog.query

    if query:
        like = f"%{query}%"
        logs_query = logs_query.filter(
            or_(AccessLog.username.like(like),
                AccessLog.dataset_name.like(like),
                AccessLog.purpose.like(like))
        )

    # date range filter
    if start or end:
        try:
            start_dt = datetime.fromisoformat(start) if start else datetime.min
            end_dt = (datetime.fromisoformat(end).replace(hour=23, minute=59, second=59)
                      if end else datetime.max)
            logs_query = logs_query.filter(and_(AccessLog.timestamp >= start_dt,
                                                AccessLog.timestamp <= end_dt))
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD.', 'warning')

    logs = logs_query.order_by(AccessLog.timestamp.desc()).paginate(page=page, per_page=per_page)
    return render_template('access_history.html', logs=logs, query=query, start=start, end=end)


@app.route('/export_logs')
@login_required
@admin_required
def export_logs():
    """
    CSV export for (optionally) filtered logs.
    Accepts same params as /history: q, start, end
    """
    query = request.args.get('q', '').strip()
    start = request.args.get('start', '').strip()
    end = request.args.get('end', '').strip()

    logs_query = AccessLog.query

    if query:
        like = f"%{query}%"
        logs_query = logs_query.filter(
            or_(AccessLog.username.like(like),
                AccessLog.dataset_name.like(like),
                AccessLog.purpose.like(like))
        )

    if start or end:
        try:
            start_dt = datetime.fromisoformat(start) if start else datetime.min
            end_dt = (datetime.fromisoformat(end).replace(hour=23, minute=59, second=59)
                      if end else datetime.max)
            logs_query = logs_query.filter(and_(AccessLog.timestamp >= start_dt,
                                                AccessLog.timestamp <= end_dt))
        except ValueError:
            pass  # ignore bad dates; export unfiltered

    logs = logs_query.order_by(AccessLog.timestamp.desc()).all()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Username', 'Dataset Name', 'Purpose', 'Timestamp'])
    for log in logs:
        cw.writerow([log.id, log.username, log.dataset_name, log.purpose, log.timestamp.isoformat()])

    output = si.getvalue()
    resp = Response(output, mimetype='text/csv')
    resp.headers['Content-Disposition'] = 'attachment; filename=access_logs.csv'
    return resp


# ------------------------------
# Dashboards & Requests
# ------------------------------
@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    pending_requests = AccessRequest.query.filter_by(status='pending').all()

    # Simple counts by day for optional charting
    logs_by_day = (
        db.session.query(func.date(AccessLog.timestamp), func.count(AccessLog.id))
        .group_by(func.date(AccessLog.timestamp))
        .order_by(func.date(AccessLog.timestamp).desc())
        .all()
    )
    log_dates = [d.strftime('%Y-%m-%d') if hasattr(d, 'strftime') else str(d) for d, _ in logs_by_day]
    log_counts = [c for _, c in logs_by_day]

    return render_template(
        'admin_dashboard.html',
        users=users,
        pending_requests=pending_requests,
        log_dates=log_dates,
        log_counts=log_counts
    )


@app.route('/user_dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    if request.method == 'POST':
        dataset_name = request.form.get('dataset_name', '').strip()
        purpose = request.form.get('purpose', '').strip()
        if dataset_name and purpose:
            new_request = AccessRequest(user_id=current_user.id,
                                        dataset_name=dataset_name,
                                        purpose=purpose)
            db.session.add(new_request)
            db.session.commit()
            flash('Access request submitted successfully! It is now pending review.', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Dataset and purpose are required to submit a request.', 'danger')

    datasets = Dataset.query.all()
    my_requests = (AccessRequest.query
                   .filter_by(user_id=current_user.id)
                   .order_by(AccessRequest.request_date.desc())
                   .all())
    return render_template('user_dashboard.html', datasets=datasets, my_requests=my_requests)


# ------------------------------
# Errors (optional)
# ------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500


# ------------------------------
# Entrypoint
# ------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
