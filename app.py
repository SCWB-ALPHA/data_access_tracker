# app.py — Data Access Tracker (clean final)

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    Response, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_, func
from datetime import datetime
from functools import wraps
import os, csv, io

# ------------------ App / Config ------------------
app = Flask(__name__)
app.config.from_pyfile('config.py')

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------ Models ------------------
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
    role = db.Column(db.String(50), default='data_entry', nullable=False)   # 'admin' or 'data_entry'
    department = db.Column(db.String(100), default='general', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Dataset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(255))   # under uploads/
    content = db.Column(db.Text)            # optional inline text

# ------------------ Login ------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ------------------ Helpers ------------------
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access that page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper

@app.context_processor
def nav_flags():
    return {'is_authenticated': current_user.is_authenticated,
            'is_admin': current_user.is_authenticated and current_user.role == 'admin'}

# ------------------ Core ------------------
@app.route('/')
def index():
    return render_template('index.html')

# ------------------ Auth ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        if not (username and email and password):
            flash('All fields are required.', 'danger'); return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger'); return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already in use.', 'danger'); return redirect(url_for('register'))
        u = User(username=username, email=email, role='data_entry', department='Data')
        u.set_password(password)
        db.session.add(u); db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.role=='admin' else 'user_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account is disabled.', 'warning'); return redirect(url_for('login'))
            login_user(user)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('admin_dashboard' if user.role=='admin' else 'user_dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash('Logged out.', 'info'); return redirect(url_for('index'))

# ------------------ Info pages ------------------
@app.route('/help')
def help_page(): return render_template('help.html')

@app.route('/accessibility_coming_soon')
def accessibility_coming_soon(): return render_template('accessibility_coming_soon.html')

@app.route('/learning_and_resources')
@login_required
def learning_and_resources(): return render_template('learning_and_resources.html')

# Back-compat aliases (old links)
@app.route('/log_data'); @login_required
def log_data(): flash("‘Log Data’ moved to ‘View Data’.", "info"); return redirect(url_for('view_data'))
@app.route('/log'); @login_required
def log(): flash("‘Log’ moved to ‘View Data’.", "info"); return redirect(url_for('view_data'))

# ------------------ View Data ------------------
@app.route('/view_data')
@login_required
def view_data():
    dataset_name = request.args.get('dataset_name')
    datasets = Dataset.query.order_by(Dataset.name.asc()).all()
    has_access = False; data_content = None; selected = None

    if dataset_name:
        selected = Dataset.query.filter_by(name=dataset_name).first()
        if not selected:
            flash(f"Dataset '{dataset_name}' does not exist.", 'danger')
            return redirect(url_for('view_data'))

        approved = AccessRequest.query.filter_by(
            user_id=current_user.id, dataset_name=dataset_name, status='approved'
        ).first()

        if approved or current_user.role == 'admin':
            if selected.file_path:
                path = os.path.join(app.config['UPLOAD_FOLDER'], selected.file_path)
                try:
                    with open(path, 'r', encoding='utf-8') as f: data_content = f.read()
                except FileNotFoundError:
                    err = f"File for '{dataset_name}' was not found on the server."
                    flash(err, 'danger'); data_content = err
                    return render_template('view_data.html', datasets=datasets, dataset_name=dataset_name,
                                           has_access=False, data_content=data_content, selected_dataset=selected)
            else:
                data_content = selected.content or '(No inline content)'
            db.session.add(AccessLog(username=current_user.username,
                                     dataset_name=dataset_name,
                                     purpose='Viewed dataset'))
            db.session.commit()
            has_access = True
            flash(f"Access to '{dataset_name}' granted and logged.", 'success')
        else:
            flash(f"No approved access for '{dataset_name}'. Submit a request.", 'warning')

    return render_template('view_data.html', datasets=datasets, dataset_name=dataset_name,
                           has_access=has_access, data_content=data_content, selected_dataset=selected)

@app.route('/download_dataset/<dataset_name>')
@login_required
def download_dataset(dataset_name):
    selected = Dataset.query.filter_by(name=dataset_name).first_or_404()
    approved = AccessRequest.query.filter_by(
        user_id=current_user.id, dataset_name=dataset_name, status='approved'
    ).first()
    if not approved and current_user.role != 'admin':
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('view_data', dataset_name=dataset_name))
    if selected.file_path:
        db.session.add(AccessLog(username=current_user.username,
                                 dataset_name=dataset_name, purpose='Downloaded dataset'))
        db.session.commit()
        return send_from_directory(app.config['UPLOAD_FOLDER'], selected.file_path, as_attachment=True)
    flash('This dataset does not have a downloadable file.', 'warning')
    return redirect(url_for('view_data', dataset_name=dataset_name))

# ------------------ Admin: history/export ------------------
def _filter_logs(query, start, end):
    logs_q = AccessLog.query
    if query:
        like = f"%{query}%"
        logs_q = logs_q.filter(or_(AccessLog.username.like(like),
                                   AccessLog.dataset_name.like(like),
                                   AccessLog.purpose.like(like)))
    if start or end:
        try:
            s = datetime.fromisoformat(start) if start else datetime.min
            e = datetime.fromisoformat(end).replace(hour=23, minute=59, second=59) if end else datetime.max
            logs_q = logs_q.filter(and_(AccessLog.timestamp >= s, AccessLog.timestamp <= e))
        except ValueError:
            flash('Invalid date format (use YYYY-MM-DD).', 'warning')
    return logs_q

@app.route('/history')
@login_required
@admin_required
def access_history():
    q = request.args.get('q','').strip()
    start = request.args.get('start','').strip()
    end = request.args.get('end','').strip()
    page = request.args.get('page', 1, type=int)
    logs = _filter_logs(q, start, end).order_by(AccessLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('access_history.html', logs=logs, query=q, start=start, end=end)

@app.route('/export_logs')
@login_required
@admin_required
def export_logs():
    q = request.args.get('q','').strip()
    start = request.args.get('start','').strip()
    end = request.args.get('end','').strip()
    logs = _filter_logs(q, start, end).order_by(AccessLog.timestamp.desc()).all()

    si = io.StringIO(); cw = csv.writer(si)
    cw.writerow(['ID','Username','Dataset','Purpose','Timestamp'])
    for l in logs: cw.writerow([l.id, l.username, l.dataset_name, l.purpose, l.timestamp.isoformat()])
    resp = Response(si.getvalue(), mimetype='text/csv')
    resp.headers['Content-Disposition'] = 'attachment; filename=access_logs.csv'
    return resp

# ------------------ Admin dashboard + user mgmt ------------------
@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.username.asc()).all()
    pending = AccessRequest.query.filter_by(status='pending').order_by(AccessRequest.request_date.desc()).all()
    logs_by_day = (db.session.query(func.date(AccessLog.timestamp), func.count(AccessLog.id))
                   .group_by(func.date(AccessLog.timestamp))
                   .order_by(func.date(AccessLog.timestamp).desc()).all())
    log_dates = [d.strftime('%Y-%m-%d') if hasattr(d,'strftime') else str(d) for d,_ in logs_by_day]
    log_counts = [c for _,c in logs_by_day]
    return render_template('admin_dashboard.html', users=users, pending_requests=pending,
                           log_dates=log_dates, log_counts=log_counts)

@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    u = User.query.get_or_404(user_id)
    action = request.form.get('action')
    if action == 'make_admin': u.role = 'admin'; db.session.commit(); flash(f"{u.username} is now admin.", 'success')
    elif action == 'make_user': u.role = 'data_entry'; db.session.commit(); flash(f"{u.username} is now user.", 'success')
    elif action == 'disable': u.is_active = False; db.session.commit(); flash(f"{u.username} disabled.", 'warning')
    elif action == 'enable': u.is_active = True; db.session.commit(); flash(f"{u.username} enabled.", 'success')
    elif action == 'delete': name = u.username; db.session.delete(u); db.session.commit(); flash(f"{name} deleted.", 'danger')
    else: flash('Invalid action.', 'danger')
    return redirect(url_for('admin_dashboard'))

# ------------------ User dashboard + requests ------------------
@app.route('/user_dashboard', methods=['GET','POST'])
@login_required
def user_dashboard():
    if request.method == 'POST':
        ds = request.form.get('dataset_name','').strip()
        purpose = request.form.get('purpose','').strip()
        if ds and purpose:
            db.session.add(AccessRequest(user_id=current_user.id, dataset_name=ds, purpose=purpose))
            db.session.commit()
            flash('Request submitted (pending).', 'success')
            return redirect(url_for('user_dashboard'))
        flash('Dataset and purpose are required.', 'danger')
    datasets = Dataset.query.order_by(Dataset.name.asc()).all()
    my_requests = (AccessRequest.query.filter_by(user_id=current_user.id)
                   .order_by(AccessRequest.request_date.desc()).all())
    return render_template('user_dashboard.html', datasets=datasets, my_requests=my_requests)

@app.route('/manage_request/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def manage_request(request_id):
    r = AccessRequest.query.get_or_404(request_id)
    action = request.form.get('action')
    if action == 'approve': r.status='approved'; flash('Request approved.', 'success')
    elif action == 'deny': r.status='denied'; flash('Request denied.', 'warning')
    else: flash('Invalid action.', 'danger'); return redirect(url_for('admin_dashboard'))
    db.session.commit(); return redirect(url_for('admin_dashboard'))

# ------------------ Errors ------------------
@app.errorhandler(404)
def not_found(e): return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e): return render_template('errors/500.html'), 500

# ------------------ Main ------------------
if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True)
