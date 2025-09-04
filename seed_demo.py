# seed_demo.py
from app import app, db, User, Dataset, AccessRequest, AccessLog
from datetime import datetime, timedelta

with app.app_context():
    db.create_all()

    # Admin + user
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@example.com', role='admin', department='Governance')
        admin.set_password('admin123')
        db.session.add(admin)

    alex = User.query.filter_by(username='alex').first()
    if not alex:
        alex = User(username='alex', email='alex@example.com', role='data_entry', department='Finance')
        alex.set_password('alex123')
        db.session.add(alex)

    # Datasets (inline content for easy demo)
    sales = Dataset.query.filter_by(name='Sales_Q2').first()
    if not sales:
        sales = Dataset(name='Sales_Q2', description='Quarter 2 summary KPIs',
                        content='Region,Revenue\nNA,120000\nEU,98000\nCaribbean,35000\n')
        db.session.add(sales)

    hr = Dataset.query.filter_by(name='HR_Headcount').first()
    if not hr:
        hr = Dataset(name='HR_Headcount', description='Monthly headcount by department',
                     content='Dept,Headcount\nFinance,12\nIT,9\nOps,20\n')
        db.session.add(hr)

    # Approved request for alex on Sales_Q2
    req = AccessRequest.query.filter_by(user_id=alex.id, dataset_name='Sales_Q2').first()
    if not req:
        req = AccessRequest(user_id=alex.id, dataset_name='Sales_Q2',
                            purpose='Quarterly KPI roll-up',
                            status='approved')
        db.session.add(req)

    # Some logs for history (last few days)
    if not AccessLog.query.first():
        base = datetime.utcnow()
        logs = [
            AccessLog(username='admin', dataset_name='Sales_Q2', purpose='Testing audit trail', timestamp=base - timedelta(days=3)),
            AccessLog(username='alex', dataset_name='Sales_Q2', purpose='Quarterly KPI roll-up', timestamp=base - timedelta(days=2)),
            AccessLog(username='admin', dataset_name='HR_Headcount', purpose='Check headcount trend', timestamp=base - timedelta(days=1)),
        ]
        db.session.add_all(logs)

    db.session.commit()
    print("✅ Demo data seeded: users (admin/admin123, alex/alex123), datasets, requests, logs.")
