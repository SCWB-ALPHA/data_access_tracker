# create_admin.py — one-shot admin & demo user
from app import app, db, User
with app.app_context():
    db.create_all()
    def upsert(u, e, p, r):
        x = User.query.filter_by(username=u).first()
        if not x:
            x = User(username=u, email=e, role=r, department='Governance' if r=='admin' else 'Data')
            x.set_password(p); db.session.add(x); db.session.commit()
            print(f"✅ created {u}/{p} ({r})")
        else:
            x.role = r; x.set_password(p); db.session.commit()
            print(f"♻️ reset {u}/{p} ({r})")
    upsert('admin','admin@example.com','admin123','admin')
    upsert('alex','alex@example.com','alex123','data_entry')
    print("DB:", app.config['SQLALCHEMY_DATABASE_URI'])
