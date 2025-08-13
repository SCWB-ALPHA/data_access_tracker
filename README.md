# Data Access Tracker

A Flask web app to **log, track, and audit** data access events. It supports user accounts, role-based access (Admin/User), and an auditable access history with filters and CSV export.

## Features
- **User Authentication** (login/register) and **RBAC** (Admin vs User)
- **Access Logging:** dataset, purpose, timestamp stored per event
- **User Dashboard:** personal access history
- **Admin Dashboard:** global access history, filters by user/date, CSV export
- (Optional) **Password reset via email** — enable after configuring mail

## Tech
Flask, SQLAlchemy (SQLite), Bootstrap/Font Awesome, Chart.js (admin metrics)

## Project Structure
