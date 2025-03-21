"""
FLEET MANAGEMENT SYSTEM - ENTERPRISE EDITION
PERFECTION-OPTIMIZED VERSION
"""

import os
import json
import logging
import pytz
from datetime import datetime, timedelta, timezone
from functools import wraps
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from bson import ObjectId
from flask import Flask, get_flashed_messages, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity,
    jwt_required, set_access_cookies, unset_jwt_cookies
)
from pymongo import MongoClient
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from prometheus_flask_exporter import PrometheusMetrics

# --- Environment Initialization ---
load_dotenv()

# --- Flask Application Factory ---
app = Flask(__name__)

# Add str to Jinja2 globals
app.jinja_env.globals.update(str=str)

# Enable CSRF protection
csrf = CSRFProtect(app)

# ==================================================================
#                          CONFIGURATION
# ==================================================================
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "super-secret-flask-key"),
    MONGO_URI=os.getenv("MONGO_URI"),
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "super-secret-key"),
    JWT_TOKEN_LOCATION=["cookies"],
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
    JWT_COOKIE_CSRF_PROTECT=False,
)

# --- Infrastructure Setup ---
metrics = PrometheusMetrics(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",  # Use in-memory storage
    default_limits=["200 per day", "50 per hour"]
)

# --- Database Initialization ---
client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=30000)
db = client["taxinovak_db"]  # EXPLICITLY TARGET YOUR DATABASE

# --- JWT Manager ---
jwt = JWTManager(app)

# ==================================================================
#                          LOGGING (TERMINAL WARRIOR EDITION)
# ==================================================================
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module
        }
        return json.dumps(log_record)

logging_handler = RotatingFileHandler('app.log', maxBytes=10*1024*1024, backupCount=5)
logging_handler.setFormatter(JSONFormatter())

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging_handler)
logger.addHandler(logging.StreamHandler())

# ==================================================================
#                          ERROR HANDLING
# ==================================================================
@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Error: {str(error)}")
    return render_template('errors/500.html'), 500

@app.errorhandler(429)
def too_many_requests(error):
    return render_template('errors/429.html'), 429

# ==================================================================
#                          DATABASE VALIDATION
# ==================================================================
def verify_db_connection():
    """Brutally verify database connection and collections."""
    try:
        client.admin.command('ping')
        logger.info("🔥 Database connection: ACTIVE")

        required_collections = ["users", "entries"]
        existing_collections = db.list_collection_names()
        missing_collections = [col for col in required_collections if col not in existing_collections]

        if missing_collections:
            logger.critical(f"💥 Missing collections: {missing_collections}")
            return False

        logger.info("✅ All required collections exist")
        return True

    except Exception as e:
        logger.critical(f"💀 Database connection FAILED: {str(e)}")
        return False

# Initialize database connection and validate on startup
if not verify_db_connection():
    logger.critical("💥 FAILED TO LAUNCH: Database validation failed")
    exit(1)

# ==================================================================
#                          ACCESS CONTROL
# ==================================================================
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = json.loads(get_jwt_identity())
        if current_user.get('role') != 'admin':
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def manager_check(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = json.loads(get_jwt_identity())
        if current_user['role'] not in ['admin', 'manager_all', 'manager_group']:
            abort(403)  # Only admins and managers can access this route

        # For group managers, ensure they can only manage their own group
        if current_user['role'] == 'manager_group':
            entry_id = kwargs.get('entry_id')
            if entry_id:
                entry = db.entries.find_one({"_id": ObjectId(entry_id)})
                if entry and entry.get('group') != current_user.get('group'):
                    abort(403)  # Group managers can only manage entries in their own group

        return fn(*args, **kwargs)
    return wrapper

# ==================================================================
#                          ROUTES AND CORE FUNCTIONALITY
# ==================================================================
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("2000/minute")
def login():
    if request.method == 'GET':
        flash_messages = get_flashed_messages()
        if flash_messages:
            for _ in flash_messages:
                pass  # Clear all messages
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Missing credentials", "error")
            return render_template('login.html', login_failed=True)

        logger.info(f"⚔️ Attempting login for user: {username}")
        
        try:
            # Ping the database to ensure it's connected
            client.admin.command('ping')
            logger.info("🔥 DATABASE CONNECTION: ACTIVE")

            # Find the user in the database
            user = db.users.find_one({"username": username})
            if user:
                logger.info(f"🎯 User found: {user['username']}")
                # Check the password
                if bcrypt.checkpw(password.encode(), user['password_hash']):  # Fixed here
                    identity = {
                        "user_id": str(user["_id"]),
                        "username": user["username"],
                        "role": user["role"],
                        "group": user.get("group")
                    }
                    access_token = create_access_token(identity=json.dumps(identity))
                    response = redirect(url_for('dashboard'))
                    set_access_cookies(response, access_token)
                    return response
                else:
                    logger.error("💥 Invalid password")
                    flash("Invalid credentials", "error")
                    return render_template('login.html', login_failed=True)
            else:
                logger.error("💥 User not found")
                flash("Invalid credentials", "error")
                return render_template('login.html', login_failed=True)
        except Exception as e:
            logger.error(f"💣 Login failed: {str(e)}")
            flash("System error", "error")
            return render_template('login.html', login_failed=True)

    return render_template('login.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = json.loads(get_jwt_identity())
    print("Current User:", current_user)  # Debugging
    user_role = current_user['role']
    query = {}

    # Redirect admins to the admin panel
    if current_user['role'] == 'admin':
        return redirect(url_for('admin_users'))  # Or any other admin route

    # Get the selected week from the query parameters
    week = request.args.get('week', default=0, type=int)
    today = datetime.now() + timedelta(weeks=week)
    start_of_week = today - timedelta(days=today.weekday())  # Monday
    end_of_week = start_of_week + timedelta(days=6)  # Sunday
    week_dates = [(start_of_week + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]

    # Fetch entries for the selected week
    query.update({
        "$or": [
            # Entries that overlap with the selected week
            {
                "date_from": {"$lte": end_of_week},  # Entries starting before or on Sunday
                "date_to": {"$gte": start_of_week}   # Entries ending after or on Monday
            },
            # Entries that are entirely within the selected week
            {
                "date_from": {"$gte": start_of_week},  # Entries starting on or after Monday
                "date_to": {"$lte": end_of_week}      # Entries ending on or before Sunday
            }
        ]
    })

    # Fetch entries and expand them into daily records
    entries = []
    raw_entries = db.entries.find(query).sort('date_from', -1)
    for entry in raw_entries:
        entry_date = entry['date_from']
        while entry_date <= entry['date_to']:
            if entry_date.strftime("%Y-%m-%d") in week_dates:
                entries.append({
                    "user_id": str(entry['user_id']), 
                    "date": entry_date.strftime("%Y-%m-%d"),
                    "type": entry['type'],
                    "time_from": entry.get('time_from'),
                    "time_to": entry.get('time_to'),
                    "_id_str": str(entry['_id'])  
                })
            entry_date += timedelta(days=1)

    # Fetch all drivers, managers, Werner, and Heinz
    drivers = list(db.users.find({"role": {"$in": ["driver", "Werner", "Heinz", "manager_group", "manager_all"]}}))

    # Convert MongoDB ObjectIds to strings
    processed_drivers = []
    for driver in drivers:
        driver['_id_str'] = str(driver['_id'])  # Add string version
        processed_drivers.append(driver)

    # Group drivers by their group and sort group_manager first
    grouped_drivers = {}
    for driver in processed_drivers:
        group = driver.get("group", "Ungrouped")  # Default to "Ungrouped" if group is None
        if group not in grouped_drivers:
            grouped_drivers[group] = []
        
        # Insert managers at the top of their group
        if driver["role"] in ["manager_all", "manager_group"]:  # Include both manager types
            grouped_drivers[group].insert(0, driver)
        else:
            grouped_drivers[group].append(driver)

    # Sort the groups in ascending order, ensuring no None values
    grouped_drivers = dict(sorted(grouped_drivers.items(), key=lambda x: x[0] or "Ungrouped"))

    return render_template(
        'dashboard.html',
        entries=entries,
        current_user=current_user,
        grouped_drivers=grouped_drivers,
        processed_drivers=processed_drivers,
        current_week=[{"day": (start_of_week + timedelta(days=i)).strftime("%A"), 
                      "date": (start_of_week + timedelta(days=i)).strftime("%Y-%m-%d")} 
                     for i in range(7)],
        week=week, username=current_user.get("username", "Guest"), user_role=user_role
    )

@app.route('/entries/create', methods=['POST'])
@jwt_required()
@manager_check  # Keep the decorator for role validation
@limiter.limit("20000/minute")
def create_entry():
    current_user = json.loads(get_jwt_identity())
    week = request.form.get('week', default=0, type=int)
    if current_user['role'] == 'driver':
        abort(403)
        
    try:
        # Ensure the manager is creating an entry in their own group
        if current_user['role'] == 'manager_group':
            user_id = request.form['user_id']
            user = db.users.find_one({"_id": ObjectId(user_id)})
            if user and user.get('group') != current_user.get('group'):
                abort(403)  # Group managers can only create entries for users in their own group

        entry_data = {
            "user_id": ObjectId(request.form['user_id']),
            "date_from": datetime.strptime(request.form['date_from'], "%Y-%m-%d").replace(hour=0, minute=0, second=0),
            "date_to": datetime.strptime(request.form['date_to'], "%Y-%m-%d").replace(hour=23, minute=59, second=59),
            "type": request.form['type'],
            "group": current_user.get('group'),  # Ensure the entry is assigned to the manager's group
            "created_at": datetime.now(timezone.utc)
        }
        
        if entry_data['type'] == 'Arbeit':
            entry_data.update({
                "time_from": request.form['time_from'],
                "time_to": request.form['time_to']
            })
        
        db.entries.insert_one(entry_data)
        flash("Entry created", "success")
    except Exception as e:
        logger.error(f"💣 Entry creation failed: {str(e)}")
        flash("Operation failed", "error")
        
    return redirect(url_for('dashboard', week=week))


@app.route('/entries/edit/<entry_id>', methods=['GET', 'POST'])
@jwt_required()
def edit_entry(entry_id):
    current_user = json.loads(get_jwt_identity())
    entry = db.entries.find_one({"_id": ObjectId(entry_id)})
    week = request.form.get('week', default=0, type=int)
    if not entry:
        flash("Entry not found", "error")
        return redirect(url_for('dashboard', week=week))

    if current_user['role'] == 'driver' and entry['user_id'] != current_user['user_id']:
        abort(403)

    if request.method == 'POST':
        try:
            update_data = {
                "date_from": datetime.strptime(request.form['date_from'], "%Y-%m-%d"),
                "date_to": datetime.strptime(request.form['date_to'], "%Y-%m-%d"),
                "type": request.form['type'],
                "time_from": request.form.get('time_from'),
                "time_to": request.form.get('time_to')
            }
            db.entries.update_one({"_id": ObjectId(entry_id)}, {"$set": update_data})
            flash("Entry updated", "success")
            return redirect(url_for('dashboard', week=week))
        except Exception as e:
            logger.error(f"💣 Entry update failed: {str(e)}")
            flash("Operation failed", "error")

    return render_template('edit_entry.html', entry=entry)

@app.route('/entries/delete/<entry_id>', methods=['POST'])
@jwt_required()
def delete_entry(entry_id):
    current_user = json.loads(get_jwt_identity())
    entry = db.entries.find_one({"_id": ObjectId(entry_id)})
    week = request.form.get('week', default=0, type=int)
    print(f"Deleting entry: {entry_id}")
    if not entry:
        flash("Entry not found", "error")
        return redirect(url_for('dashboard', week=week))

    if current_user['role'] == 'driver' and entry['user_id'] != current_user['user_id']:
        abort(403)

    db.entries.delete_one({"_id": ObjectId(entry_id)})
    flash("Entry deleted", "success")
    return redirect(url_for('dashboard', week=week))
    
@app.route('/copy-week-entries', methods=['POST'])
@jwt_required()
@manager_check
def copy_week_entries():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] not in ['admin', 'manager_all', 'manager_group']:
        abort(403)

    copy_scope = request.form.get('copy_scope')
    driver_id = request.form.get('driver_id', 'all')
    week_offset = request.form.get('week', default=0, type=int)  # Get week_offset from URL

    if copy_scope not in ['last_week', 'next_week']:
        flash("Invalid copy scope", "error")
        return redirect(url_for('dashboard'))

    try:
        # Step 1: Calculate the base week with offset
        today = datetime.now(timezone.utc)
        base_week_start = (today + timedelta(weeks=week_offset)) - timedelta(days=today.weekday())  # Monday of the navigated week
        base_week_end = base_week_start + timedelta(days=6)  # Sunday of the navigated week

        logger.info(f"Today: {today}")
        logger.info(f"Base Week Start (Monday): {base_week_start}")
        logger.info(f"Base Week End (Sunday): {base_week_end}")

        # Step 2: Determine source and target weeks based on copy_scope
        if copy_scope == 'last_week':
            source_week_start = base_week_start - timedelta(weeks=1)  # Last week's Monday relative to the navigated week
            target_week_start = base_week_start                      # Current week's Monday (navigated week)
        else:  # next_week
            source_week_start = base_week_start                      # Current week's Monday (navigated week)
            target_week_start = base_week_start + timedelta(weeks=1) # Next week's Monday relative to the navigated week

        source_week_end = source_week_start + timedelta(days=6)  # Sunday of source week
        target_week_end = target_week_start + timedelta(days=6)  # Sunday of target week

        # Adjust source week start and end to include full days
        source_week_start = source_week_start.replace(hour=0, minute=0, second=0, microsecond=0)
        source_week_end = source_week_end.replace(hour=23, minute=59, second=59, microsecond=999999)

        logger.info(f"Adjusted Source Week Start: {source_week_start}")
        logger.info(f"Adjusted Source Week End: {source_week_end}")
        logger.info(f"Target Week: {target_week_start} to {target_week_end}")

        # Step 3: Build the query
        query = {
            "$or": [
                {"date_from": {"$lte": source_week_end}, "date_to": {"$gte": source_week_start}},
                {"date_from": {"$gte": source_week_start}, "date_to": {"$lte": source_week_end}}
            ]
        }
        if driver_id != 'all':
            query["user_id"] = ObjectId(driver_id)

        logger.info(f"Query: {query}")

        # Step 4: Fetch entries from the database
        raw_entries = db.entries.find(query)
        entries_count = db.entries.count_documents(query)
        logger.info(f"Found {entries_count} entries in source week")

        # Step 5: Expand entries into daily records
        source_daily_records = []
        for entry in raw_entries:
            entry_date = entry['date_from'].replace(tzinfo=timezone.utc)
            end_date = entry['date_to'].replace(tzinfo=timezone.utc)
            logger.info(f"Processing entry: {entry['_id']}")
            logger.info(f"Entry Date From: {entry_date}")
            logger.info(f"Entry Date To: {end_date}")

            while entry_date <= end_date:
                logger.info(f"Checking date: {entry_date}")
                if source_week_start <= entry_date <= source_week_end:
                    logger.info(f"Adding entry for date: {entry_date.strftime('%Y-%m-%d')}")
                    source_daily_records.append({
                        "user_id": str(entry['user_id']),
                        "date": entry_date.strftime("%Y-%m-%d"),
                        "type": entry['type'],
                        "time_from": entry.get('time_from'),
                        "time_to": entry.get('time_to')
                    })
                else:
                    logger.info(f"Skipping date: {entry_date} (outside source week)")
                entry_date += timedelta(days=1)

        logger.info(f"Expanded to {len(source_daily_records)} daily records")
        logger.info(f"Expanded Records: {source_daily_records}")

        # Step 6: Map to target week dates
        target_daily_records = []
        for record in source_daily_records:
            source_date = datetime.strptime(record['date'], "%Y-%m-%d").date()
            days_offset = (source_date - source_week_start.date()).days
            target_date = target_week_start.date() + timedelta(days=days_offset)
            
            logger.info(f"Mapping source date: {source_date} to target date: {target_date}")
            
            new_record = record.copy()
            new_record['date'] = target_date.strftime("%Y-%m-%d")
            target_daily_records.append(new_record)

        logger.info(f"Created {len(target_daily_records)} target daily records")

        # Step 7: Insert new entries
        count, skipped = 0, 0
        for record in target_daily_records:
            target_date = datetime.strptime(record['date'], "%Y-%m-%d").date()
            new_entry = {
                "user_id": ObjectId(record['user_id']),
                "date_from": datetime.combine(target_date, datetime.min.time(), tzinfo=timezone.utc),
                "date_to": datetime.combine(target_date, datetime.max.time(), tzinfo=timezone.utc),
                "type": record['type']
            }
            if 'time_from' in record: new_entry['time_from'] = record['time_from']
            if 'time_to' in record: new_entry['time_to'] = record['time_to']

            # Check for existing entry
            existing_entry = db.entries.find_one({
                "user_id": new_entry['user_id'],
                "date_from": new_entry['date_from'],
                "date_to": new_entry['date_to'],
                "type": new_entry['type']
            })
            if not existing_entry:
                db.entries.insert_one(new_entry)
                count += 1
                logger.info(f"Inserted new entry for date: {target_date}")
            else:
                skipped += 1
                logger.info(f"Skipped duplicate entry for date: {target_date}")

        logger.info(f"Success: Copied {count}, Skipped {skipped}")
        flash(f"🎉 Copied {count} entries! Skipped {skipped} duplicates.", "success")

    except Exception as e:
        logger.error(f"Critical Error: {str(e)}", exc_info=True)
        flash("Copy operation failed. Please check logs.", "error")

    return redirect(url_for('dashboard', week=week_offset))  # Redirect to navigated week

@app.route('/clear-week-entries', methods=['POST'])
@jwt_required()

def clear_week_entries():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] not in ['admin', 'manager_all', 'manager_group']:
        abort(403)

    try:
        # Get the week parameter from the form data
        week_offset = request.form.get('week', default=0, type=int)

        # Calculate the start and end of the navigated week
        today = datetime.now(timezone.utc)
        week_start = (today + timedelta(weeks=week_offset)) - timedelta(days=today.weekday())  # Monday
        week_end = week_start + timedelta(days=6)  # Sunday

        # Adjust to include full days
        week_start = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
        week_end = week_end.replace(hour=23, minute=59, second=59, microsecond=999999)

        logger.info(f"Clearing entries for week: {week_start} to {week_end}")

        # Delete entries within the specified week
        result = db.entries.delete_many({
            "$or": [
                {"date_from": {"$lte": week_end}, "date_to": {"$gte": week_start}},
                {"date_from": {"$gte": week_start}, "date_to": {"$lte": week_end}}
            ]
        })

        logger.info(f"Deleted {result.deleted_count} entries")
        flash(f"🗑️ Cleared {result.deleted_count} entries for the week.", "success")

    except Exception as e:
        logger.error(f"Critical Error: {str(e)}", exc_info=True)
        flash("Failed to clear entries. Please check logs.", "error")

    return redirect(url_for('dashboard', week=week_offset))

@app.route('/admin/users', methods=['GET'])
@jwt_required()
def admin_users():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)  # Only admins can access this route

    users = list(db.users.find({}))
    return render_template('admin/admin_users.html', users=users,)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@jwt_required()
def admin_create_user():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        group = request.form.get('group')

        if not username or not password or not role:
            flash("Missing required fields", "error")
            return redirect(url_for('admin_create_user'))

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        db.users.insert_one({
            "username": username,
            "password_hash": hashed_password,
            "role": role,
            "group": group
        })
        flash("User created successfully", "success")
        return redirect(url_for('admin_users'))

    return render_template('admin/admin_create_user.html')

@app.route('/admin/users/edit/<user_id>', methods=['GET', 'POST'])
@jwt_required()
def admin_edit_user(user_id):
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role')
        group = request.form.get('group')

        update_data = {}
        if username:
            update_data['username'] = username
        if role:
            update_data['role'] = role
        if group:
            update_data['group'] = group
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
        flash("User updated successfully", "success")
        return redirect(url_for('admin_users'))

    return render_template('admin/admin_edit_user.html', user=user)

@app.route('/admin/users/delete/<user_id>', methods=['POST'])
@jwt_required()
def admin_delete_user(user_id):
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    db.users.delete_one({"_id": ObjectId(user_id)})
    flash("User deleted successfully", "success")
    return redirect(url_for('admin_users'))
@app.route('/admin/groups', methods=['GET'])
@jwt_required()
def admin_groups():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    groups = list(db.groups.find({}))
    return render_template('admin_groups.html', groups=groups)

@app.route('/admin/groups/create', methods=['GET', 'POST'])
@jwt_required()
def admin_create_group():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if not group_name:
            flash("Group name is required", "error")
            return redirect(url_for('admin_create_group'))

        db.groups.insert_one({"name": group_name})
        flash("Group created successfully", "success")
        return redirect(url_for('admin_groups'))

    return render_template('admin/admin_create_group.html')

@app.route('/admin/groups/delete/<group_id>', methods=['POST'])
@jwt_required()
def admin_delete_group(group_id):
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    db.groups.delete_one({"_id": ObjectId(group_id)})
    flash("Group deleted successfully", "success")
    return redirect(url_for('admin_groups'))
@app.route('/admin/schedule', methods=['GET'])
@jwt_required()
def admin_schedule():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    # Fetch all entries
    entries = list(db.entries.find({}))
    return render_template('admin/admin_schedule.html', entries=entries)

@app.route('/admin/schedule/edit/<entry_id>', methods=['GET', 'POST'])
@jwt_required()
def admin_edit_schedule(entry_id):
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    entry = db.entries.find_one({"_id": ObjectId(entry_id)})
    if not entry:
        flash("Entry not found", "error")
        return redirect(url_for('admin_schedule'))

    if request.method == 'POST':
        update_data = {
            "date_from": datetime.strptime(request.form['date_from'], "%Y-%m-%d"),
            "date_to": datetime.strptime(request.form['date_to'], "%Y-%m-%d"),
            "type": request.form['type'],
            "time_from": request.form.get('time_from'),
            "time_to": request.form.get('time_to')
        }
        db.entries.update_one({"_id": ObjectId(entry_id)}, {"$set": update_data})
        flash("Entry updated successfully", "success")
        return redirect(url_for('admin_schedule'))

    return render_template('admin_edit_schedule.html', entry=entry)

@app.route('/admin/reports', methods=['GET'])
@jwt_required()
def admin_reports():
    current_user = json.loads(get_jwt_identity())
    if current_user['role'] != 'admin':
        abort(403)

    # Fetch data for reports (e.g., shift coverage, absences)
    reports_data = {
        "total_shifts": db.entries.count_documents({}),
        "total_users": db.users.count_documents({}),
        "shift_types": list(db.entries.aggregate([
            {"$group": {"_id": "$type", "count": {"$sum": 1}}}
        ]))
    }
    return render_template('admin_reports.html', reports_data=reports_data)

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)
    return response

@app.route('/health')
def health_check():
    return jsonify({
        "status": "OK" if verify_db_connection() else "DOWN",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

# ==================================================================
#                          STARTUP
# ==================================================================
if __name__ == '__main__':
    if verify_db_connection():
        from waitress import serve
        logger.info("🚀 SUPERCHARGED SERVER STARTED")
        serve(app, host='0.0.0.0', port=5000)
    else:
        logger.critical("💥 FAILED TO LAUNCH: Database validation failed")