from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import uuid
from flask import abort, flash, redirect, url_for, render_template, request
from flask_login import login_required, current_user
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import io
import psycopg2
import os
from psycopg2.extras import RealDictCursor
from functools import wraps

# --- APPLICATION SETUP ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev_secret")


db_config = {
    'host': 'c7s7ncbk19n97r.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com',
    'user': 'u7tqojjihbpn7s',
    'password': 'p1b1897f6356bab4e52b727ee100290a84e4bf71d02e064e90c2c705bfd26f4a5',
    'database': 'd8lp4hr6fmvb9m',
    'port': 5432
}


def get_db_connection():
    """Establishes and returns a connection to the PostgreSQL database."""
    conn = psycopg2.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        dbname=db_config['database'],
        port=db_config['port']
    )
    return conn

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # The function name for the login view
login_manager.login_message = "Please log in to access this page."





# --- USER MODEL & HELPERS ---

class User(UserMixin):
    def __init__(self, user_id, username, role, employee_id):
        self.id = user_id
        self.username = username
        self.role = role
        self.employee_id = employee_id

    def get_id(self):
        return str(self.id)


from datetime import datetime, date

def calculate_hours(record):

    check_in = record.get('check_in')
    check_out = record.get('check_out')

    # ❗ Agar check_in ya check_out missing hai
    if not check_in or not check_out:
        record['worked_hours'] = 0
        return record

    # Agar string hai to convert karo
    if isinstance(check_in, str):
        check_in = datetime.strptime(check_in, "%H:%M").time()

    if isinstance(check_out, str):
        check_out = datetime.strptime(check_out, "%H:%M").time()

    # Combine for calculation
    check_in_dt = datetime.combine(date.today(), check_in)
    check_out_dt = datetime.combine(date.today(), check_out)

    worked_hours = (check_out_dt - check_in_dt).total_seconds() / 3600
    record['worked_hours'] = round(worked_hours, 2)

    return record


@login_manager.user_loader
def load_user(user_id):
    try:
        # UUID me convert karna zaruri hai
        uuid_user_id = uuid.UUID(user_id)
    except ValueError:
        return None  # invalid id

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        "SELECT id, username, role, employee_id FROM users_hrms WHERE id = %s",
        (str(uuid_user_id),)  # PostgreSQL UUID expects string
    )
    user = cur.fetchone()

    cur.close()
    conn.close()

    if user:
        return User(user['id'], user['username'], user['role'], user['employee_id'])

    return None

# --- AUTHENTICATION ROUTES ---

# LOGIN ROUTE
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['username']  # Email input
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Use JOIN: employees.email, users_hrms.password
        cur.execute("""
            SELECT u.id, u.username, u.password, u.role, u.employee_id
            FROM users_hrms u
            JOIN employees e ON u.employee_id = e.id
            WHERE e.email = %s
        """, (email,))

        user_data = cur.fetchone()
        cur.close()
        conn.close()

        if user_data and user_data['password'] == password:
            user = User(user_data['id'], user_data['username'], user_data['role'], user_data['employee_id'])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        # Username is entered
        username = request.form.get('username')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            return redirect(url_for('change_password'))

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch email automatically from employees table
        cur.execute("""
            SELECT u.id, e.email, u.password
            FROM users_hrms u
            JOIN employees e ON u.employee_id = e.id
            WHERE u.username = %s
        """, (username,))
        user = cur.fetchone()

        if not user or user['password'] != old_password:
            flash("Invalid username or old password.", "error")
            cur.close()
            conn.close()
            return redirect(url_for('change_password'))

        # Update password in users_hrms
        cur.execute("""
            UPDATE users_hrms
            SET password = %s
            WHERE id = %s
        """, (new_password, user['id']))
        conn.commit()
        cur.close()
        conn.close()

        flash("Password updated successfully! Please login with new credentials.", "success")
        return redirect(url_for('login'))

    return render_template('change_password.html')
# --- CORE ROUTES (Role-Based Access) ---

# 1. Dashboard/Index Page
@app.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    if current_user.role == 'manager':
        return redirect(url_for('manager_dashboard'))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM employees WHERE id = %s", (current_user.employee_id,))
    emp = cur.fetchone()

    cur.close()
    conn.close()

    return render_template('index.html', employee=emp)


# 2. Employee List Page (Admin ONLY)
@app.route('/core-hr/employees')
@login_required
def employee_list():

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Fetch all employees
    cur.execute("SELECT * FROM employees")
    employees = cur.fetchall()

    # Create id → name map
    emp_names = {e['id']: f"{e['first_name']} {e['last_name']}" for e in employees}

    if current_user.role == 'admin':
        display_data = []
        for e in employees:
            e_copy = dict(e)
            mgr_id = e.get('manager_id')
            e_copy['manager_name'] = emp_names.get(mgr_id, "System Admin")
            display_data.append(e_copy)

    elif current_user.role == 'manager':
        cur.execute("SELECT * FROM employees WHERE manager_id = %s",
                    (current_user.employee_id,))
        display_data = cur.fetchall()

    else:
        cur.execute("SELECT * FROM employees WHERE id = %s",
                    (current_user.employee_id,))
        me = cur.fetchone()

        if me and me.get('manager_id'):
            cur.execute("SELECT * FROM employees WHERE manager_id = %s",
                        (me['manager_id'],))
            display_data = cur.fetchall()
        else:
            display_data = [me] if me else []

    cur.close()
    conn.close()

    return render_template('core_hr/employee_list.html', employees=display_data)

# 3. Add Employee Form Handling (Admin ONLY)
@app.route('/core-hr/add', methods=['GET', 'POST'])
@login_required
def add_employee():
    """Handles the form for adding a new employee AND creating their user account."""

    if current_user.role != 'admin':
        flash('Access Denied: Only Admins can add new employees.', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cur = conn.cursor()

    # 🔹 Fetch managers for dropdown (Only role = manager)
    cur.execute("""
        SELECT e.id, e.first_name, e.last_name
        FROM employees e
        JOIN users_hrms u ON e.id = u.employee_id
        WHERE u.role = 'manager'
    """)
    managers = cur.fetchall()

    if request.method == 'POST':
        # 1️⃣ Get Employee Data from form
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        department = request.form['department']
        position = request.form['position']
        manager_id = request.form.get('manager_id') or None  # ✅ Added

        # --- EMPLOYEE DATA CREATION ---
        new_employee_id = str(uuid.uuid4())

        # Insert into employees table
        cur.execute("""
            INSERT INTO employees 
            (id, first_name, last_name, email, department, position, manager_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (new_employee_id, first_name, last_name, email, department, position, manager_id))

        # --- USER ACCOUNT CREATION ---
        new_username = first_name.lower()
        default_password = 'temp_password'

        cur.execute("""
            INSERT INTO users_hrms (username, password, role, employee_id)
            VALUES (%s, %s, %s, %s)
        """, (new_username, default_password, 'employee', new_employee_id))

        conn.commit()
        cur.close()
        conn.close()

        flash_message = (
            f'Employee {first_name} {last_name} added successfully! '
            f'User account created: Username: {new_username}, Password: {default_password}.'
        )
        flash(flash_message, 'success')

        return redirect(url_for('employee_list'))

    cur.close()
    conn.close()

    return render_template('core_hr/add_employee.html', managers=managers)


# --- ADMIN DASHBOARD ROUTE (RE-INTEGRATED) ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    """Admin dashboard to view all data, manage leaves, and export data."""

    if current_user.role != 'admin':
        flash('प्रशासनिक पहुँच अस्वीकृत।', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # --- POST Handling ---
    if request.method == 'POST':
        action = request.form.get('action')

        # ✅ APPROVE / REJECT LEAVE (Same Logic)
        if action == 'approve_leave' or action == 'reject_leave':
            leave_id = int(request.form['leave_id'])
            status = 'Approved' if action == 'approve_leave' else 'Rejected'

            cur.execute(
                "UPDATE leave_applications SET status=%s WHERE id=%s",
                (status, leave_id)
            )

            if cur.rowcount > 0:
                conn.commit()
                flash(f"छुट्टी आवेदन ID {leave_id} को {status} कर दिया गया है।", 'success')
            else:
                flash("छुट्टी आवेदन नहीं मिला।", 'error')

            cur.close()
            conn.close()
            return redirect(url_for('admin_dashboard'))

        # ✅ EXPORT ATTENDANCE (Same CSV Format)
        elif action == 'export_attendance':

            csv_content = "Employee ID,Name,Date,In Time,Out Time,Total Hours,Location\n"

            cur.execute("""
                SELECT a.*, e.first_name, e.last_name
                FROM attendance_records a
                LEFT JOIN employees e
                ON a.employee_id = e.id
            """)
            records = cur.fetchall()

            for record in records:
                processed = calculate_hours(dict(record))

                name = f"{record['first_name'] or 'Unknown'} {record['last_name'] or ''}"

                csv_content += (
                    f"{record['employee_id']},"
                    f"{name},"
                    f"{record['date']},"
                    f"{record['in_time']},"
                    f"{record['out_time']},"
                    f"{processed['total_hours_str']},"
                    f"{record['location']}\n"
                )

            cur.close()
            conn.close()

            buffer = io.BytesIO(csv_content.encode('utf-8'))
            return send_file(
                buffer,
                as_attachment=True,
                download_name='attendance_report.csv',
                mimetype='text/csv'
            )

        return redirect(url_for('admin_dashboard'))

    # -----------------------------
    # -------- GET Handling -------
    # -----------------------------

    # 1️⃣ Attendance + Employee Info (Same Logic)
    cur.execute("""
        SELECT a.*, e.first_name, e.last_name, e.department
        FROM attendance_records a
        LEFT JOIN employees e
        ON a.employee_id = e.id
    """)
    attendance_data = cur.fetchall()

    attendance_for_admin = []
    for record in attendance_data:
        processed_record = calculate_hours(dict(record))
        processed_record.update({
            'name': f"{record['first_name']} {record['last_name']}",
            'department': record['department'],
        })
        attendance_for_admin.append(processed_record)

    # 2️⃣ Performance + Employee Info (Same Logic)
    cur.execute("""
        SELECT p.*, e.first_name, e.last_name, e.department, e.position
        FROM performance_data p
        LEFT JOIN employees e
        ON p.employee_id = e.id
    """)
    performance_data_raw = cur.fetchall()

    performance_for_admin = []
    for perf in performance_data_raw:
        perf.update({
            'name': f"{perf['first_name']} {perf['last_name']}",
            'department': perf['department'],
            'position': perf['position'],
        })
        performance_for_admin.append(perf)

    # 3️⃣ Pending Leaves
    cur.execute("SELECT * FROM leave_applications WHERE status='Pending'")
    pending_leaves = cur.fetchall()

    # 4️⃣ Total Employees
    cur.execute("SELECT COUNT(*) FROM employees")
    total_employees = cur.fetchone()['count']

    cur.close()
    conn.close()

    context = {
        'total_employees': total_employees,
        'pending_leaves': pending_leaves,
        'attendance_records': sorted(attendance_for_admin, key=lambda x: x['date'], reverse=True),
        'performance_data': performance_for_admin,
    }

    return render_template('admin/admin_dashboard.html', **context)





# --- EMPLOYEE SELF-SERVICE FEATURES (Employee Role) ---
from datetime import datetime



@app.route('/my-attendance', methods=['GET', 'POST'])
@login_required
def my_attendance():
    """Handles attendance logging using Total Hours instead of In/Out time."""

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # ---------------- POST ----------------
    if request.method == 'POST':

        # Export check (no logic change)
        if request.form.get('action') == 'export_attendance':
            pass

        # Admin restriction
        if current_user.role == 'admin':
            flash('Admins cannot log personal attendance from here.', 'warning')
            return redirect(url_for('my_attendance'))

        log_date = request.form.get('log_date')
        total_hours = request.form.get('total_hours')
        location = request.form.get('location')

        today = datetime.now().strftime('%Y-%m-%d')

        if log_date > today:
            flash('Future dates not allowed!', 'error')
            return redirect(url_for('my_attendance'))

        cur.execute("""
            INSERT INTO attendance_records
            (employee_id, date, in_time, out_time, total_hours_str, location)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            current_user.employee_id,
            log_date,
            None,
            None,
            f"{total_hours} hrs",
            location
        ))

        conn.commit()
        cur.close()
        conn.close()

        flash(f'Attendance for {total_hours} hours logged for {log_date}!', 'success')
        return redirect(url_for('my_attendance'))

    # ---------------- GET ----------------

    processed_records = []

    if current_user.role in ['admin', 'manager']:

        if current_user.role == 'manager':
            cur.execute("SELECT id FROM employees WHERE manager_id=%s",
                        (current_user.employee_id,))
            team = cur.fetchall()
            my_team_ids = [e['id'] for e in team]
        else:
            my_team_ids = []

        cur.execute("""
            SELECT a.*, e.first_name, e.last_name
            FROM attendance_records a
            LEFT JOIN employees e ON a.employee_id = e.id
        """)
        records = cur.fetchall()

        for r in records:
            if (current_user.role == 'admin'
                or r['employee_id'] in my_team_ids
                or r['employee_id'] == current_user.employee_id):

                record_copy = dict(r)

                if not record_copy.get('total_hours_str'):
                    record_copy = calculate_hours(record_copy)

                record_copy['employee_name'] = (
                    f"{r['first_name']} {r['last_name']}"
                    if r['first_name'] else "Unknown"
                )

                processed_records.append(record_copy)

    else:
        cur.execute("""
            SELECT * FROM attendance_records
            WHERE employee_id=%s
        """, (current_user.employee_id,))
        user_records = cur.fetchall()

        for r in user_records:
            record_copy = dict(r)
            if not record_copy.get('total_hours_str'):
                record_copy = calculate_hours(record_copy)
            processed_records.append(record_copy)

    cur.execute("SELECT COUNT(*) FROM employees")
    total_employees = cur.fetchone()['count']

    cur.close()
    conn.close()

    today_date = datetime.now().strftime('%Y-%m-%d')

    current_status = (
        'Hours Logged'
        if any(
            r['date'].strftime('%Y-%m-%d') == today_date
            for r in processed_records
        )
        else 'Not Logged Today'
    )

    context = {
        'records': sorted(processed_records,
                          key=lambda x: x['date'],
                          reverse=True),
        'attendance_status': current_status,
        'today_date': today_date,
        'total_employees': total_employees
    }

    return render_template('employee_ss/my_attendance.html', **context)


@app.route('/upload-attendance-csv', methods=['POST'])
@login_required
def upload_attendance_csv():

    if current_user.role != 'admin':
        abort(403)

    file = request.files.get('attendance_file')

    if not file:
        flash("No file selected", "danger")
        return redirect(url_for('admin_dashboard'))

    import csv
    import io

    conn = get_db_connection()
    cur = conn.cursor()

    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_input = csv.DictReader(stream)

    for row in csv_input:
        employee_id = row['employee_id']
        date = row['date']
        total_hours = row['total_hours']
        location = row.get('location', 'Uploaded')

        cur.execute("""
            INSERT INTO attendance_records
            (employee_id, date, in_time, out_time, total_hours_str, location)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            employee_id,
            date,
            None,
            None,
            f"{total_hours} hrs",
            location
        ))

    conn.commit()
    cur.close()
    conn.close()

    flash("Attendance Uploaded Successfully", "success")
    return redirect(url_for('admin_dashboard'))

from zk import ZK
from datetime import datetime

@app.route('/sync-essl-attendance')
@login_required
def sync_essl_attendance():

    if current_user.role != 'admin':
        abort(403)

    # 🔹 Device Configuration
    DEVICE_IP = "192.168.1.201"   # <-- Yaha apna device IP dalein
    DEVICE_PORT = 4370            # <-- Usually 4370 default hota hai
    DEVICE_PASSWORD = 0           # Agar password nahi hai to 0

    try:
        zk = ZK(DEVICE_IP, port=DEVICE_PORT, timeout=5, password=DEVICE_PASSWORD)
        conn = zk.connect()
        conn.disable_device()

        attendances = conn.get_attendance()

        db_conn = get_db_connection()
        cur = db_conn.cursor()

        inserted = 0

        for att in attendances:
            employee_id = att.user_id
            punch_time = att.timestamp
            punch_date = punch_time.strftime('%Y-%m-%d')

            cur.execute("""
                INSERT INTO attendance_records
                (employee_id, date, in_time, out_time, total_hours_str, location)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (
                employee_id,
                punch_date,
                None,
                None,
                None,
                "Biometric Device"
            ))

            inserted += 1

        db_conn.commit()
        cur.close()
        db_conn.close()

        conn.enable_device()
        conn.disconnect()

        flash(f"{inserted} biometric records synced successfully.", "success")

    except Exception as e:
        flash(f"Device connection failed: {str(e)}", "danger")

    return redirect(url_for('my_attendance'))

@app.route('/my-leaves', methods=['GET', 'POST'])
@login_required
def my_leaves():
    """Handles leaves for Admin, Manager, and Employee."""

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # ----------------------------
    # -------- POST --------------
    # ----------------------------
    if request.method == 'POST':

        action = request.form.get('action')

        # ✅ EMPLOYEE OR MANAGER APPLY LEAVE (Always Pending)
        if current_user.role in ['employee', 'manager'] and action is None:

            start_date = request.form['start_date']
            end_date = request.form['end_date']
            leave_type = request.form['leave_type']

            cur.execute("""
                INSERT INTO leave_applications
                (employee_id, start_date, end_date, type, status)
                VALUES (%s, %s, %s, %s, 'Pending')
            """, (current_user.employee_id, start_date, end_date, leave_type))

            conn.commit()
            flash('Leave application submitted successfully!', 'success')
            cur.close()
            conn.close()
            return redirect(url_for('my_leaves'))

        # ✅ ONLY MANAGER CAN APPROVE/REJECT TEAM LEAVES? NO — Only admin approves
        elif current_user.role == 'manager' and action in ['approve', 'reject']:
            flash('Managers cannot approve/reject leaves. Only admins can.', 'warning')
            cur.close()
            conn.close()
            return redirect(url_for('my_leaves'))

        # ✅ ADMIN APPROVE/REJECT
        elif current_user.role == 'admin' and action in ['approve', 'reject']:

            leave_id = request.form.get('leave_id')
            new_status = 'Approved' if action == 'approve' else 'Rejected'

            # Admin can update any leave
            cur.execute("""
                UPDATE leave_applications
                SET status = %s
                WHERE id = %s
            """, (new_status, leave_id))
            conn.commit()
            flash(f'Leave ID {leave_id} {new_status} successfully!', 'success')

            cur.close()
            conn.close()
            return redirect(url_for('my_leaves'))

        else:
            flash('Admins cannot apply for leaves from this panel.', 'warning')
            cur.close()
            conn.close()
            return redirect(url_for('my_leaves'))

    # ----------------------------
    # -------- GET ---------------
    # ----------------------------

    if current_user.role == 'admin':
        # Admin sees all leaves
        cur.execute("""
            SELECT l.*, e.first_name || ' ' || e.last_name AS name
            FROM leave_applications l
            LEFT JOIN employees e ON l.employee_id = e.id
            ORDER BY l.start_date DESC
        """)
        display_records = cur.fetchall()

    elif current_user.role == 'manager':
        # Manager sees own + team leaves (but status remains pending until admin approves)
        cur.execute("""
            SELECT l.*, e.first_name || ' ' || e.last_name AS name
            FROM leave_applications l
            JOIN employees e ON l.employee_id = e.id
            WHERE e.manager_id = %s OR l.employee_id = %s
            ORDER BY l.start_date DESC
        """, (current_user.employee_id, current_user.employee_id))
        display_records = cur.fetchall()

    else:
        # Employee sees only own leaves
        cur.execute("""
            SELECT l.*, e.first_name || ' ' || e.last_name AS name
            FROM leave_applications l
            LEFT JOIN employees e ON l.employee_id = e.id
            WHERE l.employee_id = %s
            ORDER BY l.start_date DESC
        """, (current_user.employee_id,))
        display_records = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('employee_ss/my_leaves.html', records=display_records)

@app.route('/training-courses')
@login_required
def training_courses():
    """Employee training and learning management."""

    if current_user.role != 'employee':
        flash('Access Denied.', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # ✅ Same logic — get performance data for current employee
    cur.execute("""
        SELECT * FROM performance_data
        WHERE employee_id = %s
    """, (current_user.employee_id,))

    user_performance = cur.fetchone()

    cur.close()
    conn.close()

    # ✅ Static courses (Same as before)
    courses = [
        {'title': 'Annual Compliance Training', 'status': 'Completed'},
        {'title': 'Agile Fundamentals', 'status': 'In Progress'},
    ]

    # ✅ SAME training split logic
    if user_performance and user_performance.get('training'):
        training_string = user_performance['training']
        parts = training_string.split('(')

        title = parts[0].strip()
        status = parts[1].replace(')', '') if len(parts) > 1 else 'N/A'

        courses.append({
            'title': title,
            'status': status
        })

    return render_template(
        'employee_ss/training_courses.html',
        courses=courses,
        performance=user_performance
    )


@app.route('/my-documents')
@login_required
def my_documents():

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # ================= DOCUMENT FETCH (UNCHANGED) =================
    if current_user.role == 'admin':
        cur.execute("""
            SELECT d.id, d.name, d.category, d.date, e.first_name, e.last_name
            FROM documents d
            LEFT JOIN employees e ON d.employee_id = e.id
            ORDER BY d.date DESC
        """)
        rows = cur.fetchall()

        documents = []
        for r in rows:
            documents.append({
                "id": r['id'],
                "name": r['name'],
                "category": r['category'],
                "date": r['date'].strftime('%Y-%m-%d') if r['date'] else '-',
                "employee_name": f"{r['first_name']} {r['last_name']}" if r['first_name'] else "Unknown"
            })

    else:
        cur.execute("""
            SELECT id, name, category, date
            FROM documents
            WHERE employee_id = %s
            ORDER BY date DESC
        """, (current_user.employee_id,))
        rows = cur.fetchall()

        documents = []
        for r in rows:
            documents.append({
                "id": r['id'],
                "name": r['name'],
                "category": r['category'],
                "date": r['date'].strftime('%Y-%m-%d') if r['date'] else '-'
            })

    # ================= EMPLOYEE DROPDOWN DATA (NEW ADDITION) =================
    all_employees = []

    if current_user.role == 'admin':
        cur.execute("""
            SELECT id, first_name, last_name
            FROM employees
            ORDER BY first_name ASC
        """)
        all_employees = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "employee_ss/my_documents.html",
        documents=documents,
        all_employees=all_employees
    )

@app.route('/upload-document', methods=['POST'])
@login_required
def upload_document():

    if current_user.role != 'admin':
        flash("Unauthorized", "error")
        return redirect(url_for('my_documents'))

    name = request.form['name']
    category = request.form['category']
    employee_id = request.form['employee_id']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO documents (id, name, category, date, employee_id)
        VALUES (%s, %s, %s, NOW(), %s)
    """, (
        str(uuid.uuid4()),
        name,
        category,
        employee_id
    ))

    conn.commit()
    cur.close()
    conn.close()

    flash("Document uploaded successfully!", "success")
    return redirect(url_for('my_documents'))

@app.route('/manager/dashboard', methods=['GET', 'POST'])
@login_required
def manager_dashboard():
    if current_user.role != 'manager':
        flash('Access Denied: Managers only.', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 1️⃣ TEAM FETCH
    cursor.execute("""
        SELECT id, first_name, last_name, department, position
        FROM employees
        WHERE manager_id = %s
    """, (current_user.employee_id,))

    employees = cursor.fetchall()

    my_team_ids = [str(e[0]) for e in employees]

    employee_map = {
        str(e[0]): {
            "first_name": e[1],
            "last_name": e[2],
            "department": e[3],
            "position": e[4]
        }
        for e in employees
    }

    # 🔹 2️⃣ POST HANDLING (NO CHANGE)
    if request.method == 'POST':

        action = request.form.get('action')

        if action in ['approve_leave', 'reject_leave']:
            leave_id = request.form.get('leave_id')

            if leave_id and leave_id.isdigit():
                leave_id = int(leave_id)

                cursor.execute("""
                    SELECT employee_id FROM leave_applications
                    WHERE id = %s
                """, (leave_id,))
                row = cursor.fetchone()

                if row and str(row[0]) in my_team_ids:
                    new_status = 'Approved' if action == 'approve_leave' else 'Rejected'

                    cursor.execute("""
                        UPDATE leave_applications
                        SET status = %s
                        WHERE id = %s
                    """, (new_status, leave_id))

                    conn.commit()
                    flash(f"Leave {new_status} Successfully", 'success')

        elif action == 'assign_training':

            emp_id = request.form.get('employee_id')
            training_name = request.form.get('training_name')

            if emp_id in my_team_ids and training_name:
                cursor.execute("""
                    UPDATE performance_data
                    SET training = %s
                    WHERE employee_id = %s
                """, (training_name, emp_id))

                conn.commit()
                flash("Training Assigned Successfully", "success")

        return redirect(url_for('manager_dashboard'))

    # =============================
    # 🔹 3️⃣ GET HANDLING
    # =============================

    team_attendance = []
    team_perf = []
    pending_leaves = []
    approved_leaves = []

    if my_team_ids:

        # =============================
        # ✅ ATTENDANCE (FILTERED IN SQL)
        # =============================
        cursor.execute("""
            SELECT id, employee_id, date, in_time, out_time
            FROM attendance_records
            WHERE employee_id = ANY(%s)
        """, (my_team_ids,))

        attendance_rows = cursor.fetchall()

        for row in attendance_rows:
            emp = employee_map.get(str(row[1]))
            if emp:
                record = {
                    "id": row[0],
                    "employee_id": row[1],
                    "date": row[2],
                    "check_in": row[3],
                    "check_out": row[4]
                }

                rec = calculate_hours(record)

                rec.update({
                    "name": f"{emp['first_name']} {emp['last_name']}",
                    "dept": emp['department']
                })

                team_attendance.append(rec)

        # =============================
        # ✅ PERFORMANCE
        # =============================
        cursor.execute("""
            SELECT id, employee_id, training, rating
            FROM performance_data
            WHERE employee_id = ANY(%s)
        """, (my_team_ids,))

        perf_rows = cursor.fetchall()

        for row in perf_rows:
            emp = employee_map.get(str(row[1]))
            if emp:
                p_copy = {
                    "id": row[0],
                    "employee_id": row[1],
                    "training": row[2],
                    "rating": row[3],
                    "name": f"{emp['first_name']} {emp['last_name']}",
                    "pos": emp['position']
                }

                team_perf.append(p_copy)

        # =============================
        # ✅ LEAVES
        # =============================
        cursor.execute("""
            SELECT id, employee_id, name, start_date, end_date, type, status
            FROM leave_applications
            WHERE employee_id = ANY(%s)
        """, (my_team_ids,))

        leaves = cursor.fetchall()

        for l in leaves:
            leave_data = {
                "id": l[0],
                "employee_id": l[1],
                "name": l[2],
                "start_date": l[3],
                "end_date": l[4],
                "type": l[5],
                "status": l[6]
            }

            if l[6] == 'Pending':
                pending_leaves.append(leave_data)
            elif l[6] == 'Approved':
                approved_leaves.append(leave_data)

    cursor.close()
    conn.close()

    context = {
        "team_count": len(my_team_ids),
        "pending_leaves": pending_leaves,
        "approved_leaves": approved_leaves,
        "attendance": team_attendance,
        "performance": team_perf
    }

    return render_template("manager/manager_dashboard.html", **context)

@app.route('/core-hr/add-manager', methods=['GET', 'POST'])
@login_required
def add_manager():

    if current_user.role != 'admin':
        flash('Access Denied', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':

        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        department = request.form['department']
        position = request.form['position']

        manager_id = None  # Top level manager

        new_employee_id = str(uuid.uuid4())

        # Insert into employees
        cur.execute("""
            INSERT INTO employees 
            (id, first_name, last_name, email, department, position, manager_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (new_employee_id, first_name, last_name, email, department, position, manager_id))

        # Insert into users_hrms as manager
        cur.execute("""
            INSERT INTO users_hrms (username, password, role, employee_id)
            VALUES (%s, %s, %s, %s)
        """, (first_name.lower(), 'temp_password', 'manager', new_employee_id))

        conn.commit()
        cur.close()
        conn.close()

        flash("Manager added successfully!", "success")
        return redirect(url_for('employee_list'))

    cur.close()
    conn.close()

    return render_template('core_hr/add_manager.html')

# --- RUN THE APPLICATION ---
if __name__ == '__main__':
    app.run(debug=True)
