import sqlite3
from datetime import datetime
import csv
import hashlib

DB_NAME = "inventory.db"

def get_conn_cursor():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    return conn, cursor

def init_db():
    """
    Initialize the SQLite database with required tables.
    Ensures there's at least one default admin account.
    """
    conn, cursor = get_conn_cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Devices table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_type TEXT,
        hostname TEXT NOT NULL,
        serial TEXT NOT NULL,
        os TEXT,
        ip TEXT,
        purchase_date TEXT
    )
    """)

    # Update logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS update_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        update_time TEXT NOT NULL,
        changes TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id)
    )
    """)

    conn.commit()

    # Ensure at least one admin user
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    admin_count = cursor.fetchone()[0]
    if admin_count == 0:
        default_admin_username = "admin"
        default_admin_password = "admin123"
        hashed_pw = hash_password(default_admin_password)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, 'admin', ?)",
                (default_admin_username, hashed_pw, now)
            )
            conn.commit()
            print(f"Default admin '{default_admin_username}' created with password '{default_admin_password}'. Change this immediately.")
        except sqlite3.IntegrityError:
            pass  # Account already exists

    conn.close()

def hash_password(password):
    """
    Returns the SHA-256 hash of the password.
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def add_user(username, password, role="user"):
    """
    Adds a new user. Returns False if the username already exists.
    """
    if role not in ("user", "admin"):
        raise ValueError("Role must be 'user' or 'admin'")
    conn, cursor = get_conn_cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hashed_pw = hash_password(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hashed_pw, role, now)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False
    conn.close()
    return True

def user_exists(username):
    conn, cursor = get_conn_cursor()
    cursor.execute("SELECT 1 FROM users WHERE username=?", (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def authenticate_user(username, password):
    """
    Returns role if user is authenticated, else None.
    """
    conn, cursor = get_conn_cursor()
    hashed_pw = hash_password(password)
    cursor.execute("SELECT role FROM users WHERE username=? AND password=?", (username, hashed_pw))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def update_user(old_username, new_username=None, role=None):
    """
    Updates the username and/or role of a user.
    Returns False if the new username already exists.
    """
    if new_username is None and role is None:
        return False
    if role and role not in ("user", "admin"):
        raise ValueError("Role must be 'user' or 'admin'")

    conn, cursor = get_conn_cursor()

    if new_username and new_username != old_username:
        cursor.execute("SELECT 1 FROM users WHERE username=?", (new_username,))
        if cursor.fetchone():
            conn.close()
            return False

    updates = []
    params = []

    if new_username:
        updates.append("username=?")
        params.append(new_username)
    if role:
        updates.append("role=?")
        params.append(role)

    params.append(old_username)

    query = f"UPDATE users SET {', '.join(updates)} WHERE username=?"
    try:
        cursor.execute(query, params)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False

    conn.close()
    return True

def update_password(username, new_password):
    """
    Changes a user's password.
    """
    conn, cursor = get_conn_cursor()
    hashed_pw = hash_password(new_password)
    cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_pw, username))
    conn.commit()
    conn.close()

def get_all_users():
    """
    Returns list of all users with (username, role, created_at).
    """
    conn, cursor = get_conn_cursor()
    cursor.execute("SELECT username, role, created_at FROM users ORDER BY created_at")
    users = cursor.fetchall()
    conn.close()
    return users

def insert_device(device):
    """
    Adds a new device to the database.
    """
    conn, cursor = get_conn_cursor()
    cursor.execute("""
        INSERT INTO devices (device_type, hostname, serial, os, ip, purchase_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        device['device_type'],
        device['hostname'],
        device['serial'],
        device['os'],
        device['ip'],
        device['purchase_date']
    ))
    conn.commit()
    conn.close()

def get_all_devices():
    """
    Returns a list of all devices.
    """
    conn, cursor = get_conn_cursor()
    cursor.execute("SELECT id, device_type, hostname, serial, os, ip, purchase_date FROM devices")
    devices = cursor.fetchall()
    conn.close()
    return devices

def update_device(device_id, device, detailed_changes=None):
    """
    Updates device information and logs changes.
    """
    conn, cursor = get_conn_cursor()
    cursor.execute("""
        UPDATE devices
        SET device_type=?, hostname=?, serial=?, os=?, ip=?, purchase_date=?
        WHERE id=?
    """, (
        device['device_type'],
        device['hostname'],
        device['serial'],
        device['os'],
        device['ip'],
        device['purchase_date'],
        device_id
    ))
    conn.commit()

    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    changes = detailed_changes or f"Updated device {device_id}"
    cursor.execute("INSERT INTO update_logs (device_id, update_time, changes) VALUES (?, ?, ?)",
                   (device_id, update_time, changes))
    conn.commit()
    conn.close()

def delete_device(device_id):
    """
    Deletes a device.
    """
    conn, cursor = get_conn_cursor()
    cursor.execute("DELETE FROM devices WHERE id=?", (device_id,))
    conn.commit()
    conn.close()

def get_update_logs(device_id):
    """
    Gets update logs for a specific device.
    """
    conn, cursor = get_conn_cursor()
    cursor.execute("""
        SELECT id, update_time, changes
        FROM update_logs
        WHERE device_id=?
        ORDER BY update_time DESC
    """, (device_id,))
    logs = cursor.fetchall()
    conn.close()
    return logs

def export_logs_to_csv(file_path, device_id):
    """
    Exports a device's update logs to a CSV file.
    """
    logs = get_update_logs(device_id)
    with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Log ID", "Update Time", "Changes"])
        csvwriter.writerows(logs)
