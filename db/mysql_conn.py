import os

try:
    import mysql.connector
    from mysql.connector import Error
except Exception:  # pragma: no cover
    mysql = None
    Error = Exception

from backend.auth.utils import check_password
from backend.utils.json_handler import load_json, save_json

USERS_FILE = "users.json"


def get_db_connection():
    if mysql is None:
        return None
    host = os.environ.get("MYSQL_HOST")
    user = os.environ.get("MYSQL_USER")
    password = os.environ.get("MYSQL_PASSWORD")
    database = os.environ.get("MYSQL_DATABASE", "network_scanner")
    if not host or not user:
        return None
    try:
        return mysql.connector.connect(
            host=host,
            user=user,
            password=password or "",
            database=database,
        )
    except Error as e:
        print(f"Error: {e}")
        return None


def _file_users():
    data = load_json(USERS_FILE)
    return data if isinstance(data, list) else []


def _save_file_users(users):
    save_json(USERS_FILE, users)


def get_user_by_username(username):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            return user
        except Error as e:
            print(f"MySQL Error: {e}")
            return None
    for user in _file_users():
        if user.get("username") == username:
            return user
    return None


def create_user(username, password_hash, advanced_mode=False):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return None
        cursor.execute(
            "INSERT INTO users (username, password_hash, advanced_mode) VALUES (%s, %s, %s)",
            (username, password_hash, bool(advanced_mode)),
        )
        conn.commit()
        user_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return {
            "id": user_id,
            "username": username,
            "password_hash": password_hash,
            "advanced_mode": bool(advanced_mode),
        }
    users = _file_users()
    if any(u.get("username") == username for u in users):
        return None
    user = {
        "id": (max((int(u.get("id") or 0) for u in users), default=0) + 1),
        "username": username,
        "password_hash": password_hash,
        "advanced_mode": bool(advanced_mode),
    }
    users.append(user)
    _save_file_users(users)
    return user


def validate_user(username, password):
    """Verify username + plaintext password using bcrypt (file or MySQL)."""
    user = get_user_by_username(username)
    if not user:
        return False
    hashed = user.get("password_hash") or ""
    if not hashed:
        return False
    if hashed == password:
        return False
    try:
        if not check_password(password, hashed):
            return False
    except ValueError:
        return False
    return user
