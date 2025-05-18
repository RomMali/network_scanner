import mysql.connector
from mysql.connector import Error


def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='RomMali130507!',
            database='galacticguard'
        )
        return conn
    except Error as e:
        print(f"Error: {e}")
        return None


def validate_user(username, password):
    conn = get_db_connection()
    if not conn:
        return False
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s AND password_hash = %s", (username, password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user  # includes advanced_mode now
    except Error as e:
        print(f"MySQL Error: {e}")
        return False
