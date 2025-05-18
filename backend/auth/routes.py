from backend.auth.utils import hash_password, check_password, generate_token
from db.mysql_conn import get_db_connection
from flask import Blueprint, request, jsonify
from db.json_storage.json_storage import (
    add_to_blacklist,
    delete_blacklist_by_ip,
    get_blacklist,
    load_blacklist,
    load_attacks,
    load_networks,
    load_reports
)

auth_bp = Blueprint('auth', __name__)
core_bp = Blueprint('core', __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        return jsonify({"error": "User already exists"}), 409

    hashed_pw = hash_password(password)
    cursor.execute("INSERT INTO users (username, password_hash, advanced_mode) VALUES (%s, %s, %s)",
                   (username, hashed_pw, False))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not check_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(identity={"id": user["id"], "username": user["username"]})
    return jsonify({"token": token}), 200


# Ensure the blacklist file is initialized when the app starts
load_blacklist()


@auth_bp.route("/add_to_blacklist", methods=["POST"])
def add_ip_to_blacklist():
    data = request.json
    ip = data.get("ip")
    reason = data.get("reason")

    if not ip or not reason:
        return jsonify({"error": "IP address and reason are required"}), 400

    add_to_blacklist(ip, reason)
    return jsonify({"message": f"IP {ip} added to blacklist"}), 200


@auth_bp.route("/remove_from_blacklist", methods=["POST"])
def remove_ip_from_blacklist():
    data = request.json
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    if delete_blacklist_by_ip(ip):
        return jsonify({"message": f"IP {ip} removed from blacklist"}), 200
    else:
        return jsonify({"error": f"IP {ip} not found in blacklist"}), 404


@auth_bp.route("/get_blacklist", methods=["GET"])
def get_blacklist_data():
    blacklist_data = get_blacklist()
    return jsonify(blacklist_data)
