from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from backend.auth.utils import check_password, generate_token, hash_password
from db.mysql_conn import create_user, get_user_by_username

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    advanced_mode = bool(data.get("advanced_mode", False))

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if get_user_by_username(username):
        return jsonify({"error": "User already exists"}), 409

    hashed_pw = hash_password(password)
    user = create_user(username, hashed_pw, advanced_mode=advanced_mode)
    if not user:
        return jsonify({"error": "Could not create user"}), 500
    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    user = get_user_by_username(username)
    if not user or not check_password(password or "", user.get("password_hash") or ""):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(
        identity={
            "id": user["id"],
            "username": user["username"],
            "advanced_mode": bool(user.get("advanced_mode")),
        }
    )
    return jsonify(
        {
            "token": token,
            "username": user["username"],
            "advanced_mode": bool(user.get("advanced_mode")),
            "id": user["id"],
        }
    ), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    claims = get_jwt()
    return jsonify(
        {
            "id": get_jwt_identity(),
            "username": claims.get("username"),
            "advanced_mode": bool(claims.get("advanced_mode")),
        }
    )
