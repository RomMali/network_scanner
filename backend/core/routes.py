from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt

from backend.logic.event_log import format_text, get_events
from backend.logic.ml_pipeline import get_alerts
from backend.logic.nfqueue_worker import worker
from backend.logic.rules import delete_rule, list_rules, upsert_rule
from db.json_storage import json_storage
from db.json_storage.json_storage import (
    ATTACKS_FILE,
    REPORTS_FILE,
    NETWORKS_FILE,
    get_all_entries,
)
from db.mysql_conn import validate_user

core_bp = Blueprint("core", __name__)


def _status_payload():
    return worker.status()


def _start_payload():
    result = worker.start()
    if result.get("ok"):
        return jsonify({"status": "running", "Sniffer started": True, **result}), 200
    if worker.running:
        return jsonify({"status": "running", "message": "already running"}), 200
    return jsonify({"status": "stopped", "error": "failed to start"}), 400


def _stop_payload():
    result = worker.stop()
    return jsonify({"status": "stopped", **result}), 200


def _require_advanced():
    claims = get_jwt()
    if not claims.get("advanced_mode"):
        return jsonify({"error": "advanced_mode required"}), 403
    return None


@core_bp.route("/start", methods=["GET"])
def start_sniffer():
    return _start_payload()


@core_bp.route("/stop", methods=["GET"])
def stop_sniffer():
    return _stop_payload()


@core_bp.route("/status", methods=["GET"])
def service_status():
    return jsonify(_status_payload())


@core_bp.route("/attacks", methods=["GET", "POST"])
def manage_attacks():
    if request.method == "GET":
        return jsonify(json_storage.get_attacks())
    return jsonify(json_storage.add_attack(request.json)), 201


@core_bp.route("/networks", methods=["GET", "POST"])
def manage_networks():
    if request.method == "GET":
        return jsonify(json_storage.get_networks())
    return jsonify(json_storage.add_network(request.json)), 201


@core_bp.route("/reports", methods=["GET", "POST"])
def manage_reports():
    username = request.args.get("username")
    password = request.args.get("password")
    user = validate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 403

    if request.method == "GET":
        return jsonify(json_storage.get_reports(user["id"]))
    return jsonify(json_storage.add_report(request.json, user["id"])), 201


@core_bp.route("/network/<name>", methods=["PUT", "DELETE"])
def handle_network_by_name(name):
    if request.method == "PUT":
        updated = json_storage.update_network_by_name(name, request.json)
        return (jsonify(updated), 200) if updated else ({"error": "Not found"}, 404)
    deleted = json_storage.delete_network_by_name(name)
    return (jsonify(deleted), 200) if deleted else ({"error": "Not found"}, 404)


@core_bp.route("/blacklist/<ip>", methods=["PUT", "DELETE"])
@jwt_required()
def handle_blacklist_by_ip(ip):
    denied = _require_advanced()
    if denied:
        return denied
    if request.method == "PUT":
        updated = json_storage.update_blacklist_by_ip(ip, request.json)
        return (jsonify(updated), 200) if updated else (jsonify({"error": "Not found"}), 404)
    deleted = json_storage.delete_blacklist_by_ip(ip)
    return (jsonify(deleted), 200) if deleted else (jsonify({"error": "Not found"}), 404)


@core_bp.route("/api/attacks", methods=["GET"])
def get_attacks():
    data = json_storage.get_attacks()
    if not data:
        data = get_all_entries(ATTACKS_FILE)
    return jsonify(data), 200


@core_bp.route("/api/blacklist", methods=["GET", "POST"])
def blacklist_collection():
    if request.method == "GET":
        return jsonify(json_storage.get_blacklist()), 200
    from flask_jwt_extended import verify_jwt_in_request

    verify_jwt_in_request()
    denied = _require_advanced()
    if denied:
        return denied
    body = request.json or {}
    ip = body.get("ip")
    reason = body.get("reason") or "manual"
    if not ip:
        return jsonify({"error": "ip required"}), 400
    return jsonify(json_storage.add_to_blacklist(ip, reason)), 201


@core_bp.route("/api/reports", methods=["GET"])
def get_reports():
    data = get_all_entries(REPORTS_FILE)
    return jsonify(data), 200


@core_bp.route("/api/networks", methods=["GET"])
def get_networks():
    data = json_storage.get_networks()
    if not data:
        data = get_all_entries(NETWORKS_FILE)
    return jsonify(data), 200


@core_bp.route("/api/status", methods=["GET"])
def get_status():
    return jsonify(_status_payload()), 200


@core_bp.route("/api/start", methods=["POST"])
def start_ips():
    return _start_payload()


@core_bp.route("/api/stop", methods=["POST"])
def stop_ips():
    return _stop_payload()


@core_bp.route("/api/logs", methods=["GET"])
def api_logs():
    if request.args.get("format") == "json":
        return jsonify(get_events(limit=int(request.args.get("limit", 200))))
    return jsonify({"logs": format_text(), "status": _status_payload()["status"]})


@core_bp.route("/api/alerts", methods=["GET"])
def api_alerts():
    return jsonify(get_alerts(limit=int(request.args.get("limit", 100))))


@core_bp.route("/api/rules", methods=["GET", "POST"])
@jwt_required()
def api_rules():
    if request.method == "GET":
        return jsonify(list_rules())
    denied = _require_advanced()
    if denied:
        return denied
    body = request.json or {}
    return jsonify(upsert_rule(body)), 201


@core_bp.route("/api/rules/<int:rule_id>", methods=["PUT", "DELETE"])
@jwt_required()
def api_rule_item(rule_id):
    denied = _require_advanced()
    if denied:
        return denied
    if request.method == "DELETE":
        deleted = delete_rule(rule_id)
        if not deleted:
            return jsonify({"error": "Not found"}), 404
        return jsonify(deleted)
    body = request.json or {}
    body["id"] = rule_id
    return jsonify(upsert_rule(body))
