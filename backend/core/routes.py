from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt, jwt_required, verify_jwt_in_request

from backend.logic.event_log import format_text, query_events
from backend.logic.heuristics import engine as heuristics_engine
from backend.logic.ml_pipeline import get_alerts
from backend.logic.nfqueue_worker import worker
from backend.logic.threat_intel import manager as threat_intel
from backend.logic.rules import (
    approve_ml_proposal,
    delete_rule,
    list_ml_proposals,
    list_rules,
    reject_ml_proposal,
    upsert_rule,
)
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
        return jsonify({"status": "running", **result}), 200
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
def start_ips_legacy():
    return _start_payload()


@core_bp.route("/stop", methods=["GET"])
def stop_ips_legacy():
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
    if request.args.get("format") == "text":
        return jsonify({"logs": format_text(), "status": _status_payload()["status"]})
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    limit = min(max(limit, 1), 1000)
    offset = max(offset, 0)
    items, total = query_events(
        action=request.args.get("action"),
        src_ip=request.args.get("src_ip"),
        rule_id=request.args.get("rule_id"),
        limit=limit,
        offset=offset,
    )
    return jsonify(
        {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


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


@core_bp.route("/api/heuristics", methods=["GET"])
def api_heuristics_get():
    return jsonify(heuristics_engine.snapshot()), 200


@core_bp.route("/api/heuristics", methods=["PUT"])
@jwt_required()
def api_heuristics_put():
    denied = _require_advanced()
    if denied:
        return denied
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    try:
        return jsonify(heuristics_engine.update_config(body)), 200
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@core_bp.route("/api/ml/proposals", methods=["GET"])
def api_ml_proposals():
    return jsonify(list_ml_proposals()), 200


@core_bp.route("/api/ml/proposals/<rule_id>/approve", methods=["POST"])
@jwt_required()
def api_ml_proposal_approve(rule_id):
    denied = _require_advanced()
    if denied:
        return denied
    updated = approve_ml_proposal(rule_id)
    if not updated:
        return jsonify({"error": "Not found"}), 404
    return jsonify(updated), 200


@core_bp.route("/api/ml/proposals/<rule_id>/reject", methods=["POST"])
@jwt_required()
def api_ml_proposal_reject(rule_id):
    denied = _require_advanced()
    if denied:
        return denied
    deleted = reject_ml_proposal(rule_id)
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify(deleted), 200


@core_bp.route("/api/threat-intel/status", methods=["GET"])
def api_threat_intel_status():
    return jsonify(threat_intel.status()), 200


@core_bp.route("/api/threat-intel/refresh", methods=["POST"])
@jwt_required()
def api_threat_intel_refresh():
    denied = _require_advanced()
    if denied:
        return denied
    try:
        return jsonify(threat_intel.refresh_feeds()), 200
    except Exception as exc:
        return jsonify({"error": str(exc), **threat_intel.status()}), 502
