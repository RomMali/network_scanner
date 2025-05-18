from flask import Blueprint, jsonify, request
import threading
import platform
from scapy.all import get_if_list, get_if_hwaddr
from backend.logic.packet_sniffer import start_sniffing
from backend.logic.blocker import block_ip
from db.json_storage import json_storage
from db.mysql_conn import validate_user
from db.json_storage.json_storage import (
    ATTACKS_FILE,
    BLACKLIST_FILE,
    REPORTS_FILE,
    NETWORKS_FILE,
    get_all_entries
)

core_bp = Blueprint("core", __name__)
sniffer_running = False


def get_network_interface():
    os_name = platform.system()
    if os_name == "Linux":
        return "eth0"
    elif os_name == "Windows":
        available_interfaces = get_if_list()
        for interface in available_interfaces:
            try:
                mac_address = get_if_hwaddr(interface)
                if mac_address != "00:00:00:00:00:00":
                    return interface
            except Exception:
                continue
        raise RuntimeError("No valid network interface found!")
    else:
        raise RuntimeError(f"Unsupported OS: {os_name}")


@core_bp.route("/start", methods=["GET"])
def start_sniffer():
    global sniffer_running
    if not sniffer_running:
        try:
            interface = get_network_interface()
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 400

        sniffer_thread = threading.Thread(target=start_sniffing, args=(interface, block_ip), daemon=True)
        sniffer_thread.start()
        sniffer_running = True
        return jsonify({"status": "Sniffer started"})
    return jsonify({"status": "Sniffer already running"}), 400


@core_bp.route("/stop", methods=["GET"])
def stop_sniffer():
    global sniffer_running
    if sniffer_running:
        sniffer_running = False
        return jsonify({"status": "Sniffer stopped"})
    return jsonify({"status": "Sniffer not running"}), 400


@core_bp.route("/status", methods=["GET"])
def service_status():
    return jsonify({"status": "running" if sniffer_running else "stopped"})


# --------------------- JSON API ROUTES ----------------------

@core_bp.route("/attacks", methods=["GET", "POST"])
def manage_attacks():
    if request.method == "GET":
        return jsonify(json_storage.get_attacks())
    else:
        return jsonify(json_storage.add_attack(request.json)), 201


@core_bp.route("/networks", methods=["GET", "POST"])
def manage_networks():
    if request.method == "GET":
        return jsonify(json_storage.get_networks())
    else:
        return jsonify(json_storage.add_network(request.json)), 201


@core_bp.route("/reports", methods=["GET", "POST"])
def manage_reports():
    username = request.args.get("username")
    password = request.args.get("password_hash")
    user = validate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 403

    if request.method == "GET":
        return jsonify(json_storage.get_reports(user["id"]))
    else:
        return jsonify(json_storage.add_report(request.json, user["id"])), 201


@core_bp.route("/network/<name>", methods=["PUT", "DELETE"])
def handle_network_by_name(name):
    if request.method == "PUT":
        updated = json_storage.update_network_by_name(name, request.json)
        return (jsonify(updated), 200) if updated else ({"error": "Not found"}, 404)
    else:
        deleted = json_storage.delete_network_by_name(name)
        return (jsonify(deleted), 200) if deleted else ({"error": "Not found"}, 404)


@core_bp.route("/blacklist/<ip>", methods=["PUT", "DELETE"])
def handle_blacklist_by_ip(ip):
    if request.method == "PUT":
        updated = json_storage.update_blacklist_by_ip(ip, request.json)
        return (jsonify(updated), 200) if updated else ({"error": "Not found"}, 404)
    else:
        deleted = json_storage.delete_blacklist_by_ip(ip)
        return (jsonify(deleted), 200) if deleted else ({"error": "Not found"}, 404)


# --------------------- API ENTRY POINTS ----------------------

@core_bp.route("/api/attacks", methods=["GET"])
def get_attacks():
    data = get_all_entries(ATTACKS_FILE)
    return jsonify(data), 200


@core_bp.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    data = get_all_entries(BLACKLIST_FILE)
    return jsonify(data), 200


@core_bp.route("/api/reports", methods=["GET"])
def get_reports():
    data = get_all_entries(REPORTS_FILE)
    return jsonify(data), 200


@core_bp.route("/api/networks", methods=["GET"])
def get_networks():
    data = get_all_entries(NETWORKS_FILE)
    return jsonify(data), 200


@core_bp.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({"status": "running"}), 200


@core_bp.route("/api/start", methods=["POST"])
def start_ips():
    return jsonify({"message": "IPS started"}), 200


@core_bp.route("/api/stop", methods=["POST"])
def stop_ips():
    return jsonify({"message": "IPS stopped"}), 200
