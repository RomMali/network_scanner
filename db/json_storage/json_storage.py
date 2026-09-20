from backend.utils.json_handler import load_json, save_json
from datetime import datetime
import json
import os

ATTACKS_FILE = "attacks.json"
REPORTS_FILE = "reports.json"
NETWORKS_FILE = "networks.json"
BLACKLIST_FILE = "blacklist.json"

REQUIRED_FIELDS = {
    BLACKLIST_FILE: ["source_ip", "reason", "blocked_at"],
    ATTACKS_FILE: ["type", "source_ip", "timestamp", "severity"],
    NETWORKS_FILE: ["name", "ip", "created_at"],
    REPORTS_FILE: ["title", "content", "user_id", "created_at"]
}


def validate_entry(data, required_fields):
    """
    Validate that all required fields exist in the data and are not empty.
    Returns True if valid, False if not.
    """
    for field in required_fields:
        if field not in data or data[field] in [None, ""]:
            return False
    return True


def select_entry_id_by_field(filename, field, value):
    data = load_json(filename)
    for entry in data:
        if entry.get(field) == value:
            return entry.get("id")
    return None


def _add_entry(filename, new_entry):
    required_fields = REQUIRED_FIELDS.get(filename)
    if required_fields:
        if not validate_entry(new_entry, required_fields):
            raise ValueError(f"Missing required fields: {required_fields}")

    data = load_json(filename)
    new_entry["id"] = (data[-1]["id"] + 1) if data else 1
    data.append(new_entry)
    save_json(filename, data)
    return new_entry


def _update_entry_by_id(filename, entry_id, new_data):
    data = load_json(filename)
    for i, entry in enumerate(data):
        if entry.get("id") == entry_id:
            data[i].update(new_data)
            save_json(filename, data)
            return data[i]
    return None


def _delete_entry_by_id(filename, entry_id):
    data = load_json(filename)
    for i, entry in enumerate(data):
        if entry.get("id") == entry_id:
            deleted = data.pop(i)
            save_json(filename, data)
            return deleted
    return None


def _get_data(filename):
    return load_json(filename)


def _filter_by_user(filename, user_id):
    data = load_json(filename)
    return [r for r in data if r.get("user_id") == user_id]


def select_network_id_by_name(name):
    return select_entry_id_by_field(NETWORKS_FILE, "name", name)


def select_blacklist_id_by_ip(ip):
    for entry in get_blacklist():
        if entry.get("ip") == ip or entry.get("source_ip") == ip:
            return entry.get("id")
    return None


def get_attacks():
    return _get_data(ATTACKS_FILE)


def add_attack(attack_data):
    return _add_entry(ATTACKS_FILE, attack_data)


def get_networks():
    return _get_data(NETWORKS_FILE)


def add_network(network_data):
    return _add_entry(NETWORKS_FILE, network_data)


def get_reports(user_id):
    return _filter_by_user(REPORTS_FILE, user_id)


def add_report(report_data, user_id):
    report_data["user_id"] = user_id
    return _add_entry(REPORTS_FILE, report_data)


def _as_blacklist_list(data):
    if isinstance(data, dict):
        rows = []
        for i, (ip, meta) in enumerate(data.items(), start=1):
            row = {"id": i, "ip": ip}
            if isinstance(meta, dict):
                row.update(meta)
            else:
                row["reason"] = str(meta)
            rows.append(row)
        return rows
    if isinstance(data, list):
        return data
    return []


def get_blacklist():
    return _as_blacklist_list(load_json(BLACKLIST_FILE))


def iter_blacklist_ips():
    for entry in get_blacklist():
        ip = entry.get("ip") or entry.get("source_ip")
        if ip:
            yield ip


def add_to_blacklist(ip, reason):
    data = _as_blacklist_list(load_json(BLACKLIST_FILE))
    for entry in data:
        if entry.get("ip") == ip:
            entry["reason"] = reason
            entry["timestamp"] = datetime.utcnow().isoformat()
            save_json(BLACKLIST_FILE, data)
            return entry
    entry = {
        "id": (max((int(e.get("id") or 0) for e in data), default=0) + 1),
        "ip": ip,
        "source_ip": ip,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat(),
        "blocked_at": datetime.utcnow().isoformat(),
    }
    data.append(entry)
    save_json(BLACKLIST_FILE, data)
    return entry


def update_network_by_name(name, new_data):
    entry_id = select_network_id_by_name(name)
    if entry_id:
        return _update_entry_by_id(NETWORKS_FILE, entry_id, new_data)
    return None


def delete_network_by_name(name):
    entry_id = select_network_id_by_name(name)
    if entry_id:
        return _delete_entry_by_id(NETWORKS_FILE, entry_id)
    return None


def update_blacklist_by_ip(ip, new_data):
    data = _as_blacklist_list(load_json(BLACKLIST_FILE))
    for i, entry in enumerate(data):
        if entry.get("ip") == ip or entry.get("source_ip") == ip:
            data[i].update(new_data)
            data[i]["ip"] = ip
            save_json(BLACKLIST_FILE, data)
            return data[i]
    return None


def delete_blacklist_by_ip(ip):
    data = _as_blacklist_list(load_json(BLACKLIST_FILE))
    deleted = None
    kept = []
    for entry in data:
        if entry.get("ip") == ip or entry.get("source_ip") == ip:
            deleted = entry
        else:
            kept.append(entry)
    if deleted is not None:
        save_json(BLACKLIST_FILE, kept)
    return deleted


def get_all_entries(file_path):
    """Reads all entries from a given JSON file and returns them as a list."""
    if not os.path.exists(file_path):
        return []

    with open(file_path, 'r') as file:
        try:
            data = json.load(file)
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            return []


def load_attacks():
    return load_json(ATTACKS_FILE)


def load_blacklist():
    return load_json(BLACKLIST_FILE)


def load_networks():
    return load_json(NETWORKS_FILE)


def load_reports():
    return load_json(REPORTS_FILE)
