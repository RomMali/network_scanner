import json
from pathlib import Path

# Define the data directory where JSON files are stored
DATA_DIR = Path(__file__).resolve().parents[2] / "db" / "json_storage"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_json(filename):
    file_path = DATA_DIR / filename
    if not file_path.exists():
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)  # Initialize with empty list
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(filename, data):
    with open(DATA_DIR / filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
