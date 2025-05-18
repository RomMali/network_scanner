from flask import Flask, jsonify
import os

LOG_FILE = "logs/attacks.log"
app = Flask(__name__)

@app.route("/logs", methods=["GET"])
def get_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify([])  # Return empty list if no logs
    with open(LOG_FILE, "r") as file:
        logs = file.readlines()
    return jsonify([log.strip() for log in logs])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
