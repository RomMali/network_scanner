import os
import json
from backend.utils.json_handler import load_json
from collections import Counter
from datetime import datetime

# Paths
JSON_DB_PATH = r"C:\Users\Magshimim\Documents\magshimim\final\network_scanner\db\json_storage"
output_path = r"C:\Users\Magshimim\Documents\magshimim\final\network_scanner\frontend\GalacticGuard\Resources\Raw\dashboard.html"


def extract_logs(src_attacks_data):
    log = []
    for entry in src_attacks_data:
        log.append({
            "timestamp": entry.get("timestamp", ""),
            "source_ip": entry.get("source_ip", ""),
            "destination_ip": entry.get("destination_ip", ""),
            "attack_type": entry.get("attack_type", ""),
            "severity": entry.get("severity_level", "Unknown")
        })
    return log


def count_attack_types(src_attacks_data):
    counter = Counter()
    for entry in src_attacks_data:
        counter[entry.get("attack_type", "Unknown")] += 1
    return dict(counter)


def extract_activity_over_time(src_attacks_data):
    activity = Counter()
    for entry in src_attacks_data:
        timestamp = entry.get("timestamp")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                time_bucket = dt.strftime("%Y-%m-%d %H:%M")
                activity[time_bucket] += 1
            except ValueError:
                continue
    sorted_activity = sorted(activity.items())
    labels = [label for label, _ in sorted_activity]
    counts = [count for _, count in sorted_activity]
    return counts, labels


def extract_reports(src_reports_data):
    reports = []
    for report in src_reports_data:
        reports.append({
            "id": report.get("id", ""),
            "generated_at": report.get("generated_at", ""),
            "content": report.get("content", ""),
            "severity": report.get("severity_level", "Unknown"),
            "user_id": report.get("user_id", "")
        })
    return reports


def html_generator():
    # Load data
    attacks_path = os.path.join(JSON_DB_PATH, "attacks.json")
    reports_path = os.path.join(JSON_DB_PATH, "reports.json")

    attacks_data = load_json(attacks_path)
    reports_data = load_json(reports_path)

    logs = extract_logs(attacks_data)
    attack_types = count_attack_types(attacks_data)
    activity_counts, activity_labels = extract_activity_over_time(attacks_data)
    reports = extract_reports(reports_data)

    # Convert to JS-safe formats
    logs_rows = "\n".join(
        f"<tr><td>{log['timestamp']}</td><td>{log['source_ip']}</td><td>{log['destination_ip']}</td><td>{log['attack_type']}</td><td>{log['severity']}</td></tr>"
        for log in logs
    )
    reports_rows = "\n".join(
        f"<tr><td>{r['id']}</td><td>{r['generated_at']}</td><td>{r['user_id']}</td><td>{r['severity']}</td><td>{r['content']}</td></tr>"
        for r in reports
    )
    activity_labels_js = json.dumps(activity_labels)
    activity_counts_js = json.dumps(activity_counts)
    attack_type_labels_js = str(list(attack_types.keys()))
    attack_type_counts_js = str(list(attack_types.values()))

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GalacticGuard IPS Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ background-color: #f8f9fa; }}
        h1, h3 {{ color: #343a40; }}
        canvas {{ max-width: 100%; }}
    </style>
</head>
<body>
    <div class="container py-4">
        <h1 class="mb-4 text-center">GalacticGuard IPS Dashboard</h1>

        <h3>Attack Logs</h3>
        <table class="table table-bordered table-hover">
            <thead class="table-dark">
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Attack Type</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
                {logs_rows}
            </tbody>
        </table>

        <h3 class="mt-5">Attack Activity Over Time</h3>
        <canvas id="activity-chart" height="100"></canvas>

        <h3 class="mt-5">Attack Type Breakdown</h3>
        <canvas id="attack-pie-chart" height="200"></canvas>

        <h3 class="mt-5">Detailed Reports</h3>
        <table class="table table-bordered table-hover">
            <thead class="table-secondary">
                <tr>
                    <th>Report ID</th>
                    <th>Generated At</th>
                    <th>User ID</th>
                    <th>Severity</th>
                    <th>Content</th>
                </tr>
            </thead>
            <tbody>
                {reports_rows}
            </tbody>
        </table>
    </div>

    <script>
        // Attack Activity Line Chart
        new Chart(document.getElementById('activity-chart').getContext('2d'), {{
            type: 'line',
            data: {{
                labels: {activity_labels_js},
                datasets: [{{
                    label: 'Attacks',
                    data: {activity_counts_js},
                    borderColor: 'red',
                    backgroundColor: 'rgba(255, 0, 0, 0.1)',
                    fill: true
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: true
                    }}
                }}
            }}
        }});

        // Attack Types Pie Chart
        new Chart(document.getElementById('attack-pie-chart').getContext('2d'), {{
            type: 'pie',
            data: {{
                labels: {attack_type_labels_js},
                datasets: [{{
                    data: {attack_type_counts_js},
                    backgroundColor: ['#dc3545', '#ffc107', '#198754', '#0d6efd', '#6f42c1']
                }}]
            }},
            options: {{
                responsive: true
            }}
        }});
    </script>
</body>
</html>
"""

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Dashboard updated at {datetime.now().strftime('%H:%M:%S')}")


# Run the function when needed (timer script or manually)
if __name__ == "__main__":
    html_generator()

# Old HTML Template
v1 = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>IPS Dashboard</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            canvas {{
                max-width: 100%;
                height: auto;
            }}
        </style>
    </head>
    <body class="bg-light text-dark">
        <div class="container py-4">
            <h1 class="mb-4 text-center">Intrusion Prevention System Dashboard</h1>

            <!-- Attack Logs -->
            <h3>Attack Logs</h3>
            <table class="table table-striped table-hover" id="logs-table">
                <thead class="table-dark">
                    <tr>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Attack Type</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {{{{% for log in logs %}}}}
                    <tr>
                        <td>{{{{ log.timestamp }}}}</td>
                        <td>{{{{ log.source_ip }}}}</td>
                        <td>{{{{ log.destination_ip }}}}</td>
                        <td>{{{{ log.attack_type }}}}</td>
                        <td>{{{{ log.severity }}}}</td>
                    </tr>
                    {{{{% endfor %}}}}
                </tbody>
            </table>

            <!-- Detailed Reports -->
            <h3 class="mt-5">Detailed Reports</h3>
            <div id="reports-section">
                <details class="mb-3">
                    <summary><strong>Port Scan Detected - 192.168.1.101</strong></summary>
                    <ul>
                        <li><strong>Time:</strong> 2025-05-06 14:32:01</li>
                        <li><strong>Protocol:</strong> TCP</li>
                        <li><strong>Payload:</strong> SYN packets</li>
                        <li><strong>Response Action:</strong> IP blocked</li>
                    </ul>
                </details>
            </div>

            <!-- Attack Activity -->
            <h3 class="mt-5">Attack Activity Over Time</h3>
            <canvas id="activity-chart" height="100"></canvas>

            <!-- Attack Type Pie Chart -->
            <h3 class="mt-5">Attack Type Breakdown</h3>
            <canvas id="attack-pie-chart" height="200"></canvas>
        </div>

        <script>
            const activityCtx = document.getElementById('activity-chart').getContext('2d');
            new Chart(activityCtx, {{
                type: 'line',
                data: {{
                    labels: ['14:00', '14:15', '14:30', '14:45'],
                    datasets: [{{
                        label: 'Attacks',
                        data: {{{{ attack_activity }}}}, 
                        borderColor: 'red',
                        fill: false
                    }}]
                }},
                options: {{
                    responsive: true
                }}
            }});

            const pieCtx = document.getElementById('attack-pie-chart').getContext('2d');
            new Chart(pieCtx, {{
                type: 'pie',
                data: {{
                    labels: {{{{ attack_types.keys() | tojson }}}}, 
                    datasets: [{{
                        data: {{{{ attack_types.values() | tojson }}}}, 
                        backgroundColor: ['#dc3545', '#ffc107', '#198754']
                    }}]
                }},
                options: {{
                    responsive: true
                }}
            }});
        </script>
    </body>
    </html>
    """
