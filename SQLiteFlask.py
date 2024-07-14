from flask import Flask, request, jsonify, g
import sqlite3
from jsonschema import validate, ValidationError

app = Flask(__name__)

DATABASE = 'database.db'


schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "This document records the details of an incident",
    "title": "Record of a SIEM Incident",
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "report_category": {"type": "string", "enum": ["eu.acdc.attack"]},
        "report_type": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "source_key": {"type": "string", "enum": ["ip"]},
        "source_value": {"type": "string"},
        "confidence_level": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "version": {"type": "integer", "enum": [2]},
        "report_subcategory": {"type": "string", "enum": ["abuse", "abuse.spam", "compromise", "data", "dos", "dos.dns", "dos.http", "dos.tcp", "dos.udp", "login", "malware", "scan", "other"]},
        "ip_protocol_number": {"type": "integer", "minimum": 0, "maximum": 255},
        "ip_version": {"type": "integer", "enum": [4, 6]}
    },
    "required": ["id", "report_category", "timestamp", "source_key", "source_value", "confidence_level", "version", "ip_protocol_number", "ip_version"]
}

@app.route('/api/report', methods=['POST'])
def handle_report():
    data = request.get_json()
    try:
        validate(instance=data, schema=schema)  # Validate data
        db = get_db()
        db.execute('''
            INSERT INTO reports (id, report_category, report_type, timestamp, source_key, source_value, 
            confidence_level, version, report_subcategory, ip_protocol_number, ip_version) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (data['id'], data['report_category'], data['report_type'], data['timestamp'], data['source_key'],
            data['source_value'], data['confidence_level'], data['version'], data['report_subcategory'],
            data['ip_protocol_number'], data['ip_version']))
        db.commit()
        return jsonify({"status": "success", "message": "Report added successfully"}), 200
    except ValidationError as ve:
        return jsonify({"error": "Invalid data: " + str(ve)}), 400
    except sqlite3.Error as e:
        return jsonify({"error": "Database error: " + str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Unexpected error: " + str(e)}), 500

@app.route('/reports', methods=['GET'])
def view_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM reports')
    reports = cursor.fetchall()
    return jsonify({"reports": reports})

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None and hasattr(db, 'close'):
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports(
                id TEXT PRIMARY KEY,
                report_category TEXT,
                report_type TEXT,
                timestamp TEXT,
                source_key TEXT,
                source_value TEXT,
                confidence_level REAL,
                version INTEGER,
                report_subcategory TEXT,
                ip_protocol_number INTEGER,
                ip_version INTEGER
            )
        """)
        db.commit()

@app.route('/')
def home():
    return "Welcome to the SQLite3 Flask App!"

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

# example:
# curl -X POST http://10.0.0.101:5000/api/report -H "Content-Type: application/json" -d '{
#  "id": "unique-reports-id-1234",
#  "report_category": "eu.acdc.attack",
#  "report_type": "Attempted SQL injection",
#  "timestamp": "2024-07-14T12:00:00Z",
#  "source_key": "ip",
#  "source_value": "192.168.1.1",
#  "confidence_level": 0.9,
#  "version": 2,
#  "report_subcategory": "dos.http",
#  "ip_protocol_number": 6,
#  "ip_version": 4
# }'
