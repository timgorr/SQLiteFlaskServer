from flask import Flask, request, jsonify, g
import sqlite3
from jsonschema import validate, ValidationError

app = Flask(__name__)

DATABASE = 'database.db'

schema = {
    "$schema": "https://json-schema.org/draft/2020-12-schema",
    "description": "This document records the details of an incident",
    "title": "Record of a SIEM Incident",
    "type": "object",
    "properties": {
        "id": {
            "description": "A unique identifier for the report of an incident",
            "type": "string"     # id drin behalten für den primary key
        },
        "report_category": {
            "description": "The category of the report: an attack on a system.",
            "type": "string"
        },
        "report_type": {
            "description": "The type of the report.",
            "type": "string"
        },
        "timestamp": {
            "description": "The timestamp when the attack took place.",
            "type": "string"
        },
        "source_key": {
            "description": "The type of the reported object: an IP.",
            "type": "string"
        },
        "source_value": {
            "description": "The IP of the system performing the attack.",
            "type": "string"
        },
        "confidence_level": {
            "description": "The level of confidence put into the accuracy of the report..",
            "type": "number"
        },
        "version": {
            "description": "The version number of the data format used for the report.",
            "type": "integer"
        },
        "report_subcategory": {
            "description": "The type of attack performed.",
            "type": "string"
        },
        "ip_protocol_number": {
            "description": "The IANA assigned decimal internet protocol number of the attack connection.",
            "type": "integer"
        },
        "ip_version": {
            "description": "The IP version of the attack connection.",
            "type": "integer"
        },

    },
    "required": ["id", "report_type", "timestamp"]
}

# need: correct descriptions, correct required properties and type max min etc.



@app.route('/api/report', methods=['POST'])
def handle_report():
    data = request.get_json()
    try:
        validate(instance=data, schema=schema)  # Daten validieren
        db = get_db()
        db.execute('INSERT INTO reports (id, report_category, report_type, timestamp, source_key, source_value, confidence_level, version, report_subcategory, ip_protocol_number, ip_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                   (data['id'], data['report_category'], data['report_type'], data['timestamp'], data['source_key'],
                    data['source_value'], data['confidence_level'], data['version'], data['report_subcategory'],
                    data['ip_protocol_number'], data['ip_version']))
        db.commit()
        return jsonify({"status": "success", "message": "Report added successfully"}), 200
    except ValidationError as ve:
        return jsonify({"error": "Invalid data, " + str(ve)}), 400
    except sqlite3.Error as e:
        return jsonify({"error": "Database error, " + str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Error, " + str(e)}), 500

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
                        confidence_level REAL,  # REAL ist float oder int in SQLite
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

@app.route('/add', methods=['POST'])
def add_entry():
    content = request.json['content']
    db = get_db()
    db.execute('INSERT INTO entries (content) VALUES (?)', (content,))
    db.commit()
    return jsonify({"status": "success", "message": "Entry added"})

@app.route('/entries', methods=['GET'])
def view_entries():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM entries')
    entries = cursor.fetchall()
    return jsonify({"entries": entries})

if __name__ == '__main__':
	init_db()
	app.run(host='0.0.0.0', port=5000, debug=True)
