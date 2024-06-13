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
            "type": "string"
        },
        "discovery_date": {
            "description": "Timestamp of the discovery of the incident",
            "type": "string"
        },
        "vendor": {
            "description": "The vendor of the product",
            "type": "string"
        },
        "product": {
            "description": "The full name of the product",
            "type": "string"
        },
        "item_number": {
            "description": "The stock keeping unit, article or item number of the product.",
            "type": "string"
        },
        "product_version": {
            "description": "The version of the given product.",
            "type": "string"
        },
        "firmware": {
            "description": "The firmware that is being used on the product.",
            "type": "string"
        },
        "summary": {
            "description": "A summary of the incident.",
            "type": "string"
        }
    },
    "required": ["id", "discovery_date", "summary"]
}



@app.route('/api/report', methods=['POST'])
def handle_report():
    data = request.get_json()
    try:
        validate(instance=data, schema=schema)  # Daten validieren
        db = get_db()
        db.execute('INSERT INTO reports (id, discovery_date, vendor, product, item_number, product_version, firmware, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                   (data['id'], data['discovery_date'], data['vendor'], data['product'], data['item_number'],
                    data['product_version'], data['firmware'], data['summary']))
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
                        discovery_date TEXT,
                        vendor TEXT,
                        product TEXT,
                        item_number TEXT,
                        product_version TEXT,
                        firmware TEXT,
                        summary TEXT
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
