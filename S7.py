
from flask import Flask, jsonify
import sqlite3
import json
import os
from jsonschema import validate, ValidationError

app = Flask(__name__)

DATABASE = 'database.db'
JSON_FOLDER = 'json_data'  # Folder containing JSON files

# JSON schema for validation
schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "This document records the details of an incident",
    "title": "Record of a SIEM Incident",
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "discovery_date": {"type": "string"},
        "vendor": {"type": "string"},
        "product": {"type": "string"},
        "item_number": {"type": "string"}
    },
    "required": ["id", "discovery_date", "vendor", "product", "item_number"]
}

@app.route('/')
def home():
    return "Moin!"

@app.route('/favicon.ico')
def favicon():
    return '', 204
    # return app.send_static_file('favicon.ico')

def get_db():
    db = sqlite3.connect(DATABASE)
    return db

# Initialize the database
def init_db():
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, discovery_date TEXT, vendor TEXT, product TEXT, item_number TEXT)')
        db.commit()

# Validate and upload JSON files
def validate_and_upload_json_files():
    for filename in os.listdir(JSON_FOLDER):
        if filename.endswith('.json'):
            file_path = os.path.join(JSON_FOLDER, filename)
            with open(file_path, 'r') as file:
                try:
                    data = json.load(file)
                    validate(instance=data, schema=schema)
                    insert_into_db(data)
                except (json.JSONDecodeError, ValidationError) as e:
                    print(f"Error in file {filename}: {e}")
                except sqlite3.IntegrityError as e:
                    print(f"Database error for file {filename}: {e}")

def insert_into_db(data):
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('INSERT INTO incidents (id, discovery_date, vendor, product, item_number) VALUES (?, ?, ?, ?, ?)', 
                       (data['id'], data['discovery_date'], data['vendor'], data['product'], data['item_number']))
        db.commit()

@app.route('/upload-json-files', methods=['POST'])
def upload_json_files():
    validate_and_upload_json_files()
    return jsonify({"message": "JSON files validated and uploaded to the database."}), 200

if __name__ == '__main__':
	init_db()
	app.run(host='0.0.0.0', port=5001, debug=True)
