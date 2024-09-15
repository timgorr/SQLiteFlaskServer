from flask import Flask, jsonify, render_template, request, send_from_directory
import sqlite3
import json
import os
import logging
from jsonschema import validate, ValidationError

app = Flask(__name__)

# Configuration
DATABASE = 'database.db'
JSON_FOLDER = 'json_data'  # Folder containing JSON files

# Set up logging
logging.basicConfig(level=logging.INFO)

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
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

def get_db():
    return sqlite3.connect(DATABASE)

# Initialize the database
def init_db():
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS incidents ('
            'id TEXT PRIMARY KEY, '
            'discovery_date TEXT, '
            'vendor TEXT, '
            'product TEXT, '
            'item_number TEXT)'
        )
        db.commit()

def validate_and_upload_json_files():
    if not os.path.exists(JSON_FOLDER):
        logging.error("JSON folder not found.")
        return "JSON folder not found.", False  # Indicate failure

    # Get a list of all JSON files
    json_files = [f for f in os.listdir(JSON_FOLDER) if f.endswith('.json')]
    
    # Check if there are no JSON files to process
    if not json_files:
        logging.info("No JSON files to upload. The folder is empty.")
        return "No JSON files to upload. The folder is empty.", False

    success = True  # To track overall success
    files_processed = False  # Track if any files were processed

    for filename in json_files:
        file_path = os.path.join(JSON_FOLDER, filename)
        logging.info(f"Processing file: {file_path}")
        with open(file_path, 'r') as file:
            try:
                data = json.load(file)
                validate(instance=data, schema=schema)
                insert_into_db(data)
                files_processed = True  # At least one file was processed
            except (json.JSONDecodeError, ValidationError) as e:
                logging.error(f"Error in file {filename}: {e}")
                success = False  # Indicate failure
            except sqlite3.IntegrityError as e:
                logging.error(f"Database error for file {filename}: {e}")
                success = False  # Indicate failure

    # Return the appropriate message based on the processing outcome
    if not files_processed:
        return "No new JSON files were found for upload.", False  # No files processed
    elif success:
        return "All JSON files validated and uploaded to the database.", True
    else:
        return "One or more JSON files failed validation or upload.", False


def insert_into_db(data):
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO incidents (id, discovery_date, vendor, product, item_number) '
                'VALUES (?, ?, ?, ?, ?)',
                (data['id'], data['discovery_date'], data['vendor'], data['product'], data['item_number'])
            )
            db.commit()
    except sqlite3.IntegrityError as e:
        logging.error(f"Database error during insertion: {e}")
        raise

@app.route('/upload-json-files', methods=['POST'])
def upload_json_files():
    # Call the function and use its return values
    message, success = validate_and_upload_json_files()
    status_code = 200 if success else 400
    return jsonify({"message": message}), status_code

@app.route('/view-database')
def view_database():
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute('SELECT id, discovery_date, vendor, product, item_number FROM incidents')
            rows = cursor.fetchall()
            data = [
                {"id": row[0], "discovery_date": row[1], "vendor": row[2], "product": row[3], "item_number": row[4]}
                for row in rows
            ]
            return render_template('database_view.html', data=data)
    except sqlite3.Error as e:
        logging.error(f"Database query failed: {e}")
        return jsonify({"message": "An error occurred while fetching the database contents."}), 500
    

@app.route('/reset-database', methods=['POST'])
def reset_database():
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute('DELETE FROM incidents')  # Clear all entries in the incidents table
            db.commit()
        return jsonify({"message": "Database has been reset."}), 200
    except sqlite3.Error as e:
        logging.error(f"Database reset failed: {e}")
        return jsonify({"message": "An error occurred while resetting the database."}), 500


@app.route('/upload-page')
def upload_page():
    return render_template('upload.html')

if __name__ == '__main__':
    init_db()  # Ensure the database is initialized
    app.run(host='0.0.0.0', port=5001, debug=True)
