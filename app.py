from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_wtf import CSRFProtect
import sqlite3
import os
import json
import logging
from jsonschema import validate, ValidationError

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')  # Use an environment variable for the secret key
app.config['DATABASE'] = os.getenv('DATABASE_PATH', 'database.db')  # Use an environment variable for the database path
app.config['JSON_FOLDER'] = os.getenv('JSON_FOLDER', 'json_data')  # Folder containing JSON files

# Enable CSRF Protection
csrf = CSRFProtect(app)

# Set secure cookie options
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True  # Set to True if using HTTPS
)

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

def get_db():
    # Establishes a database connection
    conn = sqlite3.connect(app.config['DATABASE'])
    return conn

def init_db():
    # Initializes the database if it doesn't exist
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

@app.route('/')
def home():
    # Render the home page
    return render_template('index.html')

@app.route('/upload-page')
def upload_page():
    # Render the upload page
    return render_template('upload.html')

@app.route('/view-database')
def view_database():
    # Fetch all entries from the database and render them
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

@app.route('/upload-json-files', methods=['POST'])
@csrf.exempt  # Disable CSRF for this route if you're calling it via AJAX, but use with caution
def upload_json_files():
    json_folder = app.config['JSON_FOLDER']
    if not os.path.exists(json_folder):
        return jsonify({"message": "JSON folder not found."}), 404

    json_files = [f for f in os.listdir(json_folder) if f.endswith('.json')]
    if not json_files:
        return jsonify({"message": "No JSON files to upload."}), 404

    success = True
    for filename in json_files:
        try:
            with open(os.path.join(json_folder, filename), 'r') as file:
                data = json.load(file)
                validate(instance=data, schema=schema)
                insert_into_db(data)
        except (json.JSONDecodeError, ValidationError) as e:
            logging.error(f"Validation error in file {filename}: {e}")
            success = False
        except sqlite3.IntegrityError:
            logging.error(f"Integrity error: Duplicate ID in file {filename}")
            success = False

    if success:
        return jsonify({"message": "All JSON files validated and uploaded."}), 200
    return jsonify({"message": "Errors occurred while uploading JSON files."}), 400

def validate_and_upload_json_files():
    # Validates and uploads JSON files from the specified folder
    json_folder = app.config['JSON_FOLDER']
    if not os.path.exists(json_folder):
        logging.error("JSON folder not found.")
        return "JSON folder not found.", False  # Return error message and failure

    json_files = [f for f in os.listdir(json_folder) if f.endswith('.json')]

    if not json_files:
        logging.info("No JSON files to upload. All files are already processed or the folder is empty.")
        return "No JSON files to upload.", False

    # Flags to keep track of what happened
    has_successful_upload = False
    has_duplicates = False
    has_validation_errors = False

    # Process each file
    for filename in json_files:
        file_path = os.path.join(json_folder, filename)
        logging.info(f"Processing file: {file_path}")
        with open(file_path, 'r') as file:
            try:
                data = json.load(file)
                validate(instance=data, schema=schema)
                if insert_into_db(data):
                    has_successful_upload = True  # Successfully uploaded at least one file
                else:
                    logging.info(f"File {filename} is a duplicate.")
                    has_duplicates = True  # Mark that at least one file is a duplicate
            except (json.JSONDecodeError, ValidationError) as e:
                logging.error(f"Validation error in file {filename}: {e}")
                has_validation_errors = True  # At least one file had a validation error

    # Construct the response message based on the results
    if has_successful_upload:
        if has_validation_errors:
            return "Some JSON files were uploaded successfully, but some files failed validation.", True
        return "All new JSON files validated and uploaded successfully.", True
    elif has_duplicates and not has_successful_upload and not has_validation_errors:
        return "All JSON files are already uploaded (duplicates).", False
    elif has_validation_errors and not has_successful_upload:
        return "All JSON files failed validation.", False
    else:
        return "Errors occurred while uploading JSON files.", False

# doesnt work, not distinguishing between errors - its always errors occured while uploading json files even when just all json files been uploaded


def insert_into_db(data):
    # Inserts a new record into the incidents table
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO incidents (id, discovery_date, vendor, product, item_number) '
                'VALUES (?, ?, ?, ?, ?)',
                (data['id'], data['discovery_date'], data['vendor'], data['product'], data['item_number'])
            )
            db.commit()
        return True  # Insert was successful
    except sqlite3.IntegrityError:
        logging.error(f"Duplicate entry: {data['id']}")
        return False  # Duplicate found


@app.route('/reset-database', methods=['POST'])
@csrf.exempt  # Disable CSRF for this route if you're calling it via AJAX, but use with caution
def reset_database():
    # Clears all data in the incidents table
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute('DELETE FROM incidents')
            db.commit()
        return jsonify({"message": "Database has been reset."}), 200
    except sqlite3.Error as e:
        logging.error(f"Database reset failed: {e}")
        return jsonify({"message": "An error occurred while resetting the database."}), 500

if __name__ == '__main__':
    init_db()  # Ensure the database is initialized
    app.run(host='0.0.0.0', port=5001, debug=True)
