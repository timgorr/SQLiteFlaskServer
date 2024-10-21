from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_wtf import CSRFProtect
import sqlite3
import os
import json
import logging
from jsonschema import validate, ValidationError, FormatChecker
# from markupsafe import Markup

app = Flask(__name__)


app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')  # env var for secret key
app.config['DATABASE'] = os.getenv('DATABASE_PATH', 'database.db')  # env var for database path
# app.config['JSON_FOLDER'] = '/mnt/client_data'  # specified folder with JSON files on remote server

# if CSRF protection needed (Flask-WTF)
csrf = CSRFProtect(app)



app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True  
)

# logging
logging.basicConfig(level=logging.INFO)

# JSON schema
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
        "report_subcategory": {
            "type": "string",
            "enum": ["abuse", "abuse.spam", "compromise", "data", "dos", "dos.dns", "dos.http", "dos.tcp", "dos.udp",
                     "login", "malware", "scan", "other"]
        },
        "ip_protocol_number": {"type": "integer", "minimum": 0, "maximum": 255},
        "ip_version": {"type": "integer", "enum": [4, 6]}
    },
    "required": ["id", "report_category", "timestamp", "source_key", "source_value", "confidence_level", "version",
                 "ip_protocol_number", "ip_version"]
}

def get_db():
    # database connection
    conn = sqlite3.connect(app.config['DATABASE'])
    return conn

@app.route('/favicon.ico')
def favicon():
    return '', 204 

def init_db():
    with get_db() as db:
        cursor = db.cursor()
        # Drop the table if it exists to avoid conflicts with the new schema
        cursor.execute('DROP TABLE IF EXISTS incidents')
        
        # table creation
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS incidents ('
            'id TEXT PRIMARY KEY, '
            'report_category TEXT, '
            'report_type TEXT, '
            'timestamp TEXT, '
            'source_key TEXT, '
            'source_value TEXT, '
            'confidence_level REAL, '
            'version INTEGER, '
            'report_subcategory TEXT, '
            'ip_protocol_number INTEGER, '
            'ip_version INTEGER)'
        )
        db.commit()


# @app.route('/')
# def home():
#     # home page Render
#     return render_template('index.html')

# @app.route('/upload-page')
# def upload_page():
#     # upload page render
#     return render_template('upload.html')

@app.route('/')
def view_database():
    # Fetch and render of all database entries
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute('SELECT id, report_category, report_type, timestamp, source_key, source_value, confidence_level, version, report_subcategory, ip_protocol_number, ip_version FROM incidents')
            rows = cursor.fetchall()
            data = [
                {
                    "id": row[0],
                    "report_category": row[1],
                    "report_type": row[2],
                    "timestamp": row[3],
                    "source_key": row[4],
                    "source_value": row[5],
                    "confidence_level": row[6],
                    "version": row[7],
                    "report_subcategory": row[8],
                    "ip_protocol_number": row[9],
                    "ip_version": row[10]
                } for row in rows
            ]
        return render_template('index.html', data=data)
    except sqlite3.Error as e:
        logging.error(f"Database query failed: {e}")
        return jsonify({"message": f"An error occurred while fetching the database contents: {e}"}), 500

def insert_into_db(data):
    # insert of new record into incidents table
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO incidents (id, report_category, report_type, timestamp, source_key, source_value, confidence_level, version, report_subcategory, ip_protocol_number, ip_version) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    data['id'],
                    data['report_category'],
                    data.get('report_type'),  # report_type is optional
                    data['timestamp'],
                    data['source_key'],
                    data['source_value'],
                    data['confidence_level'],
                    data['version'],
                    data.get('report_subcategory'),  # report_subcategory is optional
                    data['ip_protocol_number'],
                    data['ip_version']
                )
            )
            db.commit()
        return True  # Insert successful
    except sqlite3.IntegrityError:
        logging.error(f"Duplicate entry: {data['id']}")
        return False  # Duplicate found

def validate_and_upload_json_files(data_list):
    # Validation and upload of JSON data received from the client
    if not data_list:
        logging.error("No JSON data received.")
        return "No JSON data received.", False

    # Variables to check what error happened
    has_successful_upload = False
    has_duplicates = False
    has_validation_errors = False

    # Process each JSON data item
    for data in data_list:
        try:
            # schema validation checking (format checker not working - timestamp can be any TEXT)
            validate(instance=data, schema=schema, format_checker=FormatChecker())
            if insert_into_db(data):
                has_successful_upload = True  # Successfully uploaded at least one file
            else:
                logging.info(f"Duplicate data found: {data}")
                has_duplicates = True  # At least one entry is a duplicate
        except (json.JSONDecodeError, ValidationError) as e:
            logging.error(f"Validation error: {e}")
            has_validation_errors = True  # At least one file had a validation error
        except sqlite3.IntegrityError as e:
            logging.error(f"Database integrity error: {e}")
            has_duplicates = True  # Duplicate error
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return f"Unexpected error: {str(e)}", False

    # Response message based on the results
    if has_successful_upload:
        if has_validation_errors:
            return "Some JSON data was uploaded successfully, but some entries failed validation.", True
        return "All new JSON data validated and uploaded successfully.", True
    elif has_duplicates and not has_successful_upload and not has_validation_errors:
        return "All JSON data is already uploaded (duplicates).", False
    elif has_validation_errors and not has_successful_upload:
        return "All JSON data failed validation.", False
    else:
        return "Errors occurred while uploading JSON data.", False


@app.route('/upload-json-files', methods=['POST'])
@csrf.exempt  # Disable CSRF if you're calling via AJAX
def upload_json_files():
    # Check if the request contains JSON data
    if not request.is_json:
        return jsonify({"message": "Invalid input, JSON data required."}), 400

    # Get the JSON data from the request
    json_data = request.get_json()

    # If the data is expected to be a list of JSON objects
    if not isinstance(json_data, list):
        json_data = [json_data]

    # Call validate_and_upload_json_files to handle the upload and validation
    message, success = validate_and_upload_json_files(json_data)
    if success:
        return jsonify({"message": message}), 200
    return jsonify({"message": message}), 400


@app.route('/reset-database', methods=['POST'])
@csrf.exempt  # Disable CSRF for this route if you're calling it via AJAX ?
def reset_database():
    # Clears all data in the incidents table
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute('DELETE FROM incidents')  # deletes all rows but keeps the table structure
            db.commit()
        return jsonify({"message": "Database has been reset."}), 200
    except sqlite3.Error as e:
        logging.error(f"Database reset failed: {e}")
        return jsonify({"message": "An error occurred while resetting the database."}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
