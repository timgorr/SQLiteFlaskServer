from flask import Flask, render_template, request, jsonify
from flask_wtf import CSRFProtect
import sqlite3
import os
import logging

app = Flask(__name__)



app.config['DATABASE'] = os.getenv('DATABASE_PATH', 'database.db')  # env var for database path


csrf = CSRFProtect(app)



app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True  
)

logging.basicConfig(level=logging.INFO)



def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    return conn

@app.route('/favicon.ico')
def favicon():
    return '', 204 


def init_db():
    conn = sqlite3.connect('database.db') 
    cursor = conn.cursor()


    cursor.execute('''
    CREATE TABLE IF NOT EXISTS incidents (
        report_category TEXT,
        report_type TEXT,
        timestamp TEXT,
        source_key TEXT,
        source_value TEXT,
        confidence_level TEXT,
        version INTEGER,
        report_subcategory TEXT,
        ip_protocol_number TEXT,
        ip_version TEXT,
        UNIQUE (report_category, report_type, timestamp, source_key, source_value, confidence_level)
    )
    ''')


    cursor.execute('''
    CREATE TABLE IF NOT EXISTS malware_reports (
        report_category TEXT,
        report_type TEXT,
        timestamp TEXT,
        source_key TEXT,
        source_value TEXT,
        confidence_level REAL,
        version INTEGER,
        UNIQUE (report_category, report_type, timestamp, source_key, source_value)
    )
    ''')

 
    conn.commit()
    conn.close()
               


@app.route('/')
def view_database():
    try:
        with get_db() as db:
            cursor = db.cursor()

            cursor.execute('SELECT report_category, report_type, timestamp, source_key, source_value, confidence_level, version, report_subcategory, ip_protocol_number, ip_version FROM incidents')
            incidents_rows = cursor.fetchall()
            incidents_data = [
                {
                    "report_category": row[0],
                    "report_type": row[1],
                    "timestamp": row[2],
                    "source_key": row[3],
                    "source_value": row[4],
                    "confidence_level": row[5],
                    "version": row[6],
                    "report_subcategory": row[7],
                    "ip_protocol_number": row[8],
                    "ip_version": row[9]
                } for row in incidents_rows
            ]


            cursor.execute('SELECT report_category, report_type, timestamp, source_key, source_value,confidence_level, version FROM malware_reports')
            malware_rows = cursor.fetchall()
            malware_data = [
                {
                    "report_category": row[0],
                    "report_type": row[1],
                    "timestamp": row[2],
                    "source_key": row[3],
                    "source_value": row[4],
                    "confidence_level": row[5],
                    "version": row[6]
                } for row in malware_rows
            ]

        return render_template('index.html', incidents_data=incidents_data, malware_data=malware_data)
    except sqlite3.Error as e:
        logging.error(f"Database query failed: {e}")
        return jsonify({"message": f"An error occurred while fetching the database contents: {e}"}), 500

def insert_into_incidents(data):
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute(
                '''INSERT INTO incidents 
                (report_category, report_type, timestamp, source_key, source_value, confidence_level, version, report_subcategory, ip_protocol_number, ip_version) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    data['report_category'],
                    data.get('report_type'),
                    data['timestamp'],
                    data['source_key'],
                    data['source_value'],
                    data['confidence_level'],
                    data['version'],
                    data.get('report_subcategory'),
                    data['ip_protocol_number'],
                    data['ip_version']
                )
            )
            db.commit()
        return True  # Insert successful
    except sqlite3.IntegrityError:
        logging.error(f"Duplicate entry: {data}")
        return False  # Duplicate found


def insert_into_malware_reports(data):
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute(
                '''INSERT INTO malware_reports 
                (report_category, report_type, timestamp, source_key, source_value,  confidence_level, version) 
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (
                    data['report_category'],
                    data['report_type'],
                    data['timestamp'],
                    data['source_key'],
                    data['source_value'],
                    data['confidence_level'],
                    data['version']
                )
            )
            db.commit()
        return True  # Insert successful
    except sqlite3.IntegrityError:
        logging.error(f"Duplicate entry: {data}")
        return False  # Duplicate found




@app.route('/upload-json-files', methods=['POST'])
@csrf.exempt  # Disable CSRF if you're calling via AJAX
def upload_json_files():
    if not request.is_json:
        return jsonify({"message": "Invalid input, JSON data required."}), 400

    # json von request
    json_data = request.get_json()

    # json liste
    if not isinstance(json_data, list):
        json_data = [json_data]

    # each json upload process
    has_successful_upload = False
    has_duplicates = False

    for data in json_data:
        try:
            # Check which table 
            if data['report_category'] == "eu.acdc.attack":
                if is_duplicate(data):  
                    logging.info(f"Duplicate data found: {data}")
                    has_duplicates = True
                    continue
                if insert_into_incidents(data):  
                    has_successful_upload = True

            elif data['report_category'] == "eu.acdc.malware":
                if is_malware_duplicate(data):  
                    logging.info(f"Duplicate data found: {data}")
                    has_duplicates = True
                    continue
                if insert_into_malware_reports(data):  
                    has_successful_upload = True

        except sqlite3.IntegrityError as e:
            logging.error(f"Database integrity error: {e}")
            has_duplicates = True
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return jsonify({"message": f"Unexpected error: {str(e)}"}), 500


    if has_successful_upload:
        return jsonify({"message": "All new JSON data uploaded successfully."}), 200
    elif has_duplicates:
        return jsonify({"message": "Some or all JSON data is already uploaded (duplicates)."}), 400
    else:
        return jsonify({"message": "Errors occurred while uploading JSON data."}), 400



def is_duplicate(data):
    conn = get_db()
    cursor = conn.cursor()
    query = """
    SELECT COUNT(*) FROM incidents 
    WHERE report_category = ? AND report_type = ? AND timestamp = ? 
    AND source_key = ? AND source_value = ? AND confidence_level = ?
    """
    values = (
        data['report_category'],
        data['report_type'],
        data['timestamp'],
        data['source_key'],
        data['source_value'],
        data['confidence_level']
    )
    cursor.execute(query, values)
    result = cursor.fetchone()[0]
    conn.close()
    return result > 0



def is_malware_duplicate(data):
    conn = get_db()
    cursor = conn.cursor()
    query = """
    SELECT COUNT(*) FROM malware_reports 
    WHERE report_category = ? AND report_type = ? AND timestamp = ? 
    AND source_key = ? AND source_value = ?
    """
    values = (
        data['report_category'],
        data['report_type'],
        data['timestamp'],
        data['source_key'],
        data['source_value']
    )
    cursor.execute(query, values)
    result = cursor.fetchone()[0]
    conn.close()
    return result > 0  # true falls duplicate gefunden  



@app.route('/reset-database', methods=['POST'])
@csrf.exempt  # Disable CSRF for this route if you're calling it via AJAX ?
def reset_database():
    try:
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute('DELETE FROM incidents')  # deletes all rows but keeps the table structure
            cursor.execute('DELETE FROM malware_reports')  # deletes all rows but keeps the table structure
            db.commit()
        return jsonify({"message": "Database has been reset."}), 200
    except sqlite3.Error as e:
        logging.error(f"Database reset failed: {e}")
        return jsonify({"message": "An error occurred while resetting the database."}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
