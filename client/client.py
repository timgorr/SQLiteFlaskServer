import os
import json
import requests
from jsonschema import validate, ValidationError, FormatChecker


attack_schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "This document records the details of an incident",
    "title": "Record of a SIEM Incident",
    "type": "object",
    "properties": {
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
    "required": ["report_category", "report_type", "timestamp", "source_key", "source_value", "confidence_level", "version", "report_subcategory",
                 "ip_protocol_number", "ip_version"]
}


malware_schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "This document records the details of a malware report",
    "title": "Malware Report",
    "type": "object",
    "properties": {
        "report_category": {"type": "string", "enum": ["eu.acdc.malware"]},
        "report_type": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "source_key": {"type": "string"},
        "source_value": {"type": "string"},
        "cpe": {"type": "string"},
        "sample_b64": {"type": "string"},
        "confidence_level": {"type": "number"},
        "version": {"type": "integer"}
    },
    "required": [
        "report_category",
        "report_type",
        "timestamp",
        "source_key",
        "source_value",
        "confidence_level",
        "version"
    ]
}


json_folder = os.path.expanduser('/home/client/client_data_M')  


server_url = 'http://192.168.162.241:5001/upload-json-files'

# validate data depending on category
def validate_report(data):
    try:
        if data.get("report_category") == "eu.acdc.attack":
            validate(instance=data, schema=attack_schema)
        elif data.get("report_category") == "eu.acdc.malware":
            validate(instance=data, schema=malware_schema)
        else:
            return False, "Invalid report category."
        return True, "Validation successful."
    except ValidationError as e:
        return False, f"Validation error: {e.message}"


def send_to_server(data):
    response = requests.post(server_url, json=data)
    if response.status_code == 200:
        return True, response.json()
    else:
        return False, response.text


def process_files():
    if not os.path.exists(json_folder):
        print("JSON folder not found.")
        return

    json_files = [f for f in os.listdir(json_folder) if f.endswith('.json')]
    
    if not json_files:
        print("No JSON files to process.")
        return

    for filename in json_files:
        file_path = os.path.join(json_folder, filename)
        with open(file_path, 'r') as file:
            try:
                data = json.load(file)
                
                # Validate JSON Data
                is_valid, error_message = validate_report(data)
                if is_valid:
                    # if valid SEND
                    success, response = send_to_server(data)
                    if success:
                        print(f"File {filename} uploaded successfully: {response}")
                    else:
                        print(f"Failed to upload {filename}: {response}")
                else:
                    print(f"Validation failed for {filename}: {error_message}")
                    
            except json.JSONDecodeError:
                print(f"Failed to parse JSON in {filename}")
            except Exception as e:
                print(f"An error occurred while processing {filename}: {e}")


if __name__ == '__main__':
    process_files()
