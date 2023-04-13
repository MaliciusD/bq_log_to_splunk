#pip install -r requirements.txt
#gcloud auth application-default login

import json
import socket
from google.cloud import bigquery
import hashlib
import google.auth
from time import sleep

nb_restart = 1

while True:
    project_id = "nginx-test-383407"
    dataset_id = "nginx_logs"
    table_id = "nginx_access_20230412"

    credentials, _ = google.auth.default()

    client = bigquery.Client(project=project_id, credentials=credentials)

    def append_json_to_file(filename: str, json_data: dict) -> None:
        with open(filename, 'a') as f:
            f.write(json.dumps(json_data) + '\n')

    def append_to_file(filename: str, text: str) -> None:
        with open(filename, 'a') as f:
            f.write(text + '\n')

    def checkos(json_data: dict, filename: str) -> int:
        json_str = json.dumps(json_data, sort_keys=True)
        s_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

        with open(filename, 'r') as f:
            for line in f:
                if s_hash == line.strip():
                    return 1
                
        with open(filename, 'a') as f:
            f.write(s_hash + '\n')
        return 0

    query = f"""
    SELECT timestamp, severity, httpRequest, textPayload
    FROM `{project_id}.{dataset_id}.{table_id}`
    ORDER BY timestamp DESC
    """

    query_job = client.query(query)
    rows = query_job.result()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for row in rows:
        timestamp = row[0]
        severity = row[1]
        httpRequest = row[2]
        textPayload = json.loads(row[3]) if row[3] else None
        
        log_data = {
            'timestamp': str(timestamp),
            'severity': severity,
            'httpRequest': httpRequest,
            'textPayload': textPayload,
        }

        leef_log = log_data
        if (checkos(leef_log, "hashes.txt") == 0):
            append_json_to_file("log/secure.log", leef_log)
        else:
            continue

    sleep(30)
    print("restarting nb/"+str(nb_restart)+"...")
    nb_restart += 1
    continue
