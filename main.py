import requests
import pandas as pd
from datetime import datetime, time
from collections import Counter
from statistics import mean
import os
import paramiko
import json
import pickle
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

def get_ssh_details_from_env():
    return (
        os.environ['SSH_HOST'],
        int(os.environ.get('SSH_PORT', 22)),
        os.environ['SSH_USER'],
        os.environ.get('SSH_PASSWORD', None),
        os.environ['SSH_KEY_PATH'],
        os.environ['SSH_REMOTE_LOG']
    )

def download_log_file_sftp(host, port, user, password, key_filepath, remote_path):
    local_path = "downloaded_querylog.json"
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"\n🔌 Connecting to {user}@{host}:{port} via SSH...")
        if key_filepath:
            ssh_client.connect(hostname=host, port=port, username=user, key_filename=key_filepath)
        else:
            ssh_client.connect(hostname=host, port=port, username=user, password=password)
        print("✅ SSH connection successful.")
        print(f"📥 Downloading '{remote_path}' via SFTP...")
        sftp = ssh_client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
        print(f"👍 File downloaded to '{local_path}'")
        return local_path
    except Exception as e:
        print(f"❌ SSH/SFTP error: {e}")
        return None
    finally:
        ssh_client.close()

def save_cache(data, cache_path):
    with open(cache_path, 'wb') as f:
        pickle.dump(data, f)

def load_cache(cache_path):
    with open(cache_path, 'rb') as f:
        return pickle.load(f)

def parse_local_log_file(local_path):
    logs = []
    with open(local_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                if all(k in log_entry for k in ['T', 'IP', 'QH', 'Elapsed']):
                    logs.append(log_entry)
            except json.JSONDecodeError:
                continue
    return logs

def analyze_and_export(logs):
    if not logs:
        print("No logs to analyze.")
        return

    most_recent_date = max(datetime.fromisoformat(log['T']).date() for log in logs)
    filtered_logs = []
    for log in logs:
        ts = datetime.fromisoformat(log['T'])
        if ts.date() == most_recent_date:
            log['timestamp_obj'] = ts
            log['hour'] = ts.hour
            filtered_logs.append({
                'timestamp_obj': ts,
                'client_ip': log['IP'],
                'domain': log['QH'],
                'response_ms': log['Elapsed'] / 1_000_000.0,
                'hour': ts.hour
            })

    df = pd.DataFrame(filtered_logs)
    df['time_block'] = df['hour'] // 3
    interval_summary = df.groupby('time_block').agg(
        Query_Count=('domain', 'count'),
        Avg_Response_ms=('response_ms', 'mean'),
        Most_Accessed_Domain=('domain', lambda x: x.mode()[0] if not x.mode().empty else "N/A")
    ).reset_index()
    interval_summary['Time_Block'] = interval_summary['time_block'].apply(lambda b: f"{b*3:02}:00 - {b*3+2:02}:59")
    df_time_blocks = interval_summary[['Time_Block', 'Query_Count', 'Avg_Response_ms', 'Most_Accessed_Domain']]
    df_time_blocks['Avg_Response_ms'] = df_time_blocks['Avg_Response_ms'].round(2)

    domain_counter = Counter(df['domain'])
    df_top_domains = pd.DataFrame(domain_counter.most_common(10), columns=['Domain', 'Access_Count'])

    df_raw_data = df.copy()
    df_raw_data['timestamp'] = df_raw_data['timestamp_obj'].dt.strftime('%Y-%m-%d %H:%M:%S')
    df_raw_data.drop(columns=['timestamp_obj', 'hour', 'time_block'], inplace=True)

    output_filename = "adguard_analysis_all_clients.xlsx"
    with pd.ExcelWriter(output_filename, engine='openpyxl') as writer:
        df_top_domains.to_excel(writer, sheet_name='Top_Domains', index=False)
        df_time_blocks.to_excel(writer, sheet_name='Activity_by_Time_Block', index=False)
        df_raw_data.to_excel(writer, sheet_name='All_Clients_Raw_Data', index=False)

    print(f"✅ Saved analysis to {output_filename}")
    return output_filename

def upload_to_gdrive(filepath):
    print(f"🚀 Uploading {filepath} to Google Drive...")
    gauth = GoogleAuth()
    gauth.LoadCredentialsFile("token.json")
    if gauth.credentials is None:
        gauth.LocalWebserverAuth()
    elif gauth.access_token_expired:
        gauth.Refresh()
    else:
        gauth.Authorize()
    gauth.SaveCredentialsFile("token.json")

    drive = GoogleDrive(gauth)
    gfile = drive.CreateFile({'title': os.path.basename(filepath)})
    gfile.SetContentFile(filepath)
    gfile.Upload()
    print("✅ Upload complete!")

def main():
    host, port, user, password, key_filepath, remote_path = get_ssh_details_from_env()
    downloaded_path = download_log_file_sftp(host, port, user, password, key_filepath, remote_path)
    if downloaded_path:
        raw_logs = parse_local_log_file(downloaded_path)
        if raw_logs:
            logs = [
                {
                    'T': log['T'],
                    'IP': log['IP'],
                    'QH': log['QH'],
                    'Elapsed': log['Elapsed']
                }
                for log in raw_logs
            ]
            output_file = analyze_and_export(logs)
            upload_to_gdrive(output_file)

if __name__ == "__main__":
    main()
