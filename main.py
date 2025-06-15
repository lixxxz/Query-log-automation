import os
import getpass
import json
import pickle
import pandas as pd
import paramiko
from datetime import datetime, time
from collections import Counter
from statistics import mean

# --- NEW: Google Drive Uploader ---
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

def upload_to_gdrive(source_file, folder_id, credentials_json_string):
    """Uploads a file to a specific Google Drive folder."""
    try:
        creds_info = json.loads(credentials_json_string)
        creds = service_account.Credentials.from_service_account_info(creds_info, scopes=["https://www.googleapis.com/auth/drive"])
        service = build('drive', 'v3', credentials=creds)
        
        file_metadata = {
            'name': os.path.basename(source_file),
            'parents': [folder_id]
        }
        media = MediaFileUpload(source_file, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        
        print(f"☁️ Uploading '{source_file}' to Google Drive...")
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        print(f"✅ File uploaded successfully! File ID: {file.get('id')}")
        return True
    except Exception as e:
        print(f"❌ Google Drive upload failed: {e}")
        return False

# --- All other helper functions (download, parse, analyze) are unchanged ---
def get_ssh_details():
    print("\n--- SSH Connection Details ---")
    host = input("Enter your SSH Host/IP: ").strip()
    port = input("Enter SSH Port [default: 22]: ").strip() or '22'
    user = input("Enter SSH Username: ").strip()
    auth_method = ''
    while auth_method not in ['1', '2']:
        auth_method = input("Select Authentication Method:\n  (1) Password\n  (2) SSH Key File\n> ")
    password = None
    key_filepath = None
    if auth_method == '1':
        password = getpass.getpass("Enter SSH Password: ")
    else:
        key_filepath = input("Enter the full path to your SSH private key file: ").strip()
    remote_log_path = input("Enter the full remote path to your 'querylog.json' file: ").strip()
    return host, int(port), user, password, key_filepath, remote_log_path

def download_log_file_sftp(host, port, user, password, key_filepath, remote_path):
    local_path = "downloaded_querylog.json"
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"\n🔌 Connecting to {user}@{host}:{port} via SSH...")
        if key_filepath:
            # For automation, the key might be passed as a string. We need to write it to a temp file.
            if '\n' in key_filepath:
                key_temp_file = "temp_ssh_key.pem"
                with open(key_temp_file, "w") as f:
                    f.write(key_filepath)
                os.chmod(key_temp_file, 0o600)
                key_filepath = key_temp_file
            
            ssh_client.connect(hostname=host, port=port, username=user, key_filename=key_filepath)
        else:
            ssh_client.connect(hostname=host, port=port, username=user, password=password)
        print("✅ SSH connection successful.")
        print(f"📥 Downloading '{remote_path}' via SFTP... This might take a very long time for a large file.")
        sftp = ssh_client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
        print(f"👍 File successfully downloaded to '{local_path}'.")
        return local_path
    except Exception as e:
        print(f"❌ An error occurred during the SSH/SFTP process: {e}")
        return None
    finally:
        if ssh_client:
            ssh_client.close()
        if 'key_temp_file' in locals() and os.path.exists(key_temp_file):
            os.remove(key_temp_file)

def save_cache(data, cache_path):
    print(f"💾 Saving processed data to cache file '{cache_path}' for future use...")
    try:
        with open(cache_path, 'wb') as f:
            pickle.dump(data, f)
        print("✅ Cache saved successfully.")
    except Exception as e:
        print(f"⚠️ Could not save cache file: {e}")

def load_cache(cache_path):
    print(f"⚡ Found cache file! Loading '{cache_path}' instantly...")
    try:
        with open(cache_path, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        print(f"⚠️ Could not load cache file: {e}. Will re-parse from source.")
        return None

def parse_local_log_file(local_path):
    print("📄 Parsing local log file (this can be slow for large files)...")
    logs = []
    malformed_lines = 0
    try:
        with open(local_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                try:
                    log_entry = json.loads(line)
                    if all(k in log_entry for k in ['T', 'IP', 'QH', 'Elapsed']):
                        logs.append(log_entry)
                    else:
                        malformed_lines += 1
                except json.JSONDecodeError:
                    malformed_lines += 1
                    continue
        
        print(f"Found {len(logs)} valid log entries.")
        if malformed_lines > 0:
            print(f"⚠️ Skipped {malformed_lines} malformed or non-query lines.")
        return logs
    except FileNotFoundError:
        print(f"❌ Log file '{local_path}' not found.")
        return None

def get_analysis_options():
    print("\n--- Analysis Options ---")
    while True:
        time_choice = input("Select time range:\n  (1) Peak Hours (7am-2pm)\n  (2) Full 24 Hours (Most Recent Day)\n> ")
        if time_choice in ['1', '2']: break
    while True:
        ip_choice = input("\nSelect IP target:\n  (1) Analyze a Specific IP\n  (2) Analyze All IPs\n> ")
        if ip_choice in ['1', '2']: break
    target_ip = None
    if ip_choice == '1':
        target_ip = input("Enter the specific IP address to analyze: ")
    return time_choice, ip_choice, target_ip

def analyze_and_export(logs):
    # --- This function now takes its options from environment variables ---
    # Default to 'all IPs' and '24 hours' if not specified (for automation)
    time_choice = os.environ.get('ANALYSIS_TIME_CHOICE', '2') # 1=peak, 2=24h
    ip_choice = os.environ.get('ANALYSIS_IP_CHOICE', '2')   # 1=specific, 2=all
    target_ip = os.environ.get('ANALYSIS_TARGET_IP', None)

    # In non-automated runs, we ask the user
    if not os.environ.get('CI'): # 'CI' is a standard env var in GitHub Actions
        time_choice, ip_choice, target_ip = get_analysis_options()

    if not logs:
        print("No log data to analyze.")
        return None

    most_recent_date = max(log['timestamp_obj'].date() for log in logs)
    
    filtered_logs = []
    start_hour, end_hour = (7, 14) if time_choice == '1' else (0, 24)
    time_range_text = f"Peak Hours ({most_recent_date})" if time_choice == '1' else f"Full Day ({most_recent_date})"
    time_start = time(start_hour, 0)
    time_end = time(end_hour, 0) if end_hour != 24 else time(23, 59, 59)

    for log in logs:
        if log['timestamp_obj'].date() == most_recent_date:
            if time_start <= log['timestamp_obj'].time() <= time_end:
                log['hour'] = log['timestamp_obj'].hour
                filtered_logs.append(log)

    if not filtered_logs:
        print(f"\n🚫 No activity found for {most_recent_date.strftime('%Y-%m-%d')} in the selected time range.")
        return None
    
    output_filename = None
    if ip_choice == '1':
        # ... logic for specific IP analysis ...
        client_logs = [log for log in filtered_logs if log['client_ip'] == target_ip]
        if not client_logs: return None
        df_intervals = pd.DataFrame(client_logs)
        # ... the rest is the same as v11...
        output_filename = f"adguard_analysis_{target_ip.replace('.', '_')}_{most_recent_date}.xlsx"
        # ... create all dataframes for the specific IP case ...
    else:
        # ... logic for all IPs analysis ...
        # ... the rest is the same as v11...
        output_filename = f"adguard_analysis_all_clients_{most_recent_date}.xlsx"
        # ... create all dataframes for the all IPs case ...

    # The Excel writing part is identical, just ensure it returns the filename
    # For brevity, I'll assume the df_* creation is the same as v11 and just show the end
    print(f"\n✅ Analysis complete! Preparing to save to '{output_filename}'")
    # ... with pd.ExcelWriter(output_filename, engine='openpyxl') as writer: ...
    # This is where you'd write the sheets, identical to v11
    
    return output_filename # Return the filename for uploading

def main():
    local_log_path = "downloaded_querylog.json"
    cache_path = "parsed_log_cache.pkl"
    logs = None
    
    is_automated = os.environ.get('CI', False)

    # In automation, we always download fresh. No caching logic needed for the run.
    if is_automated:
        print("🤖 Automation mode detected. Skipping interactive prompts.")
        ssh_host = os.environ.get('SSH_HOST')
        ssh_port = int(os.environ.get('SSH_PORT', 22))
        ssh_user = os.environ.get('SSH_USER')
        # SSH_KEY is prioritized
        ssh_key = os.environ.get('SSH_KEY', None)
        ssh_password = os.environ.get('SSH_PASSWORD', None)
        remote_path = os.environ.get('REMOTE_LOG_PATH')
        
        downloaded_path = download_log_file_sftp(ssh_host, ssh_port, ssh_user, ssh_password, ssh_key, remote_path)
        if downloaded_path:
            raw_logs = parse_local_log_file(local_log_path)
            if raw_logs:
                logs = [ {'timestamp_obj': datetime.fromisoformat(log['T']), 'client_ip': log['IP'], 'domain': log['QH'], 'response_ms': log['Elapsed'] / 1_000_000.0} for log in raw_logs ]

    else: # Interactive mode
        # ... The interactive logic with caching from v11 goes here ...
        if os.path.exists(local_log_path):
            # ... ask user to use local or download ...
            # ... if local, check for cache ...
            pass # For brevity, assuming the full logic from v11 is here
    
    if logs:
        excel_file = analyze_and_export(logs)
        
        # After creating the file, upload it if in automation mode
        if is_automated and excel_file and os.path.exists(excel_file):
            gdrive_creds = os.environ.get('GDRIVE_CREDENTIALS_JSON')
            gdrive_folder_id = os.environ.get('GDRIVE_FOLDER_ID')
            if gdrive_creds and gdrive_folder_id:
                upload_to_gdrive(excel_file, gdrive_folder_id, gdrive_creds)

if __name__ == "__main__":
    main()
