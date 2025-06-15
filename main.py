import os
import getpass
import json
import pickle
import pandas as pd
import paramiko
from datetime import datetime, time
from collections import Counter
from statistics import mean

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

def upload_to_gdrive(source_file, folder_id, credentials_json_string):
    """Uploads a file to a specific Google Drive folder."""
    try:
        creds_info = json.loads(credentials_json_string)
        creds = service_account.Credentials.from_service_account_info(creds_info, scopes=["https://www.googleapis.com/auth/drive"])
        service = build('drive', 'v3', credentials=creds)
        
        file_metadata = {'name': os.path.basename(source_file), 'parents': [folder_id]}
        media = MediaFileUpload(source_file, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        
        print(f"☁️ Uploading '{source_file}' to Google Drive...")
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        print(f"✅ File uploaded successfully! File ID: {file.get('id')}")
        return True
    except Exception as e:
        print(f"❌ Google Drive upload failed: {e}")
        return False

def get_ssh_details():
    # This function is for interactive mode only
    # ... (code is unchanged)
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

def download_log_file_sftp(host, port, user, password, key_string, remote_path):
    """Connects via SSH and downloads the log file using SFTP, with improved logging."""
    local_path = "downloaded_querylog.json"
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    key_temp_file = None # Define variable to ensure it exists for the 'finally' block

    try:
        print(f"\n🔌 Preparing to connect to {user}@{host}:{port} via SSH...")
        
        # Prioritize key-based authentication
        if key_string:
            print("🔑 Found SSH_KEY secret. Attempting to connect using the key...")
            key_temp_file = "temp_ssh_key.pem"
            with open(key_temp_file, "w") as f:
                f.write(key_string)
            os.chmod(key_temp_file, 0o600) # Set correct permissions for the key file
            
            ssh_client.connect(hostname=host, port=port, username=user, key_filename=key_temp_file, timeout=20)

        # Fallback to password authentication if key is not provided
        elif password:
            print("🔑 No SSH_KEY found. Attempting to connect using SSH_PASSWORD...")
            ssh_client.connect(hostname=host, port=port, username=user, password=password, timeout=20)
        
        else:
            raise ValueError("FATAL: No SSH key or password provided in GitHub secrets.")

        print("✅ SSH connection successful.")
        print(f"📥 Downloading '{remote_path}' via SFTP...")
        
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
        # Clean up the temporary key file if it was created
        if key_temp_file and os.path.exists(key_temp_file):
            os.remove(key_temp_file)
            print("🧹 Cleaned up temporary SSH key file.")

# ... All other functions like save_cache, load_cache, parse_local_log_file, get_analysis_options, analyze_and_export are unchanged ...
# ... They are omitted here for brevity but should be in your file ...

def main():
    """Main function to run the analysis with intelligent caching."""
    # This function is now mostly for automation, the interactive part is a fallback
    local_log_path = "downloaded_querylog.json"
    cache_path = "parsed_log_cache.pkl"
    logs = None
    excel_file = None
    
    is_automated = os.environ.get('CI', False)

    if is_automated:
        print("🤖 Automation mode detected.")
        ssh_host = os.environ.get('SSH_HOST')
        ssh_port = int(os.environ.get('SSH_PORT', 22))
        ssh_user = os.environ.get('SSH_USER')
        ssh_key_string = os.environ.get('SSH_KEY', None)
        ssh_password = os.environ.get('SSH_PASSWORD', None)
        remote_path = os.environ.get('REMOTE_LOG_PATH')
        
        # Automation always downloads a fresh file
        downloaded_path = download_log_file_sftp(ssh_host, ssh_port, ssh_user, ssh_password, ssh_key_string, remote_path)
        
        if downloaded_path:
            raw_logs = parse_local_log_file(local_log_path)
            if raw_logs:
                # Process logs after downloading
                logs = [ {'timestamp_obj': datetime.fromisoformat(log['T']), 'client_ip': log['IP'], 'domain': log['QH'], 'response_ms': log['Elapsed'] / 1_000_000.0} for log in raw_logs ]
    else:
        # Interactive mode logic...
        # ... (omitted for brevity, this is your v12 interactive code with caching) ...
        print("Running in interactive mode...")
    
    if logs:
        # Assuming analyze_and_export is defined elsewhere as in v12
        excel_file = analyze_and_export(logs)
        
    if is_automated and excel_file and os.path.exists(excel_file):
        gdrive_creds = os.environ.get('GDRIVE_CREDENTIALS_JSON')
        gdrive_folder_id = os.environ.get('GDRIVE_FOLDER_ID')
        if gdrive_creds and gdrive_folder_id:
            upload_to_gdrive(excel_file, gdrive_folder_id, gdrive_creds)

if __name__ == "__main__":
    # You will need to copy the full 'analyze_and_export' and other helper functions from the previous version
    # This example only contains the most relevant updated functions.
    # main() 
    print("Please ensure you have copied the full script content from the previous versions.")
