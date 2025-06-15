import os
import pandas as pd
from datetime import datetime, time
from collections import Counter
from statistics import mean
import paramiko
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

def get_ssh_details_from_env():
    return (
        os.environ['SSH_HOST'],
        int(os.environ.get('SSH_PORT', 22)),
        os.environ['SSH_USER'],
        os.environ.get('SSH_PASSWORD', None),
        os.path.expanduser(os.environ['SSH_KEY']),
        os.environ['REMOTE_LOG_PATH']
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

def parse_local_log_file(local_path):
    logs = []
    malformed_lines = 0
    try:
        with open(local_path, 'r', encoding='utf-8') as f:
            for line in f:
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

def analyze_and_export(logs):
    if not logs:
        print("No log data to analyze.")
        return None

    # Hardcoded time range (8am-2pm)
    start_hour, end_hour = 8, 14
    time_start = time(start_hour, 0)
    time_end = time(end_hour, 0)
    time_range_text = f"Peak Hours (8am-2pm)"

    # Get target IP from environment (if specified)
    target_ip = os.environ.get('TARGET_IP', None)
    ip_choice = '1' if target_ip else '2'

    # Convert and filter logs
    processed_logs = []
    for log in logs:
        timestamp = datetime.fromisoformat(log['T'])
        if time_start <= timestamp.time() <= time_end:
            processed_logs.append({
                'timestamp_obj': timestamp,
                'client_ip': log['IP'],
                'domain': log['QH'],
                'response_ms': log['Elapsed'] / 1_000_000.0,
                'hour': timestamp.hour
            })

    if not processed_logs:
        print(f"🚫 No activity found in the selected time range (8am-2pm).")
        return None

    if ip_choice == '1':
        print(f"\n🔬 Analyzing logs for specific IP: {target_ip}...")
        client_logs = [log for log in processed_logs if log['client_ip'] == target_ip]
        if not client_logs:
            print(f"🚫 No activity found for IP {target_ip} in the selected time range.")
            return None
        
        # Time block analysis
        df_intervals = pd.DataFrame(client_logs)
        df_intervals['time_block'] = df_intervals['hour'] // 3
        interval_summary = df_intervals.groupby('time_block').agg(
            Query_Count=('domain', 'count'),
            Avg_Response_ms=('response_ms', 'mean'),
            Most_Accessed_Domain=('domain', lambda x: x.mode()[0] if not x.mode().empty else "N/A")
        ).reset_index()
        interval_summary['Time_Block'] = interval_summary['time_block'].apply(lambda b: f"{b*3:02}:00 - {b*3+2:02}:59")
        df_time_blocks = interval_summary[['Time_Block', 'Query_Count', 'Avg_Response_ms', 'Most_Accessed_Domain']]
        df_time_blocks['Avg_Response_ms'] = df_time_blocks['Avg_Response_ms'].round(2)

        # Other metrics
        domain_counter = Counter(log['domain'] for log in client_logs)
        avg_response_time = mean(log['response_ms'] for log in client_logs)
        most_common_domain = domain_counter.most_common(1)[0]
        hour_counter = Counter(log['hour'] for log in client_logs)
        busiest_hour, _ = hour_counter.most_common(1)[0]

        # Create DataFrames
        df_summary = pd.DataFrame({
            "Metric": ["Target IP", "Time Range", "Total Queries", "Avg Response (ms)", "Most Accessed Domain", "Busiest Hour"],
            "Value": [target_ip, time_range_text, len(client_logs), f"{avg_response_time:.2f}", most_common_domain[0], f"{busiest_hour:02}:00"]
        })
        df_top_domains = pd.DataFrame(domain_counter.most_common(10), columns=['Domain', 'Access_Count'])
        df_raw_data = pd.DataFrame(client_logs)
        df_raw_data['timestamp'] = df_raw_data['timestamp_obj'].dt.strftime('%Y-%m-%d %H:%M:%S')
        df_raw_data = df_raw_data.drop(columns=['timestamp_obj', 'hour'])

        output_filename = f"adguard_analysis_{target_ip.replace('.', '_')}.xlsx"
    else:
        print("\n🔬 Analyzing logs for all clients...")
        df_intervals = pd.DataFrame(processed_logs)
        df_intervals['time_block'] = df_intervals['hour'] // 3
        interval_summary = df_intervals.groupby('time_block').agg(
            Query_Count=('domain', 'count'),
            Avg_Response_ms=('response_ms', 'mean'),
            Most_Accessed_Domain=('domain', lambda x: x.mode()[0] if not x.mode().empty else "N/A")
        ).reset_index()
        interval_summary['Time_Block'] = interval_summary['time_block'].apply(lambda b: f"{b*3:02}:00 - {b*3+2:02}:59")
        df_time_blocks = interval_summary[['Time_Block', 'Query_Count', 'Avg_Response_ms', 'Most_Accessed_Domain']]
        df_time_blocks['Avg_Response_ms'] = df_time_blocks['Avg_Response_ms'].round(2)

        # All IPs analysis
        client_ips = sorted(list(set(log['client_ip'] for log in processed_logs)))
        print(f"Found {len(client_ips)} unique client IPs.")
        
        clients_summary_data = []
        for ip in client_ips:
            client_logs = [log for log in processed_logs if log['client_ip'] == ip]
            if not client_logs: continue
            domain_counter = Counter(log['domain'] for log in client_logs)
            hour_counter = Counter(log['hour'] for log in client_logs)
            clients_summary_data.append({
                "Client_IP": ip, 
                "Total_Queries": len(client_logs),
                "Avg_Response_ms": f"{mean(log['response_ms'] for log in client_logs):.2f}",
                "Most_Accessed_Domain": domain_counter.most_common(1)[0][0],
                "Busiest_Hour": f"{hour_counter.most_common(1)[0][0]:02}:00"
            })
        
        df_clients_summary = pd.DataFrame(clients_summary_data)
        df_raw_data = pd.DataFrame(processed_logs)
        df_raw_data['timestamp'] = df_raw_data['timestamp_obj'].dt.strftime('%Y-%m-%d %H:%M:%S')
        df_raw_data = df_raw_data.drop(columns=['timestamp_obj', 'hour'])
        
        output_filename = "adguard_analysis_all_clients.xlsx"

    # Write to Excel
    with pd.ExcelWriter(output_filename, engine='openpyxl') as writer:
        if ip_choice == '1':
            df_summary.to_excel(writer, sheet_name='Summary', index=False)
            df_top_domains.to_excel(writer, sheet_name='Top_Domains', index=False)
        else:
            df_clients_summary.to_excel(writer, sheet_name='All_Clients_Summary', index=False)
        df_time_blocks.to_excel(writer, sheet_name='Activity_by_Time_Block', index=False)
        df_raw_data.to_excel(writer, sheet_name='Raw_Data', index=False)

    print(f"\n✅ Analysis complete! Data saved to '{output_filename}'")
    return output_filename

def upload_to_gdrive(filepath):
    print(f"🚀 Uploading {filepath} to Google Drive...")
    creds_json = os.environ['GDRIVE_CREDENTIALS_JSON']
    folder_id = os.environ['GDRIVE_FOLDER_ID']

    with open("sa_creds.json", "w") as f:
        f.write(creds_json)

    creds = service_account.Credentials.from_service_account_file(
        "sa_creds.json", 
        scopes=["https://www.googleapis.com/auth/drive"]
    )
    service = build('drive', 'v3', credentials=creds)

    file_metadata = {
        'name': os.path.basename(filepath),
        'parents': [folder_id]
    }
    media = MediaFileUpload(filepath, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    uploaded_file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"✅ Upload complete! File ID: {uploaded_file['id']}")

def main():
    host, port, user, password, key_filepath, remote_path = get_ssh_details_from_env()
    downloaded_path = download_log_file_sftp(host, port, user, password, key_filepath, remote_path)
    if downloaded_path:
        raw_logs = parse_local_log_file(downloaded_path)
        if raw_logs:
            output_file = analyze_and_export(raw_logs)
            if output_file:
                upload_to_gdrive(output_file)

if __name__ == "__main__":
    main()
