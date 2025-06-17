# Query Log Automation ⚙️

![AdGuard Logo](https://raw.githubusercontent.com/minhvip20956/adguard-home/refs/heads/master/favicon.ico)  
![Python](https://img.shields.io/badge/python-3.11-blue) ![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?logo=github-actions&logoColor=white)

![GitHub last commit](https://img.shields.io/github/last-commit/lixxxz/Query-log-automation?style=for-the-badge)
![GitHub repo size](https://img.shields.io/github/repo-size/lixxxz/Query-log-automation?style=for-the-badge)

## Overview

This script automates the analysis of AdGuard DNS query logs, generating detailed reports and automatically uploading them to Google Drive.  It's designed to provide valuable insights into your network traffic patterns.

## Key Features ✨

*   **Automated Analysis:** Processes AdGuard query logs for comprehensive metrics.
*   **Time Filtering:** Analyzes data during peak hours (8 AM - 2 PM) by default, allowing you to focus on critical periods.
*   **Reporting:** Creates Excel reports including:
    *   Summary statistics
    *   Top domains and response time analysis
    *   Hourly activity breakdown
    *   Raw query data
*   **Google Drive Integration:** Automatically uploads generated reports to your Google Drive for easy access and sharing.

## How it Works (Briefly) 🛠️

1.  **Log Download:** The script securely downloads logs from your AdGuard Home server using SFTP.
2.  **Data Parsing:** It parses the downloaded log file, extracting relevant information like client IP addresses, domains queried, and response times.  The script expects JSON-formatted log entries.
3.  **Analysis & Reporting:**  It analyzes the parsed data, filters by time range (8 AM - 2 PM), and generates a detailed Excel report.
4.  **Google Drive Upload:** The generated report is then automatically uploaded to your Google Drive account.

## 🚧 Development Status

[ ] Feature Requests
  - Support for additional log formats
  - CLI configuration options
  
[✓] Current Functionality:

  ✅ SSH connection with both key and password support  
  ✅ Time-filtered JSON parsing (8am-2pm)  
  ✅ Google Drive upload via Service Account credentials   
  ✅ Multi-sheet Excel report generation  

