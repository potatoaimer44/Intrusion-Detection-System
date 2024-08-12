# Network Intrusion Detection Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Tkinter](https://img.shields.io/badge/Tkinter-UI-red)

This repository contains two powerful cybersecurity tools built using Python: a **Web Domain Scanner** and an **Intrusion Detection System (IDS)**. These tools are designed to help security professionals and enthusiasts analyze network traffic and web domains for vulnerabilities and threats.

## Table of Contents

- [Web Domain Scanner](#web-domain-scanner)
  - [Overview](#overview-web-domain-scanner)
  - [Features](#features-web-domain-scanner)
  - [Installation](#installation-web-domain-scanner)
  - [Usage](#usage-web-domain-scanner)
  - [File Structure](#file-structure-web-domain-scanner)
- [Intrusion Detection System](#intrusion-detection-system)
  - [Overview](#overview-intrusion-detection-system)
  - [Features](#features-intrusion-detection-system)
  - [Installation](#installation-intrusion-detection-system)
  - [Usage](#usage-intrusion-detection-system)
  - [Rules Configuration](#rules-configuration)
  - [Email Alerts](#email-alerts)
  - [File Structure](#file-structure-intrusion-detection-system)
- [Contributions](#contributions)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Web Domain Scanner

### Overview

The **Web Domain Scanner** is a comprehensive tool designed to gather detailed information about a given web domain and identify potential security vulnerabilities. This tool is built using Python, leveraging Tkinter for the graphical user interface.

**GitHub Repository:** [Web Domain Scanner](https://github.com/potatoaimer44/Intrusion-Detection-System.git)

### Features

- **Domain Information Gathering:** Collects IP address, server details, CMS, and protocol information.
- **Sensitive Path Finder:** Identifies sensitive paths and files on the target domain.
- **Vulnerability Scans:** Includes scans for CORS misconfigurations, SQL Injection, XSS, Open Redirects, and more.
- **Port Scanning:** Identifies open ports and associated vulnerabilities.
- **JavaScript URL Extraction:** Gathers all JavaScript URLs from the target domain.
- **Public Archives URL Fetching:** Extracts URLs from public archives for further analysis.
- **Directory Brute-Forcing:** Attempts to brute-force directories to find hidden files or folders.
- **Results Logging:** All scan results are saved in a structured directory for easy review.

### Installation

#### Prerequisites

- Python 3.8+
- Tkinter (usually pre-installed with Python)
- Required Python libraries (install via `requirements.txt`)

#### Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/potatoaimer44/Intrusion-Detection-System.git
   cd Intrusion-Detection-System

2. ### Install Required Dependencies
   ```bash
   pip install -r requirements.txt
   

3. ### Run the Scanner
   ```bash
    python web_scanner.py

## Usage

1. **Launch the Application:**

   - Run the `ids.py` script using Python, and the Tkinter GUI will open.

2. **Select Network Interface:**

   - Choose the network interface you want to monitor from the dropdown menu.

3. **Start Sniffing:**

   - Click the `Start Sniffing` button to begin monitoring network traffic.

4. **View Alerts:**

   - Alerts for any suspicious activity detected based on your predefined rules will be displayed in the alert table.

5. **Stop Sniffing:**

   - Click the `Stop Sniffing` button to stop monitoring the network.

## Rules Configuration

- Rules are defined in the `rules.txt` file. Each rule should follow this format:


- **Example:**
  ```
  alert tcp 192.168.1.100 any -> 192.168.1.1 80 Possible HTTP Traffic
  ```

- **Explanation:**
  - `alert`: The action to be taken when the rule is matched.
  - `<protocol>`: The protocol to match (e.g., `tcp`, `udp`, or `any`).
  - `<source_ip>`: The source IP address to match (or `any`).
  - `<source_port>`: The source port to match (or `any`).
  - `->`: Indicates the direction of traffic.
  - `<dest_ip>`: The destination IP address to match (or `any`).
  - `<dest_port>`: The destination port to match (or `any`).
  - `<alert_message>`: A message that will be displayed or logged when the rule is triggered.

## Email Alerts

- The IDS sends email alerts for detected threats. To configure the email settings, you need to modify the `PacketSniffer.send_alert` method in the code.

- **Configuration:**

  Update the following parameters with your email details:

  ```python
  smtp_server = 'smtp.gmail.com'
  smtp_port = 587
  sender_email = 'your_email@gmail.com'
  receiver_email = 'recipient_email@gmail.com'
  password = 'your_email_password'

## File Structure

Intrusion-Detection-System/
│
├── ids.py # Main application script
├── rules.txt # File containing detection rules
├── ids.log # Log file for detected alerts
├── requirements.txt # Python dependencies
└── README.md # Project documentation
