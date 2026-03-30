import socket
import json
import time
import uuid
from datetime import datetime
import re
from collections import defaultdict

# Configuration Variables
LOG_FILE = 'auth.log'           # The local file simulating cloud logs
LOGSTASH_HOST = '127.0.0.1'     # Logstash container exposed on localhost
LOGSTASH_PORT = 5000            # TCP port we configured in logstash.conf

# State to track brute force attempts
failed_logins = defaultdict(int)
BRUTE_FORCE_THRESHOLD = 3

def parse_log_line(line):
    """
    Reads a raw log line, extracts interesting fields, and returns a dictionary
    with advanced cybersecurity enrichment and threat tagging.
    """
    # Regex pattern to extract standard Linux log fields: Time, Host, Process, Message
    pattern = r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$'
    match = re.match(pattern, line.strip())
    
    # Base structure with event ID and default threat attributes
    log_data = {
        "event_id": str(uuid.uuid4()),            # Unique event ID for traceability
        "timestamp": datetime.now().isoformat(),  # Modern ISO timestamp
        "log_type": "unknown",
        "environment": "cloud-sim",
        "tags": [],
        "risk_level": "low"
    }
    
    if match:
        original_timestamp, host, process, message = match.groups()
        
        log_data.update({
            "original_timestamp": original_timestamp, # Forensic timestamp
            "host": host,                             # e.g., cloud-server
            "process": process,                       # e.g., sshd[1234]
            "message": message,                       # e.g., Failed password...
            "log_type": "authentication"              # Broad categorization
        })

        # --- Advanced Cybersecurity Threat Enrichment ---
        
        # 1 & 3: Detect Failed SSH Logins and Suspicious IPs
        failed_match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)', message)
        if failed_match:
            user, ip = failed_match.groups()
            log_data["src_ip"] = ip
            log_data["target_user"] = user
            log_data["tags"].append("failed_login")
            
            # Brute Force Detection Stateful Tracking
            failed_logins[ip] += 1
            if failed_logins[ip] >= BRUTE_FORCE_THRESHOLD:
                log_data["tags"].append("brute_force_attempt")
                log_data["tags"].append("suspicious_ip")
                log_data["risk_level"] = "high"
                
        # Handle Successful Logins mapping for context
        success_match = re.search(r'Accepted (?:publickey|password) for (\S+) from (\d+\.\d+\.\d+\.\d+)', message)
        if success_match:
            user, ip = success_match.groups()
            log_data["src_ip"] = ip
            log_data["target_user"] = user
            log_data["tags"].append("successful_login")

        # 2. Detect Privilege Escalation Attempts (sudo to root)
        if "sudo" in process or "sudo:" in message:
            log_data["tags"].append("privilege_escalation_attempt")
            if "USER=root" in message and ("COMMAND=/bin/bash" in message or "COMMAND=/bin/sh" in message):
                log_data["tags"].append("critical_escalation")
                log_data["risk_level"] = "critical"
                
        # 4. Detect Firewall Blocks indicating malicious probing or C2 communication
        if "UFW BLOCK" in message:
            log_data["log_type"] = "firewall"
            log_data["tags"].append("firewall_block")
            log_data["risk_level"] = "medium"
            
            # Extract source IP from firewall log
            ip_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                log_data["src_ip"] = ip_match.group(1)
                log_data["tags"].append("suspicious_ip")

    else:
        # Fallback if the line format is unusual
        log_data["message"] = line.strip()

    return log_data

def send_to_logstash():
    """
    Reads logs, dynamically enriches them with cybersecurity tags,
    and securely ships them to the SIEM via TCP socket.
    """
    print(f"[*] Starting advanced log shipper. Reading logs from {LOG_FILE}...")
    
    try:
        # 1. Open a new TCP Socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Connect the socket to Logstash
        print(f"[*] Connecting to Logstash SIEM at {LOGSTASH_HOST}:{LOGSTASH_PORT}...")
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        print("[+] Secure connection established.")
        
        # 3. Open the authentication log file
        with open(LOG_FILE, 'r') as file:
            for line in file:
                if not line.strip():
                    continue # Ignore empty lines
                
                # Parse the raw line and apply cybersecurity enrichment
                log_data = parse_log_line(line)
                
                # Convert the Python dictionary into a JSON payload
                json_data = json.dumps(log_data)
                
                # Send the JSON payload to Logstash securely over TCP
                sock.sendall((json_data + '\n').encode('utf-8'))
                
                # Console output summarizing the risk level and tags
                risk = log_data.get('risk_level', 'low').upper()
                tags = log_data.get('tags', [])
                print(f"[+] Shipped [Risk: {risk}] Event ID: {log_data['event_id']}")
                if tags:
                    print(f"    Tags: {', '.join(tags)}")
                
                # Sleep briefly to simulate logs streaming in real-time
                time.sleep(1)
                
    except ConnectionRefusedError:
        print("[-] Error: Connection refused. Ensure Logstash (Docker) is running on port 5000.")
    except FileNotFoundError:
        print(f"[-] Error: Log file '{LOG_FILE}' not found in the current directory.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
    finally:
        # 4. Clean up connection
        try:
            sock.close()
            print("[*] Connection to SIEM closed.")
        except:
            pass

if __name__ == "__main__":
    send_to_logstash()
