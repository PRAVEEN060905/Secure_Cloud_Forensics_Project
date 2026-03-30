# Secure Cloud Log Collection and Forensic Analysis Using SIEM Tools

This comprehensive guide provides everything you need to implement a beginner-friendly cyber forensics project. You will simulate a cloud logging environment, securely collect logs, analyze them using a SIEM tool (the Elastic Stack), and learn how to verify digital evidence integrity.

---

## 1. Environment Setup (Windows & WSL)

We will use Windows Subsystem for Linux (WSL) running Ubuntu to accurately simulate a cloud environment structure and test our setup natively.

### Steps to Install:
1. Open **PowerShell** as Administrator.
2. Run the following command to install WSL and Ubuntu:
   ```powershell
   wsl --install
   ```
   *(If prompted, restart your computer).*
3. **Verify Installation**: After the reboot, open the **Ubuntu** application from the Windows Start menu or run `wsl` in Windows Terminal to enter your Linux bash shell.

---

## 2. Docker Setup

We use Docker to run the SIEM tools (Elasticsearch, Logstash, Kibana) because setting up complex big data infrastructure natively is difficult. Docker provides lightweight, pre-configured instances out-of-the-box.

1. **Install Docker Desktop**: Download it from [docker.com](https://www.docker.com/products/docker-desktop) and run the installer.
2. **Enable WSL Integration**: 
   - Open Docker Desktop.
   - Go to **Settings** (gear icon) -> **Resources** -> **WSL Integration**.
   - Check the box enabling integration for your default WSL distro (`Ubuntu`).

---

## 3. Deploying the Elastic Stack (SIEM)

In the project folder, we have created a `docker-compose.yml` file. Here is the role of each component it spins up:
- **Elasticsearch**: The core data engine. It receives, stores, and searches the log data securely.
- **Logstash**: The pipeline. It receives data from our Python script, ensures it's properly formatted (JSON), and forwards it to Elasticsearch.
- **Kibana**: The visual analyzer. An interface that connects to Elasticsearch allowing us to query and visualize the logs.

### Instructions to run:
1. Open your Ubuntu terminal (`wsl`).
2. Navigate to this project directory:
   ```bash
   cd "/mnt/c/Users/prave/cyber forensics/Secure_Cloud_Forensics_Project"
   ```
3. Run the following command to download and start the tools in the background:
   ```bash
   docker compose up -d
   ```
   *(Note: This might take a few minutes the first time as it downloads the images).*

---

## 4. Logstash Configuration

The `logstash.conf` file is already created in the project folder.
- **Input**: Listens on TCP port 5000 and expects `json` data.
- **Output**: Forwards the parsed data into `elasticsearch` securely over HTTP on port 9200.

---

## 5. Log Source Simulation (Advanced Cyber Events)

We have generated an `auth.log` file representing an exposed cloud server. It contains several simulated and critical forensic events:
- **Brute Force Attacks**: Repeated `Failed password for invalid user admin...` from `192.168.1.100`.
- **Targeted Attacks**: `Failed password for root...`
- **Successful Logins**: `Accepted publickey for ubuntu...`
- **Privilege Escalation**: `sudo: ubuntu... COMMAND=/bin/bash` representing lateral movement to root.
- **Firewall Drops**: `UFW BLOCK... SRC=10.0.0.5 DST=198.51.100.22` representing suspicious outbound connections to malicious IPs.

---

## 6. Python Log Shipper (Advanced Cybersecurity Features)

The `log_shipper.py` script acts as our advanced telemetry and security agent. It parses lines to structured **JSON** and enriches them with intelligent threat indications:
1. **Unique Event IDs**: Generates a UUID for every log element to trace events effortlessly.
2. **Stateful Brute Force Detection**: Remembers IPs failing logins consecutively. Upon reaching a threshold, it tags the IP as a `suspicious_ip` and flags the event as a `brute_force_attempt`.
3. **Privilege Escalation Tracking**: Spots `sudo` to `/bin/bash` and tags it as `critical_escalation`, elevating the `risk_level` to `critical`.
4. **Firewall Blocks**: Identifies dropped network connections, extracting the source IPs automatically.
5. **Automatic Tagging**: Every event dynamically receives properties like `"tags": ["failed_login", "suspicious_ip"]` and `"risk_level": "high"` before being streamed securely over a TCP socket to the SIEM.

---

## 7. Running the Log Shipper

Now it is time to feed your evidence into the SIEM.

1. Ensure your Docker containers have fully started.
2. Inside your Ubuntu/WSL terminal, execute the shipper:
   ```bash
   python3 log_shipper.py
   ```
3. You will see colored/structured output validating `JSON` events being shipped, complete with their evaluated Risk Levels and associated Threat Tags. 

---

## 8. Verifying Log Ingestion

To confirm that Elasticsearch has safely stored our enriched evidence:

1. Open your web browser.
2. Navigate directly to the Elasticsearch API endpoint:
   [http://localhost:9200/cloud-logs-*/_search?pretty](http://localhost:9200/cloud-logs-*/_search?pretty)
   
**What does the JSON Output mean?**
- You will see the injected `"event_id"`, `"risk_level"`, and `"tags"` in the native document body, verifying the ingestion pipeline functions seamlessly.

---

## 9. Log Analysis Using Kibana (Hunting Threats)

Let's do the actual forensic analysis visually using our new threat tags.

1. **Open Kibana** at [http://localhost:5601](http://localhost:5601).
2. **Create a Data View** (if you haven't yet):
   - Scroll down to **Management** -> **Stack Management** -> **Data Views**.
   - Create data view: `cloud-logs-*` utilizing `timestamp` as the primary field.
3. **Hunt for Threats**:
   - Open the menu ☰ and click **Analytics** -> **Discover**.
   - Your logs will appear! Thanks to our advanced pipeline, you can easily query using our dynamic tagging system instead of raw text.
   - Use the **Search Bar Filter** to find specific issues easily:
     - `tags: "brute_force_attempt"`
     - `risk_level: "critical" OR risk_level: "high"`
     - `tags: "firewall_block" AND tags: "suspicious_ip"`
     - `src_ip: "192.168.1.100"`

---

## 10. Evidence Integrity Verification (Hashing)

In a court of law or professional investigation, you must prove the original log file (`auth.log`) was not edited or tampered with by a malicious actor. We do this by calculating its unique cryptographic hash (SHA-256).

1. In your Ubuntu/WSL terminal, run:
   ```bash
   sha256sum auth.log
   ```
2. **Output example**:
   `e4b2d55... auth.log`
3. **Why this works**:
   If an attacker opens `auth.log` and deletes the logs containing their `suspicious_ip`, the file contents change. Even removing a single space will drastically alter the SHA-256 hash. When investigators re-hash the file and match it against the original state, matching hashes guarantee the digital evidence has 100% integrity.
