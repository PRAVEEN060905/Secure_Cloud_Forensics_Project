# 🚀 Commands to Run - Secure Cloud Forensics Project

Follow these steps to set up and run the project.

---

## 1️⃣ Start WSL (Ubuntu)

Open terminal and run:
```bash
wsl
2️⃣ Navigate to Project Directory
cd "/mnt/c/Users/prave/cyber forensics/Secure_Cloud_Forensics_Project"
3️⃣ Start Docker Services (Elastic Stack)
docker compose up -d

⏳ Wait 1–2 minutes for all services to start.

4️⃣ Verify Containers are Running
docker ps

You should see:

Elasticsearch
Logstash
Kibana
5️⃣ Run Log Shipper (Send Logs)
python3 log_shipper.py

✔️ This will send logs to Logstash → Elasticsearch

6️⃣ Verify Logs in Elasticsearch

Open browser:

http://localhost:9200/cloud-logs-*/_search?pretty
7️⃣ Open Kibana Dashboard

Go to:

http://localhost:5601
8️⃣ Create Data View in Kibana
Go to: Stack Management → Data Views
Create:
cloud-logs-*
Select timestamp as time field
9️⃣ Perform Threat Analysis

Use these queries:

tags: "brute_force_attempt"
risk_level: "high"
tags: "firewall_block"
src_ip: "192.168.1.100"
🔟 Verify Log Integrity (Forensics Step)
sha256sum auth.log

✔️ Ensures logs are not tampered