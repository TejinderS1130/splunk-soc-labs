**SOC Lab: SSH Brute Force & Password Spraying Detection**
Splunk SIEM | Incident Triage | MITRE ATT&CK | Automated Containment
 
**Overview**
This project simulates real-world SSH authentication attacks against a Linux server and demonstrates an end-to-end Security Operations Centre (SOC) workflow aligned with Canadian enterprise environments.

The lab replicates:
Detection → Investigation → Classification → Containment → Validation → Documentation
Technologies used:
•	Splunk Enterprise (SIEM)
•	Splunk Universal Forwarder
•	Kali Linux (Hydra)
•	CentOS Linux
•	Fail2Ban (Automated containment)
 
SOC Analyst Relevance
This project demonstrates practical Tier-1 / Tier-2 SOC capabilities:
•	SIEM log monitoring and triage
•	Detection rule development and tuning
•	Distinguishing brute force vs password spraying attacks
•	Multi-user correlation logic
•	MITRE ATT&CK mapping
•	Alert threshold design to reduce false positives
•	Automated containment implementation
•	Structured incident documentation
This mirrors workflows used in Canadian enterprise SOC environments.
 
**Lab Architecture**
Component	Role

Kali Linux	Attack simulation
CentOS Server	Target host
Splunk Enterprise	SIEM
Universal Forwarder	Log ingestion
Fail2Ban	Automated containment

Logs monitored:
•	/var/log/secure
•	/var/log/messages
Forwarding via TCP port 9997.
 
**Log Ingestion & SIEM Configuration**

Install Universal Forwarder
sudo rpm -ivh splunkforwarder-10.x.x.rpm
sudo /opt/splunkforwarder/bin/splunk start --accept-license
Configure Forwarding
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.192.5:9997
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/secure
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/messages
Validate Connectivity
sudo /opt/splunkforwarder/bin/splunk list forward-server
Verification query:
index=* source="/var/log/secure"
 
**Incident A — SSH Brute Force (T1110.001)**
Attack Simulation
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.64.10 -t 4
Indicators Observed
•	High-frequency login failures
•	Single account targeted (root)
•	Same source IP
•	Time-based spike
Detection Query
source="/var/log/secure" "Failed password"
| timechart span=10s count
MITRE ATT&CK Mapping
•	Tactic: Credential Access
•	Technique: T1110 – Brute Force
•	Sub-technique: T1110.001 – Password Guessing
 
**Incident B — Password Spraying (T1110.003)**

Attack Simulation
sudo hydra -L users.txt -p Welcome123 ssh://192.168.64.10 -t 1
Indicators Observed
•	Same password reused
•	Multiple accounts targeted
•	Lower rate per user
•	Same source IP

Detection Engineering (Correlation Logic)
source="/var/log/secure" "Failed password"
| rex "for (?<user>\w+)"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(user) as unique_users count as attempts by src_ip
| where unique_users >= 3
Results
•	unique_users = 4
•	attempts = 78
•	src_ip = 192.168.64.11
MITRE ATT&CK Mapping
•	Tactic: Credential Access
•	Technique: T1110 – Brute Force
•	Sub-technique: T1110.003 – Password Spraying
 
**Incident C — SSH Reconnaissance (T1595)**
Detection Query
source="/var/log/secure" "Did not receive identification string"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
MITRE ATT&CK Mapping
•	Tactic: Reconnaissance
•	Technique: T1595 – Active Scanning
 
**Automated Containment — Fail2Ban**
SSH Jail Configuration
[sshd]
enabled = true
port = ssh
logpath = /var/log/secure
maxretry = 3
findtime = 300
bantime = 600
Validation
sudo fail2ban-client status sshd
Result:
•	Banned IP: 192.168.64.11
•	Automated containment successful
Splunk verification:
source="/var/log/secure" "fail2ban"
 
**Incident Triage Workflow**
1.	Alert triggered on abnormal authentication spike
2.	Validated log source integrity
3.	Extracted source IP and targeted accounts
4.	Classified attack type (Brute Force vs Password Spraying)
5.	Mapped activity to MITRE ATT&CK
6.	Deployed containment control
7.	Validated IP ban effectiveness
8.	Documented findings and detection logic
 
**False Positive Considerations**
Detection thresholds were tuned to reduce noise:
•	Required ≥ 3 unique users for password spraying classification
•	Used time-based anomaly detection for brute force identification
•	Correlated consistent source IP before escalation
 
**MITRE ATT&CK Coverage Summary**
Incident	Tactic	Technique
SSH Brute Force	Credential Access	T1110.001
Password Spraying	Credential Access	T1110.003
SSH Recon	Reconnaissance	T1595
