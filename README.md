# SOC Lab: SSH Brute Force & Password Spraying Detection

![Splunk](https://img.shields.io/badge/SIEM-Splunk-black?style=for-the-badge\&logo=splunk)
![Linux](https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge\&logo=linux)
![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![SOC](https://img.shields.io/badge/Role-SOC%20Analyst-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Project-Completed-brightgreen?style=for-the-badge)

**Splunk SIEM | Incident Triage | MITRE ATT&CK | Automated Containment**

---

## Overview

This project simulates real-world SSH authentication attacks against a Linux server and demonstrates an end-to-end Security Operations Centre (SOC) workflow aligned with Canadian enterprise environments.

---

## SOC Workflow

```
Detection → Investigation → Classification → Containment → Validation → Documentation
```

---

## Technologies Used

* Splunk Enterprise (SIEM)
* Splunk Universal Forwarder
* Kali Linux (Hydra)
* CentOS Linux
* Fail2Ban (Automated containment)

---

## Lab Architecture

```
                 🌐 Internet (Attacker)
                        │
                ┌───────────────┐
                │  Kali Linux   │
                │  192.168.64.x │
                └──────┬────────┘
                       │
                 (SSH Attack)
                       │
        ┌──────────────▼──────────────┐
        │      CentOS Target Server   │
        │        192.168.64.10        │
        └──────────────┬──────────────┘
                       │
         Log Forwarding (Port 9997)
                       │
        ┌──────────────▼──────────────┐
        │     Splunk Enterprise SIEM  │
        │        192.168.192.5        │
        └──────────────┬──────────────┘
                       │
                Detection & Alerts
                       │
        ┌──────────────▼──────────────┐
        │        Fail2Ban Engine      │
        │   (Automated Containment)   │
        └─────────────────────────────┘
```

---

## Lab Components

| Component           | Role                  |
| ------------------- | --------------------- |
| Kali Linux          | Attack simulation     |
| CentOS Server       | Target host           |
| Splunk Enterprise   | SIEM                  |
| Universal Forwarder | Log ingestion         |
| Fail2Ban            | Automated containment |

---

## Logs Monitored

* `/var/log/secure`
* `/var/log/messages`

**Forwarding Port:** `9997`

---

## Log Ingestion & SIEM Configuration

## Install Universal Forwarder

```bash
sudo rpm -ivh splunkforwarder-10.x.x.rpm
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```

## Configure Forwarding

```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.192.5:9997
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/secure
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/messages
```

## Validate Connectivity

```bash
sudo /opt/splunkforwarder/bin/splunk list forward-server
```

## Verification Query

```spl
index=* source="/var/log/secure"
```

---

# Incident A — SSH Brute Force (T1110.001)

---

## Attack Simulation

```bash
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.64.10 -t 4
```

## Indicators Observed

* High-frequency login failures
* Single account targeted (root)
* Same source IP
* Time-based spike

## Detection Query

```spl
source="/var/log/secure" "Failed password"
| timechart span=10s count
```

## MITRE ATT&CK Mapping

* **Tactic:** Credential Access
* **Technique:** T1110 – Brute Force
* **Sub-technique:** T1110.001 – Password Guessing

---

# Incident B — Password Spraying (T1110.003)

---

## Attack Simulation

```bash
sudo hydra -L users.txt -p Welcome123 ssh://192.168.64.10 -t 1
```

## Indicators Observed

* Same password reused
* Multiple accounts targeted
* Lower rate per user
* Same source IP

## Detection Engineering

```spl
source="/var/log/secure" "Failed password"
| rex "for (?<user>\w+)"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(user) as unique_users count as attempts by src_ip
| where unique_users >= 3
```

### Results

* `unique_users = 4`
* `attempts = 78`
* `src_ip = 192.168.64.11`

## MITRE ATT&CK Mapping

* **Tactic:** Credential Access
* **Technique:** T1110 – Brute Force
* **Sub-technique:** T1110.003 – Password Spraying

---

# Incident C — SSH Reconnaissance (T1595)

---

## Detection Query

```spl
source="/var/log/secure" "Did not receive identification string"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

## MITRE ATT&CK Mapping

* **Tactic:** Reconnaissance
* **Technique:** T1595 – Active Scanning

---

# Automated Containment — Fail2Ban

---

## SSH Jail Configuration

```ini
[sshd]
enabled = true
port = ssh
logpath = /var/log/secure
maxretry = 3
findtime = 300
bantime = 600
```

## Validation

```bash
sudo fail2ban-client status sshd
```

## Result

* Banned IP: `192.168.64.11`
* Automated containment successful

## Splunk Verification

```spl
source="/var/log/secure" "fail2ban"
```

---

## Incident Triage Workflow

1. Alert triggered on abnormal authentication spike
2. Validated log source integrity
3. Extracted source IP and targeted accounts
4. Classified attack type (Brute Force vs Password Spraying)
5. Mapped activity to MITRE ATT&CK
6. Deployed containment control
7. Validated IP ban effectiveness
8. Documented findings and detection logic

---

## False Positive Considerations

* Required ≥ 3 unique users for password spraying classification
* Used time-based anomaly detection for brute force identification
* Correlated consistent source IP before escalation

---

## MITRE ATT&CK Coverage Summary

| Incident          | Tactic            | Technique |
| ----------------- | ----------------- | --------- |
| SSH Brute Force   | Credential Access | T1110.001 |
| Password Spraying | Credential Access | T1110.003 |
| SSH Recon         | Reconnaissance    | T1595     |

---

## Key Takeaways

* Built real-world SOC detection logic using Splunk
* Differentiated brute force vs password spraying attacks
* Implemented automated containment using Fail2Ban
* Applied MITRE ATT&CK for structured threat analysis
* Simulated full SOC incident response lifecycle

---
