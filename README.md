# SIEM-PROJECT
# 🔥 SIEM-PROJECT  


### AI‑Enhanced Wazuh SIEM for Threat Detection, Log Intelligence & Automated Reports

This project builds a **complete, professional SIEM system** using **Wazuh**, enhanced with:

- ✔ AI log filtering (noise reduction, clustering, summarization)
- ✔ Threat Intelligence enrichment (VirusTotal, OTX, AbuseIPDB, GreyNoise)
- ✔ Automated incident reporting (PDF/Markdown)
- ✔ Real attack monitoring (SSH brute force, web attacks, malware execution)
- ✔ Real‑time alerting (Telegram/Discord)
- ✔ Custom dashboards and actionable insights

This is a **full SOC-grade project**, suitable for portfolio, CV, and real monitoring labs.

---

## 🚀 1. Architecture Overview

```
                        ┌──────────────────────────┐
                        │   Wazuh AIO (1 VM)       │
                        │ Manager + Indexer + Dash │
                        └───────────┬──────────────┘
                                    │ REST API
                                    ▼
                       ┌──────────────────────────┐
                       │      AI Engine (Python)  │
                       │--------------------------│
                       │ • AI log filtering       │
                       │ • Threat Intel lookups   │
                       │ • Auto PDF reporting     │
                       │ • Incident correlation   │
                       └──────────┬───────────────┘
                                   ▼
                 ┌────────────────────────────────────┐
                 │  Telegram / Discord Notifications  │
                 └────────────────────────────────────┘


Monitored machines:
- Ubuntu (SSH brute-force)
- DVWA Web Server (path traversal, SQLi, RFI)
- Windows 10 (Sysmon + malware execution)
```

---

## ⚔️ 2. Attack Lab Included

### **Brute Force SSH**
```
hydra -l root -P rockyou.txt ssh://target-ip
```

### **Path Traversal**
```
http://dvwa/?page=../../../../etc/passwd
```

### **SQL Injection**
```
sqlmap -u "http://dvwa/sqli/?id=1&Submit=Submit"
```

### **Windows Malware Execution**
- EXE dropper  
- PowerShell payload  
- Registry persistence  

Sysmon + Wazuh captures all related events.

---

## 🤖 3. AI Features

### **3.1 AI Log Filtering**
- Classifies events (benign / suspicious / malicious)
- Removes noise
- Groups campaigns
- Summarizes daily incidents

### **3.2 Threat Intelligence Enrichment**
Queries:
- VirusTotal  
- AbuseIPDB  
- OTX  
- GreyNoise  

Outputs:
- IOC reputation  
- Associated malware families  
- Campaign attribution  
- Confidence score  

### **3.3 Automated Incident Reports**
Daily reports include:
- Executive summary  
- MITRE ATT&CK mapping  
- IOC list  
- Attack timeline  
- Remediation steps  
- Severity classification  

Generates:
- `reports/YYYY-MM-DD-report.pdf`

---

## 📁 4. Repository Structure

```
SIEM-PROJECT/
├─ README.md
├─ wazuh/
│  ├─ aio-install-guide.md
│  ├─ agent-configs/
│  └─ dashboards/
├─ ai-engine/
│  ├─ ai_filter.py
│  ├─ report_generator.py
│  ├─ ti_lookup.py
│  ├─ requirements.txt
├─ attack-lab/
│  ├─ brute_force.md
│  ├─ dvwa_attack.md
│  ├─ malware_windows.md
├─ docs/
│  ├─ architecture_diagram.png (placeholder)
│  ├─ mitre_mapping.md
│  └─ use_cases.md
├─ scripts/
│  ├─ fetch_alerts.py
│  ├─ send_telegram.py
│  └─ scheduler.sh
├─ reports/
│  └─ example_report.pdf (placeholder)
└─ .gitignore
```

---

## 🛠 5. Installation

### **Install Wazuh AIO**
See:
```
wazuh/aio-install-guide.md
```

### **Start AI Engine**
```
cd ai-engine
pip install -r requirements.txt
python ai_filter.py
```

---

## 🧪 6. Running the Attack Lab

See:
```
attack-lab/
```

Each attack has full steps + expected logs + how Wazuh triggers rules.

---

## 📊 7. Dashboards Included

- SSH Bruteforce Dashboard  
- Web Attack Dashboard  
- Windows Malware Dashboard  

Import via:
```
wazuh/dashboards/
```

---

## 📄 8. Example Report

Generated report sample:
```
reports/example_report.pdf
```

---

## 🎯 9. Roadmap

- [ ] Add YARA malware detection  
- [ ] Add ELK integration  
- [ ] Add ML anomaly detection  
- [ ] Add honeypot log ingestion  

---

## 👤 Author
**Noriko (Ho Ngoc Duc)**  
Student @ PTIT — Security / SOC / DFIR / Threat Intelligence  

---

## 📄 License
MIT License. Free for personal & educational use.

