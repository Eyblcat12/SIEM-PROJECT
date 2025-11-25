# SIEM-PROJECT
# 🔥 SIEM-PROJECT  


## 📖 Overview
This project builds a complete, professional SIEM system capable of detecting advanced cyber threats that traditional rule-based systems might miss. It bridges the gap between raw log collection and actionable intelligence using Machine Learning and Threat Intelligence APIs.

Key Capabilities:
- Collecting logs from multiple endpoints  
- Detecting anomalies using AI models  
- Performing automatic Threat Intelligence lookups  
- Sending instant real-time alerts  
- Generating professional incident PDF reports  


## 🚀 1. Architecture Overview
The system operates on a continuous automation pipeline:
```
      
        ┌─────────────────┐               ┌─────────────────┐
        │ Attack Scenario │────────────▶ │   Wazuh Agent    |
        │ (Simulation)    │               │ (Windows/Linux) │
        └─────────────────┘               └────────┬────────┘
                                                │
                                                ▼
                                       ┌─────────────────┐
                                       │  Wazuh Manager  │
                                       │    (Server)     │
                                       └────────┬────────┘
                                                │ (Log Storage)
                                                ▼
┌──────────────────────┐        ┌──────────────────────────────┐
│   Actionable Output  │◀───────│       AI SIEM ENGINE         │
│----------------------│        │-----------------------------  │
│ 1. 📲 Telegram Alert │◀───────│ • Fetch Logs (API)           │
│ 2. 📄 PDF Report     │        │ • AI Analysis (RandomForest) │
│ 3. 📊 Dashboard      │        │ • Threat Intel Lookup (VT)   │
└──────────────────────┘        └──────────────────────────────┘
```

---

## 🚀 Features & Tech Stack

### 🛠️ Core Components
- **Wazuh**: Open-source SIEM for log collection, integrity monitoring (FIM), and rule-based detection.
- **Python**: The backbone for automation, API integration, and AI logic.
### 🤖 AI & Intelligence 
- Machine Learning: Uses scikit-learn (Random Forest / TF-IDF) to classify malicious command lines and behavioral patterns.
- Threat Enrichment:
    - 🦠 **VirusTotal API**: Scans file hashes for malware. 
    - 🚫 **AbuseIPDB API**: Verifies reputation of source IP addresses.
### 🔔 Automation
- **Orchestrator**: ***main_pipeline.py*** ensures continuous monitoring (cron-like behavior).
- **Telegram Bot**: Delivers critical alerts directly to mobile devices.
- **PDF Generator**: Creates daily incident summaries for SOC analysts

## **📂 Project Structure**
```

SIEM-PROJECT/
├── ai-engine-v3/
│   ├── config.py             
│   ├── inference.py        
│   └── train_model.py      
│   ├── preprocess.py       
│   ├── report_genarator.py 
│   └── ti_lookup.py
|   │__ utils.py
|   |__ requirement.txt 
├── scripts/
│   ├── fetch_alerts.py     # Fetches real-time logs from Wazuh API
│   ├── send_telegram.py    # Telegram alert module
│   └── simulate_attack.bat # ⚔️ "One-Click" Attack Simulation
├── reports/                # Generated PDF reports stored here
├── main_pipeline.py        # 🚀 MASTER SCRIPT (Orchestrator)
├── wazuh_data.csv          # Temporary data buffer
├── .env                    # API Keys & Config (Private)
└── README.md
```
---

## ⚔️ Attack Lab (Simulation)
This project includes a Windows Batch script (scripts/simulate_attack.bat) to safely simulate real-world attacks for demo purposes:
- Reconnaissance: Network scanning, port checking.
- Persistence: Creating backdoor users (hacker_demo), adding to Admin group.
- Defense Evasion: Disabling Firewall, clearing Event Logs.
- Malware Execution: Downloading EICAR test files, executing suspicious PowerShell scripts.

---

## ⚙️ Installation & Setup
### 1.Prerequisites
- Python 3.10+  
- Wazuh Server (Virtual Machine or Cloud)
- Wazuh Agent installed on a Windows/Linux endpoint.
### 2. Clone Repository
- git clone [https://github.com/Eyblcat12/siem-project.git](https://github.com/Eyblcat12/siem-project.git)
### 3. Configure Environment
Create a .env file in the root directory:
```
# Wazuh Config
WAZUH_API_URL="https://<YOUR_WAZUH_IP>:9200"
WAZUH_USER="admin"
WAZUH_PASS="<YOUR_PASSWORD>"

# Threat Intel APIs
VIRUSTOTAL_API_KEY="<YOUR_VT_KEY>"
ABUSEIPDB_API_KEY="<YOUR_ABUSEIPDB_KEY>"

# Telegram Alerts
TELEGRAM_BOT_TOKEN="<YOUR_BOT_TOKEN>"
TELEGRAM_CHAT_ID="<YOUR_CHAT_ID>"
```
## **🏃‍♂️ Usage**
```
cd ai-engine
pip install -r requirements.txt
python ai_filter.py
```
### Step 1: Start the Monitoring Pipeline
Run the main orchestrator. It will fetch logs every 60 seconds.
```
python main_pipeline.py

```
### Step 2: Trigger an Attack (Demo)
On the victim machine (Windows), run the simulation script as Administrator:

```
scripts\simulate_attack.bat

```

### Step 3: Observe Results
- Console: You will see the pipeline processing logs -> "🚨 Threat Detected"
- Mobile: Check Telegram for instant alerts.
- Folder: Check /reports for the generated PDF.
---

## 📊 Dashboards & Screenshots

---

##  Roadmap

- [x] Integrate Wazuh with Python 
- [x] Implement AI Detection Model 
- [x] Threat Intelligence Lookup
- [ ] Add ELK Stack (Elasticsearch) native integration
- [ ] Develop a ReactJS Frontend for the AI Engine
- [ ] Add YARA rules for advanced malware scanning 


## 👤 Author
**Noriko (Ho Ngoc Duc)**  
Student @ PTIT — Security / SOC / DFIR / Threat Intelligence  

---

## 📄 License
MIT License. Free for personal & educational use.

