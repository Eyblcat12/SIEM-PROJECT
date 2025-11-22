# Windows Agent Setup Guide

## 1. Install Wazuh Agent
Download from:
https://packages.wazuh.com

Run:
- Install > Register Agent > Put your manager IP

## 2. Replace ossec.conf
Copy ossec.conf → C:\Program Files (x86)\ossec-agent\

Restart:
net stop wazuh
net start wazuh

## 3. Install Sysmon
sysmon64.exe -i sysmon-config.xml

## 4. Verify
Check ossec.log:
C:\Program Files (x86)\ossec-agent\ossec.log

Check on Wazuh dashboard:
Agents → Status → Active
