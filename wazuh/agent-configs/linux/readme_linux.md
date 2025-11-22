# Linux Agent Setup Guide

## 1. Install Wazuh Agent
curl -s https://packages.wazuh.com/4.x/install.sh | bash

## 2. Register Agent
/var/ossec/bin/agent-auth -m <MANAGER_IP>

## 3. Replace ossec.conf
cp ossec.conf /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent

## 4. Apply Auditd rules
cp auditd.rules /etc/audit/rules.d/audit.rules
systemctl restart auditd

## 5. Verify
tail -f /var/ossec/logs/ossec.log
