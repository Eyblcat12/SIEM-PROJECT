## 📋 Yêu cầu hệ thống (Prerequisites)

  Thành phần   Yêu cầu tối thiểu          Khuyên dùng
  ------------ -------------------------- ------------------
  **OS**       Ubuntu 22.04 / 20.04 LTS   Ubuntu 22.04 LTS
  **RAM**      4 GB                       8 GB+
  **CPU**      2 vCPU                     4 vCPU
  **Disk**     20 GB                      50 GB+

**⚠️ Lưu ý:** Bạn PHẢI đặt IP tĩnh trước khi cài đặt để tránh lỗi SSL
khi reboot.

## 🚀 Phần 1: Cài đặt các thành phần Core

### Thêm Wazuh Repository

``` bash
sudo apt-get install apt-transport-https zip unzip lsb-release curl gnupg -y
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
```

### Cài đặt Wazuh Indexer

``` bash
sudo apt-get install wazuh-indexer -y
```

Nếu RAM \< 8GB sửa `/etc/wazuh-indexer/jvm.options`: - -Xms1g →
-Xms512m - -Xmx1g → -Xmx512m

``` bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer
```

### Cài đặt Wazuh Manager

``` bash
sudo apt-get install wazuh-manager -y
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

### Cài đặt Wazuh Dashboard

``` bash
sudo apt-get install wazuh-dashboard -y
```

Sửa `/etc/wazuh-dashboard/opensearch_dashboards.yml`: - server.host:
"0.0.0.0" - opensearch.hosts: \["https://`<IP-SERVER>`{=html}:9200"\]

``` bash
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
```

## 🔐 Phần 2: SSL Certificates

### Tạo chứng chỉ

``` bash
curl -sO https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
```

Sửa config.yml → thay \<...-ip\> bằng IP thật.

``` bash
sudo bash wazuh-certs-tool.sh -A
```

### Phân phối chứng chỉ

#### Indexer

``` bash
sudo mkdir -p /etc/wazuh-indexer/certs
sudo cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/
sudo cp wazuh-certificates/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
sudo cp wazuh-certificates/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
sudo cp wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/
sudo cp wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/
sudo chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
sudo chmod 500 /etc/wazuh-indexer/certs
sudo chmod 400 /etc/wazuh-indexer/certs/*
sudo systemctl restart wazuh-indexer
```

#### Dashboard

``` bash
sudo mkdir -p /etc/wazuh-dashboard/certs
sudo cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/
sudo cp wazuh-certificates/dashboard.pem /etc/wazuh-dashboard/certs/dashboard.pem
sudo cp wazuh-certificates/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
sudo chmod 500 /etc/wazuh-dashboard/certs
sudo chmod 400 /etc/wazuh-dashboard/certs/*
sudo systemctl restart wazuh-dashboard
```

### Khởi tạo Security

``` bash
sudo env JAVA_HOME=/usr/share/wazuh-indexer/jdk \
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem
```

## 🔗 Phần 3: Filebeat

### Cài đặt

``` bash
sudo apt-get install filebeat -y
```

### Copy chứng chỉ

``` bash
sudo mkdir -p /etc/filebeat/certs
sudo cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/
sudo cp wazuh-certificates/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
sudo cp wazuh-certificates/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
sudo chown -R root:root /etc/filebeat/certs
sudo chmod 500 /etc/filebeat/certs
sudo chmod 400 /etc/filebeat/certs/*
```

### Kích hoạt

``` bash
sudo filebeat setup --index-management
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

## ✅ Hoàn thành

Truy cập Dashboard tại:

https://`<IP-SERVER>`{=html}

User: admin\
Pass: admin (hoặc mật khẩu bạn đã đổi)
