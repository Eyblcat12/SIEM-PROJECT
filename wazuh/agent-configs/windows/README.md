# 💻 Hướng dẫn cài Wazuh Agent cho Windows (Siêu tốc)

Thư mục này chứa hướng dẫn để cài đặt Wazuh Agent trên Windows 10/11 và
Windows Server.

## 📥 1. Tải về (Download)

Bạn có thể tải file .msi theo 2 cách:

### ✔ Cách 1 (Tự động)

Trong Wazuh Dashboard → **Add agent** → chọn **Windows**.

### ✔ Cách 2 (Thủ công)

Tải trực tiếp:
https://packages.wazuh.com/4.x/windows/wazuh-agent-current.msi

------------------------------------------------------------------------

## ⚡ 2. Cài đặt nhanh bằng PowerShell (Khuyên dùng)

1.  Mở **PowerShell** bằng quyền **Run as Administrator**
2.  Chạy lệnh sau (nhớ đổi IP 192.168.44.138 thành IP Wazuh Server của
    bạn):

``` powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-current.msi -OutFile wazuh-agent.msi; msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='192.168.44.138' WAZUH_REGISTRATION_SERVER='192.168.44.138'

NET START WazuhSvc
```

Nếu hiện:\
**The Wazuh service was started successfully.**\
→ là OK!

------------------------------------------------------------------------

## 🛠️ 3. Tùy chọn: Bật giám sát sâu với Sysmon

### Bước 1 --- Cài Sysmon

1.  Tải Sysmon từ Microsoft\
2.  Tải file `sysmon-config.xml` (có kèm trong thư mục này)\
3.  Chạy CMD (Admin):

``` cmd
Sysmon64.exe -i sysmon-config.xml
```

### Bước 2 --- Cho Wazuh đọc log Sysmon

Thêm vào file:

    C:\Program Files (x86)\ossec-agent\ossec.conf

Đoạn sau:

``` xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Khởi động lại Agent:

``` powershell
Restart-Service -Name WazuhSvc
```

------------------------------------------------------------------------

## ✅ 4. Kiểm tra kết nối

1.  Truy cập Wazuh Dashboard\
2.  Vào **Agents**\
3.  Máy Windows phải hiện **Active** màu xanh

Nếu xanh → Chúc mừng bạn đã kết nối thành công! 🎉
