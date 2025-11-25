import requests
import json
import sys
from utils import logger
import os
from dotenv import load_dotenv

# Load .env
load_dotenv()

# Lấy API key từ biến môi trường
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
# --- CẤU HÌNH API KEY (Thay bằng key của bạn) ---
# Khuyên dùng biến môi trường để bảo mật hơn.


# --- CẤU HÌNH NGƯỠNG (Threshold) ---
# Nếu AbuseIPDB báo confidence > 50% thì coi là độc hại
ABUSEIPDB_THRESHOLD = 50 
# Nếu VirusTotal có > 3 engines báo đỏ thì coi là độc hại

VIRUSTOTAL_THRESHOLD = 3

def check_ip_abuseipdb(ip_address):
    """
    Kiểm tra uy tín IP trên AbuseIPDB.
    Trả về: (is_malicious, confidence_score, country)
    """
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        logger.warning("⚠️ Chưa cấu hình AbuseIPDB API Key.")
        return False, 0, "Unknown"

    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            country = data.get('countryCode', 'Unknown')
            
            is_malicious = score >= ABUSEIPDB_THRESHOLD
            if is_malicious:
                logger.info(f"🚫 AbuseIPDB: IP {ip_address} là ĐỘC HẠI (Score: {score}%)")
            
            return is_malicious, score, country
        else:
            logger.error(f"Lỗi AbuseIPDB: {response.status_code}")
            return False, 0, "Error"
    except Exception as e:
        logger.error(f"Lỗi kết nối AbuseIPDB: {e}")
        return False, 0, "Error"

def check_hash_virustotal(file_hash, file_path=None):
    """
    Kiểm tra mã băm (MD5/SHA256) trên VirusTotal.
    Trả về: (is_malicious, positives_count, total_engines)
    """
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        logger.warning("⚠️ Chưa cấu hình VirusTotal API Key.")
        return False, 0, 0

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']['attributes']['last_analysis_stats']
            malicious = data.get('malicious', 0)
            total = sum(data.values())
            
            is_malicious = malicious >= VIRUSTOTAL_THRESHOLD
            if is_malicious:
                log_msg = f"🦠 VirusTotal: PHÁT HIỆN MALWARE! ({malicious}/{total})"
                log_msg += f"\n   - Hash: {file_hash}"
                if file_path:
                    log_msg += f"\n   - 📂 Đường dẫn file: {file_path}" # In đường dẫn tại đây
                
                logger.info(log_msg)
            return is_malicious, malicious, total
        elif response.status_code == 404:
            logger.info(f"VirusTotal: Hash {file_hash} chưa từng được quét.")
            return False, 0, 0
        else:
            logger.error(f"Lỗi VirusTotal: {response.status_code}")
            return False, 0, 0
    except Exception as e:
        logger.error(f"Lỗi kết nối VirusTotal: {e}")
        return False, 0, 0

if __name__ == "__main__":
    # Test thử
    print("--- TESTING TI LOOKUP ---")
    
    # 1. Test IP (IP của Google DNS - Sạch)
    print("\nChecking IP 8.8.8.8:")
    check_ip_abuseipdb("8.8.8.8")
    
    # 2. Test Hash (Hash của EICAR Test File - Virus giả lập)
    eicar_md5 = "44d88612fea8a8f36de82e1278abb02f"
    fake_path = "C:\\Windows\\System32\\suspicious_file.exe" # Giả lập đường dẫn
    print(f"\nChecking Hash {eicar_md5}:")
    check_hash_virustotal(eicar_md5,file_path=fake_path)