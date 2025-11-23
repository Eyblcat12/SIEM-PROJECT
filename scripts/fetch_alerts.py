import requests
import json
import pandas as pd
import urllib3
import time
import sys

sys.stdout.reconfigure(encoding='utf-8')
# Tắt cảnh báo chứng chỉ SSL tự ký 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CẤU HÌNH ---
INDEXER_URL = "https://192.168.44.138:9200"
USERNAME = "admin"
PASSWORD = "admin"  
# -----------------------------------------------------------

def fetch_latest_alerts(limit=500):
    """
    Hàm này kết nối vào Database Wazuh để lấy log cảnh báo
    """
    print(f"🔌 Đang kết nối tới {INDEXER_URL}...")
    
    # Đường dẫn API tìm kiếm trong Indexer
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"
    
    # Query: Lấy log mới nhất
    payload = {
        "size": limit,
        "query": {
            "match_all": {} 
        },
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ]
    }

    try:
        # Gửi request
        response = requests.get(
            url, 
            auth=(USERNAME, PASSWORD), 
            json=payload, 
            verify=False, # Bỏ qua check SSL
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            hits = data['hits']['hits']
            print(f"✅ Thành công! Đã lấy được {len(hits)} cảnh báo.")
            
            # Trích xuất dữ liệu sạch (chỉ lấy phần _source)
            clean_logs = [hit['_source'] for hit in hits]
            return clean_logs
        else:
            print(f"❌ Lỗi kết nối: {response.status_code}")
            print(response.text)
            return []

    except Exception as e:
        print(f"❌ Lỗi nghiêm trọng: {e}")
        print("💡 Gợi ý: Kiểm tra lại xem Ubuntu đã mở port 9200 chưa? (sudo ufw allow 9200)")
        return []

def save_to_json(data, filename="wazuh_alerts.json"):
    """Lưu dữ liệu ra file JSON"""
    if not data: return
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"💾 Đã lưu JSON vào: {filename}")

def save_to_csv(data, filename="wazuh_alerts.csv"):
    """Lưu ra CSV để xem bằng Excel"""
    if not data: return
    # Làm phẳng dữ liệu JSON
    df = pd.json_normalize(data)
    df.to_csv(filename, index=False)
    print(f"💾 Đã lưu CSV vào: {filename}")

# --- CHẠY CHƯƠNG TRÌNH ---
if __name__ == "__main__":
    print("--- BẮT ĐẦU THU THẬP DỮ LIỆU ---")
    logs = fetch_latest_alerts()
    
    if logs:
        # Lưu file ra thư mục gốc của dự án (..) để dễ thấy
        save_to_json(logs, "../wazuh_data.json")
        save_to_csv(logs, "../wazuh_data.csv")
        print("\n🎉 Xong! Kiểm tra thư mục gốc SIEM-PROJECT xem có file csv chưa.")
    else:
        print("\n⚠️ Không lấy được dữ liệu nào.")