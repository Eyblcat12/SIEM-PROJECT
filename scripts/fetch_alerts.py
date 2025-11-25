import requests
import json
import pandas as pd
import urllib3
import time
import sys
import os
sys.stdout.reconfigure(encoding='utf-8')
# Tắt cảnh báo chứng chỉ SSL tự ký 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CẤU HÌNH ---
INDEXER_URL = "https://192.168.44.138:9200"
USERNAME = "admin"
PASSWORD = "admin"  
# -----------------------------------------------------------

def fetch_latest_alerts(limit=1000):
    """
    Hàm này kết nối vào Database Wazuh để lấy log cảnh báo MỚI NHẤT (Trong 2 phút qua)
    """
    print(f"🔌 Đang kết nối tới {INDEXER_URL}...")
    
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"
    
    # --- SỬA ĐỔI QUAN TRỌNG: THÊM BỘ LỌC THỜI GIAN ---
    payload = {
        "size": limit,
        "query": {
            "bool": {
                "must": [
                    # Chỉ lấy log trong khoảng thời gian từ (Bây giờ - 2 phút) đến hiện tại
                    {
                        "range": {
                            "timestamp": {
                                "gte": "now-5m", 
                                "lt": "now"
                            }
                        }
                    }
                    # Nếu Wazuh của bạn dùng trường '@timestamp' thì sửa chữ 'timestamp' ở trên thành '@timestamp' nhé
                ]
            }
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
        response = requests.get(
            url, 
            auth=(USERNAME, PASSWORD), 
            json=payload, 
            verify=False, 
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            hits = data['hits']['hits']
            print(f"✅ Thành công! Đã lấy được {len(hits)} cảnh báo MỚI.")
            
            clean_logs = [hit['_source'] for hit in hits]
            return clean_logs
        else:
            print(f"❌ Lỗi kết nối: {response.status_code}")
            print(response.text)
            return []

    except Exception as e:
        print(f"❌ Lỗi nghiêm trọng: {e}")
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
    PROJECT_ROOT = "D:/SIEM-PROJECT"
    if logs:
        # Lưu file ra thư mục gốc của dự án (..) để dễ thấy
        csv_path = os.path.join(PROJECT_ROOT, "wazuh_data.csv")
        save_to_csv(logs, csv_path)
        print(f"\n🎉 Xong! Đã cập nhật dữ liệu mới vào: {csv_path}")
    else:
        print("\n⚠️ Không có log mới trong 5 phút qua. Hệ thống đang chờ...")