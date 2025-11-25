import requests
import os
import sys
from dotenv import load_dotenv

# --- 1. Load cấu hình ---
# Đoạn này giúp file tìm được .env dù đang nằm trong thư mục con 'scripts'

load_dotenv()

# Nếu file nằm ngay thư mục gốc thì chỉ cần: load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_alert(message):
    """
    Gửi tin nhắn cảnh báo đến Telegram.
    """
    if not BOT_TOKEN or not CHAT_ID:
        print("⚠️  Lỗi: Chưa cấu hình TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID trong .env")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown" # Hoặc 'HTML' nếu muốn format đẹp
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            # print("✅ Đã gửi Telegram thành công!") 
            # (Comment lại để đỡ rác log khi chạy thực tế)
            return True
        else:
            print(f"❌ Lỗi gửi Telegram: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Lỗi kết nối Telegram: {e}")
        return False

# --- PHẦN TEST ĐỘC LẬP ---
# Khi chạy trực tiếp file này, nó sẽ gửi tin nhắn test.
if __name__ == "__main__":
    print("--- ĐANG TEST GỬI TELEGRAM ---")
    print(f"Token: {BOT_TOKEN[:5]}... (Đã ẩn)")
    print(f"Chat ID: {CHAT_ID}")
    
    test_msg = "🚀 *SIEM AI SYSTEM TEST*\n\nĐây là tin nhắn kiểm tra kết nối.\nNếu bạn đọc được tin này, hệ thống Alert đã hoạt động! ✅"
    
    success = send_alert(test_msg)
    if success:
        print("\n✅ THÀNH CÔNG! Hãy kiểm tra điện thoại.")
    else:
        print("\n❌ THẤT BẠI. Vui lòng kiểm tra lại Token/ID.")