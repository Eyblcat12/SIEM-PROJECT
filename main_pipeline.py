import subprocess
import time
import sys
import os
from datetime import datetime

# --- CẤU HÌNH ---
LOOP_INTERVAL = 60  # Quét lại sau mỗi 60 giây
PYTHON_EXEC = sys.executable

# --- CẤU HÌNH ĐƯỜNG DẪN FILE (Bác sửa lại nếu khác nhé) ---
# Dựa trên ảnh của bác thì cấu trúc là:
# Root/
#   ├── scripts/fetch_alerts.py
#   ├── ai-engine-v3/inference.py
#   └── ai-engine-v3/report_generator.py

PATH_FETCH = os.path.join("scripts", "fetch_alerts.py")
PATH_INFERENCE = os.path.join("ai-engine-v3", "inference.py")
PATH_REPORT = os.path.join("ai-engine-v3", "report_generator.py")

def run_step(script_path, description):
    """Hàm chạy script con"""
    print(f"\n{'='*40}")
    print(f"🚀 {description}")
    print(f"📂 File: {script_path}")
    
    if not os.path.exists(script_path):
        print(f"❌ Lỗi: Không tìm thấy file tại {script_path}")
        return False

    try:
        # Chạy script và chờ nó xong mới chạy cái tiếp theo
        result = subprocess.run([PYTHON_EXEC, script_path], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Lỗi khi chạy {script_path} (Code: {e.returncode})")
        return False
    except Exception as e:
        print(f"❌ Lỗi hệ thống: {e}")
        return False

def main():
    print(f"🔥 SIEM AI AUTOMATION - Đang chạy (Interval: {LOOP_INTERVAL}s)")
    print("👉 Nhấn Ctrl + C để dừng.\n")

    try:
        while True:
            start_time = datetime.now()
            print(f"\n--- 🕒 CHU KỲ QUÉT: {start_time.strftime('%H:%M:%S')} ---")

            # BƯỚC 1: LẤY DỮ LIỆU MỚI
            # Quan trọng: Bước này phải đảm bảo cập nhật file wazuh_data.csv
            if run_step(PATH_FETCH, "1. Fetch Data (Lấy log Wazuh)"):
                
                # BƯỚC 2: AI PHÂN TÍCH & GỬI TELEGRAM
                # (Đã bao gồm preprocess bên trong)
                if run_step(PATH_INFERENCE, "2. AI Inference & Alert"):
                    
                    # BƯỚC 3: TẠO BÁO CÁO (Tùy chọn)
                    # Bác có thể comment dòng này nếu không muốn tạo PDF liên tục mỗi phút
                    run_step(PATH_REPORT, "3. Generate Report")
            
            else:
                print("⚠️ Bỏ qua chu kỳ này do lỗi Fetch Data.")

            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"\n✅ Xong chu kỳ trong {elapsed:.2f}s.")
            print(f"💤 Ngủ {LOOP_INTERVAL}s chờ lượt tiếp theo...")
            time.sleep(LOOP_INTERVAL)

    except KeyboardInterrupt:
        print("\n🛑 Đã dừng hệ thống (User Cancelled).")

if __name__ == "__main__":
    main()