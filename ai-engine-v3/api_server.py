from flask import Flask, request, jsonify
import pandas as pd
import sys
import os
import logging
import numpy as np
from tabulate import tabulate

# --- CẤU HÌNH LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- CẤU HÌNH ĐƯỜNG DẪN IMPORT ---
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import AI Modules
try:
    from inference import predict_from_dataframe, alert_threats
    logger.info("✅ Đã load thành công module AI (inference.py)")
except ImportError as e:
    logger.error(f"❌ Lỗi import module: {e}")
    sys.exit(1)

app = Flask(__name__)

# --- CẤU HÌNH SERVER ---
HOST = '0.0.0.0' 
PORT = 5000

# Cấu hình pandas
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
pd.set_option('display.max_colwidth', 100)

@app.route('/analyze', methods=['POST'])
def analyze_log():
    """
    API Endpoint nhận log từ Wazuh và phân tích
    """
    try:
        # 1. Nhận dữ liệu
        data = request.get_json(force=True, silent=True)
        
        if not data:
            return jsonify({"status": "error", "message": "No JSON data received"}), 400
            
        # --- [THAY ĐỔI 1] XỬ LÝ FORMAT ELASTICSEARCH/WAZUH ---
        # Kiểm tra xem dữ liệu có nằm trong '_source' hay không (để lấy đúng rule.level)
        if '_source' in data:
            alert_data = data['_source']
            logger.info("🔍 Phát hiện log Elasticsearch (_source), đang trích xuất...")
        else:
            # Fallback: Kiểm tra format Wazuh Integrator chuẩn
            alert_data = data.get('alert', data)
        
        # 2. Chuyển đổi sang DataFrame
        if isinstance(alert_data, dict):
            alert_list = [alert_data]
        else:
            alert_list = alert_data 
            
        flat_alert = pd.json_normalize(alert_list)
        
        if flat_alert.empty:
             return jsonify({"status": "error", "message": "Empty Dataframe"}), 400

        # --- [THAY ĐỔI 2] MAP DỮ LIỆU WINDOWS EVENT LOG ---
        # AI cần đọc cột 'full_log'. Log Windows lại để nội dung ở 'data.win.system.message'
        # Đoạn code này sẽ copy nội dung từ message sang full_log để AI hiểu.
        
        text_candidates = [
            'data.win.system.message',      # <--- QUAN TRỌNG NHẤT CHO LOG WINDOWS CỦA BẠN
            'rule.description', 
            'data.win.eventdata.commandLine',
            'full_log'
        ]
        
        # Tìm trường nào có chữ thì lấy gán vào full_log
        for col in text_candidates:
            if col in flat_alert.columns and pd.notna(flat_alert[col].iloc[0]):
                val = str(flat_alert[col].iloc[0])
                if len(val) > 5: 
                    flat_alert['full_log'] = val # Gán đè để module preprocess nhận diện
                    logger.info(f"📝 Đã map text từ cột '{col}' sang 'full_log' cho AI.")
                    break
        
        # --- DEBUG DATA: In ra để kiểm tra ---
        critical_cols = ['rule.level', 'rule.id', 'agent.name', 'full_log']
        logger.info("-" * 30)
        logger.info("🔍 DEBUG PREPARED DATA (Dữ liệu thực tế vào AI):")
        for col in critical_cols:
            val = flat_alert.get(col).iloc[0] if col in flat_alert.columns else "MISSING"
            logger.info(f"   - {col}: {str(val)[:100]}") 
        logger.info("-" * 30)

        # 3. Chạy AI dự đoán
        preds, probs = predict_from_dataframe(flat_alert)
        
        # Xử lý kết quả
        ai_prediction = int(preds[0]) if (preds is not None and len(preds) > 0) else 0
        risk_score = float(probs[0]) if (probs is not None and len(probs) > 0) else 0.0
        
        # Lấy rule level thủ công để so sánh
        manual_level = int(flat_alert.get('rule.level', 0).iloc[0])

        result = {
            "status": "processed",
            "ai_prediction": ai_prediction,
            "risk_score": risk_score
        }

        # 4. Logic Cảnh báo
        # [THAY ĐỔI 3] Thêm điều kiện: Nếu Level >= 10 thì FORCE ALERT luôn, không cần AI đồng ý (để test)
        if ai_prediction == 1 or manual_level >= 10: 
            
            logger.info(f"🚨 THREAT DETECTED | Score: {risk_score:.4f} | Level: {manual_level}")
            
            flat_alert['ai_pred'] = ai_prediction
            flat_alert['ai_score'] = risk_score
            flat_alert['full_text'] = flat_alert.get('full_log', flat_alert.get('rule.description', 'N/A'))

            # In bảng
            print("\n" + "!"*60)
            print(f"🚨 CẢNH BÁO: MỐI ĐE DỌA PHÁT HIỆN [Score: {risk_score:.2f}]")
            print("!"*60)
            
            cols_to_print = ['timestamp', 'agent.name', 'rule.level', 'ai_score', 'full_text']
            valid_cols = [c for c in cols_to_print if c in flat_alert.columns]
            
            # Rút gọn text
            flat_alert['full_text_short'] = flat_alert['full_text'].astype(str).apply(lambda x: x[:80] + '...' if len(x)>80 else x)
            print_cols = [c if c != 'full_text' else 'full_text_short' for c in valid_cols]

            try:
                print(tabulate(flat_alert[print_cols], headers='keys', tablefmt='fancy_grid', showindex=False))
            except:
                print(flat_alert[valid_cols].to_string())

            # Gửi Telegram
            try:
                alert_threats(flat_alert)
                result['action'] = 'alert_sent'
            except Exception as e:
                logger.error(f"Lỗi gửi Telegram: {e}")
                
        else:
            # LOG SAFE
            logger.info(f"✅ SAFE | Score: {risk_score:.4f} | Level: {manual_level} | ID: {flat_alert.get('rule.id', 'N/A').iloc[0]}")
            if manual_level > 5 and risk_score < 0.3:
                 logger.warning(f"⚠️  Level cao ({manual_level}) nhưng AI Score thấp. Check lại mapping text.")

        return jsonify(result)

    except Exception as e:
        logger.error(f"❌ Critical Error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print(f"🚀 AI ENGINE API STARTED on port {PORT}")
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)