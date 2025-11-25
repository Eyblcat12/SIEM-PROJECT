import joblib
import pandas as pd
from scipy.sparse import hstack
from config import MODEL_PATH, ENCODERS_PATH, VECTORIZER_PATH, DATA_PATH
from utils import logger, load_artifacts
from preprocess import feature_engineer, read_csv_safe
import argparse
import sys
import os

# --- 1. IMPORT MODULE TI LOOKUP ---
try:
    from ti_lookup import check_ip_abuseipdb, check_hash_virustotal
    TI_ENABLED = True
except ImportError:
    logger.warning("⚠️ Không tìm thấy ti_lookup.py. Tính năng kiểm tra IP/Hash sẽ tắt.")
    TI_ENABLED = False

# --- Import Telegram ---
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from scripts.send_telegram import send_alert
    TELEGRAM_ENABLED = True
except ImportError:
    TELEGRAM_ENABLED = False

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def load_all():
    try:
        if not os.path.exists(MODEL_PATH):
            return None, None, None
        return load_artifacts(MODEL_PATH, ENCODERS_PATH, VECTORIZER_PATH)
    except Exception:
        return None, None, None

def predict_from_dataframe(df):
    model, artifacts, vectorizer = load_all()
    if model is None: return None, None

    X_num, X_cat, X_text, _ = feature_engineer(df, is_training=False)
    df['full_text'] = X_text 

    try:
        preprocessor = artifacts['preprocessor']
        X_pre = preprocessor.transform(X_num.join(X_cat))
        
        if vectorizer:
            X_text_tfidf = vectorizer.transform(X_text)
        else:
            from scipy.sparse import csr_matrix
            X_text_tfidf = csr_matrix((X_pre.shape[0], 0))
        
        X_full = hstack([X_pre, X_text_tfidf])
        probs = model.predict_proba(X_full)[:, 1]
        
        threshold = 0.5
        preds = (probs >= threshold).astype(int)
        return preds, probs
    except Exception as e:
        logger.error(f"Lỗi dự đoán: {e}")
        return None, None

def alert_threats(df):
    threats = df[df['ai_pred'] == 1]
    if threats.empty: return

    logger.info(f"🚀 Đang xử lý {len(threats)} mối đe dọa (Kiểm tra TI & Gửi Telegram)...")
    
    for _, row in threats.head(5).iterrows():
        msg = f"🚨 *AI DETECTED THREAT!* (Score: {row['ai_score']:.2f})\n"
        msg += f"🖥️ Agent: `{row.get('agent.name', 'Unknown')}`\n"
        
        ti_info = ""
        if TI_ENABLED:
            # --- QUAN TRỌNG: KIỂM TRA TÊN CỘT CSV Ở ĐÂY ---
            # Bạn có thể cần sửa 'data.srcip' thành tên cột IP trong file CSV của bạn
            src_ip = row.get('data.srcip') or row.get('src_ip')
            
            # Bạn có thể cần sửa 'syscheck.sha256_after' thành tên cột Hash trong CSV
            file_hash = row.get('syscheck.sha256_after') or row.get('data.virustotal.sha256')
            file_path = row.get('syscheck.path') or row.get('file_path')

            if src_ip and str(src_ip) != 'nan':
                is_mal_ip, ip_score, country = check_ip_abuseipdb(src_ip)
                if is_mal_ip:
                    ti_info += f"🚫 *Bad IP:* {src_ip} ({country}) - Score: {ip_score}%\n"

            if file_hash and str(file_hash) != 'nan':
                is_mal_hash, positives, total = check_hash_virustotal(file_hash, file_path=file_path)
                if is_mal_hash:
                    ti_info += f"🦠 *Malware:* {positives}/{total} engines\n"
                    if file_path: ti_info += f"📂 `{file_path}`\n"

        if ti_info: msg += "\n🔍 *THREAT INTEL:*\n" + ti_info + "\n"
        
        full_text = str(row.get('full_text', 'N/A'))
        if len(full_text) > 100: full_text = full_text[:100] + "..."
        msg += f"📝 Log: `{full_text}`"
        
        if TELEGRAM_ENABLED: send_alert(msg)
        else: print(msg)

if __name__ == '__main__':
    pd.set_option('display.max_columns', None)
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, default=str(DATA_PATH))
    args = parser.parse_args()

    logger.info(f"🧪 Bắt đầu dự đoán: {args.file}")
    try:
        df = read_csv_safe(args.file)
        preds, probs = predict_from_dataframe(df)
        
        if preds is not None:
            df['ai_pred'] = preds
            df['ai_score'] = probs
            n_threats = sum(preds)
            print(f"\n📊 Tổng: {len(df)} | 🚨 Threat: {n_threats}")
            
            if n_threats > 0:
                alert_threats(df)
            else:
                print("✅ Sạch. Không có mối đe dọa.")
    except Exception as e:
        logger.error(f"Lỗi: {e}")