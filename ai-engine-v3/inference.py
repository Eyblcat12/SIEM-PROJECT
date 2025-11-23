import joblib
import pandas as pd
from scipy.sparse import hstack
from config import MODEL_PATH, ENCODERS_PATH, VECTORIZER_PATH, DATA_PATH
from utils import logger, load_artifacts
from preprocess import feature_engineer, read_csv_safe
import argparse
import sys
import os

# --- Import module gửi Telegram ---
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
            logger.error(f"❌ Không tìm thấy model: {MODEL_PATH}")
            return None, None, None
        return load_artifacts(MODEL_PATH, ENCODERS_PATH, VECTORIZER_PATH)
    except Exception as e:
        logger.error(f"Lỗi load model: {e}")
        return None, None, None

def predict_from_dataframe(df):
    model, artifacts, vectorizer = load_all()
    if model is None: return None, None

    # 1. Xử lý dữ liệu (quan trọng: is_training=False)
    X_num, X_cat, X_text, _ = feature_engineer(df, is_training=False)

    # 2. Gán lại cột full_text vào DataFrame gốc để hiển thị sau này
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
        
        # Đọc threshold từ file nếu có
        threshold_path = os.path.join(os.path.dirname(MODEL_PATH), "threshold.txt")
        if os.path.exists(threshold_path):
            with open(threshold_path, "r") as f:
                threshold = float(f.read().strip())
        else:
            threshold = 0.5
            
        preds = (probs >= threshold).astype(int)
        return preds, probs
    except Exception as e:
        logger.error(f"Lỗi dự đoán: {e}")
        return None, None

def alert_threats(df):
    if not TELEGRAM_ENABLED: return
    threats = df[df['ai_pred'] == 1]
    if threats.empty: return

    logger.info(f"🚀 Đang gửi cảnh báo cho {len(threats)} mối đe dọa...")
    # Gửi tối đa 3 cảnh báo để tránh spam
    for _, row in threats.head(3).iterrows():
        msg = f"🚨 *AI DETECTED THREAT!* (Score: {row['ai_score']:.2f})\n"
        msg += f"🖥️ Agent: `{row.get('agent.name', 'Unknown')}`\n"
        msg += f"🔥 Level: {row.get('rule.level', 0)}\n"
        
        # Cắt ngắn text khi gửi Telegram cho gọn
        full_text = str(row.get('full_text', 'N/A'))
        if len(full_text) > 100: full_text = full_text[:100] + "..."
        msg += f"📝 Cmd: `{full_text}`\n"
        msg += f"⏰ Time: {row.get('timestamp', 'N/A')}"
        send_alert(msg)

if __name__ == '__main__':
    # --- CẤU HÌNH HIỂN THỊ PANDAS (Để in bảng đẹp) ---
    pd.set_option('display.max_columns', None)   # Hiện tất cả các cột
    pd.set_option('display.width', 1000)         # Mở rộng chiều ngang console
    pd.set_option('display.max_colwidth', None)  # Không cắt nội dung text dài

    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, default=str(DATA_PATH))
    args = parser.parse_args()

    logger.info(f"🧪 Bắt đầu dự đoán trên file: {args.file}")
    try:
        df = read_csv_safe(args.file)
        preds, probs = predict_from_dataframe(df)
        
        if preds is not None:
            # Gán kết quả vào DataFrame
            df['ai_pred'] = preds
            df['ai_score'] = probs
            
            n_threats = sum(preds)
            print(f"\n📊 Tổng: {len(df)} | 🚨 Threat: {n_threats}")
            
            if n_threats > 0:
                # --- LỌC VÀ IN KẾT QUẢ ---
                # 1. Định nghĩa danh sách cột muốn xem
                cols_to_show = ['timestamp', 'agent.name', 'rule.level', 'ai_score', 'ai_pred', 'full_text']
                
                # 2. Lọc lấy các dòng là Threat và sắp xếp theo điểm rủi ro giảm dần
                threat_df = df[df['ai_pred'] == 1].sort_values(by='ai_score', ascending=False)
                
                # 3. Chỉ lấy các cột tồn tại thực tế (tránh lỗi KeyError)
                valid_cols = [c for c in cols_to_show if c in threat_df.columns]
                
                print("\n🔍 CHI TIẾT MỐI ĐE DỌA (Top 5):")
                
                # 4. IN RA MÀN HÌNH
                # formatters: Cắt ngắn cột full_text xuống 80 ký tự + "..." để bảng không bị vỡ quá mức
                print(threat_df[valid_cols].head(5).to_string(
                    index=False,
                    formatters={'full_text': lambda x: str(x)[:80] + '...' if len(str(x)) > 80 else str(x)}
                ))
                
                alert_threats(df)
            else:
                print("✅ Không phát hiện mối đe dọa nào.")
                
    except Exception as e:
        logger.error(f"Lỗi chính: {e}")
        import traceback
        traceback.print_exc()