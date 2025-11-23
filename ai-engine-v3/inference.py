import joblib
import pandas as pd
from scipy.sparse import hstack
from config import MODEL_PATH, ENCODERS_PATH, VECTORIZER_PATH, DATA_PATH
from utils import logger, load_artifacts
from preprocess import feature_engineer, read_csv_safe
import argparse
import sys
import os

# --- Hỗ trợ hiển thị tiếng Việt ---
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def load_all():
    """Load model và các thành phần artifacts"""
    try:
        if not os.path.exists(MODEL_PATH):
            logger.error(f"❌ Không tìm thấy file model: {MODEL_PATH}. Vui lòng chạy train.py trước!")
            return None, None, None
            
        model, encoders, vectorizer = load_artifacts(MODEL_PATH, ENCODERS_PATH, VECTORIZER_PATH)
        return model, encoders, vectorizer
    except Exception as e:
        logger.error(f"Lỗi khi load model: {e}")
        return None, None, None

def predict_from_dataframe(df):
    """
    Dự đoán mối đe dọa từ DataFrame log mới.
    """
    model, artifacts, vectorizer = load_all()
    if model is None: return None, None

    # 1. Xử lý dữ liệu (QUAN TRỌNG: is_training=False để không tìm nhãn y)
    # Hàm trả về: X_num, X_cat, X_text, y (y sẽ là None)
    X_num, X_cat, X_text, _ = feature_engineer(df, is_training=False)

    try:
        # 2. Transform features bằng bộ xử lý đã train
        preprocessor = artifacts['preprocessor']
        
        # Biến đổi số & category
        X_pre = preprocessor.transform(X_num.join(X_cat))
        
        # Biến đổi text (nếu có vectorizer)
        if vectorizer:
            X_text_tfidf = vectorizer.transform(X_text)
        else:
            # Nếu model không dùng NLP, tạo ma trận rỗng tương ứng
            from scipy.sparse import csr_matrix
            X_text_tfidf = csr_matrix((X_pre.shape[0], 0))
        
        # 3. Gộp dữ liệu
        X_full = hstack([X_pre, X_text_tfidf])
        
        # 4. Dự đoán
        # predict_proba trả về xác suất [xác suất an toàn, xác suất threat]
        # Lấy cột [1] là xác suất Threat
        probs = model.predict_proba(X_full)[:, 1]
        
        # Áp dụng ngưỡng (Threshold). Mặc định 0.5, bạn có thể load threshold tối ưu từ file nếu muốn
        threshold = 0.5
        preds = (probs >= threshold).astype(int)
        
        return preds, probs
        
    except Exception as e:
        logger.error(f"Lỗi trong quá trình dự đoán: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == '__main__':
    # Xử lý tham số dòng lệnh
    parser = argparse.ArgumentParser(description='Chạy dự đoán AI cho log Wazuh')
    parser.add_argument('--file', type=str, default=str(DATA_PATH), help='Đường dẫn file log (CSV)')
    args = parser.parse_args()

    logger.info(f"🧪 Bắt đầu dự đoán trên file: {args.file}")
    
    try:
        # Đọc file dữ liệu
        df = read_csv_safe(args.file)
        
        # Chạy dự đoán
        preds, probs = predict_from_dataframe(df)
        
        if preds is not None:
            # Gắn kết quả vào DataFrame để xem
            df['ai_pred'] = preds
            df['ai_score'] = probs
            
            # In kết quả ra màn hình (Top 10 dòng có điểm rủi ro cao nhất)
            print("\n" + "="*60)
            print("🔍 KẾT QUẢ DỰ ĐOÁN (Sắp xếp theo điểm rủi ro giảm dần)")
            print("="*60)
            
            # Chọn cột để hiển thị
            cols_to_show = ['timestamp', 'agent.name', 'rule.level', 'ai_pred', 'ai_score']
            valid_cols = [c for c in cols_to_show if c in df.columns]
            
            # Sắp xếp và lấy top 10
            top_threats = df.sort_values(by='ai_score', ascending=False).head(10)
            print(top_threats[valid_cols].to_string(index=False))
            
            # Thống kê tổng quan
            n_threats = sum(preds)
            print("\n" + "-"*30)
            print(f"📊 Tổng số log đã quét: {len(df)}")
            print(f"🚨 Số lượng mối đe dọa phát hiện: {n_threats}")
            print(f"✅ Tỷ lệ sạch: {(len(df)-n_threats)/len(df):.2%}")
            print("-"*30)
            
    except Exception as e:
        logger.error(f"Lỗi chính chương trình: {e}")