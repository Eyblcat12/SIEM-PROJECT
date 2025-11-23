from config import DATA_PATH, LABEL_RULES
import pandas as pd
import numpy as np
from utils import logger, check_required_cols
from pathlib import Path

# Các cột bắt buộc phải có trong file CSV
REQUIRED = ['timestamp'] 

def read_csv_safe(path):
    """
    Đọc file CSV an toàn.
    Hỗ trợ cả đường dẫn dạng chuỗi (str) và đối tượng Path.
    """
    try:
        # Chuyển đổi sang đối tượng Path nếu nó là chuỗi
        if isinstance(path, str):
            path = Path(path)
            
        if path is None or not path.exists():
            logger.error(f"❌ File not found: {path}")
            raise FileNotFoundError(f"File {path} does not exist.")
            
        df = pd.read_csv(path)
        logger.info(f"📂 Loaded CSV with {len(df)} rows and {len(df.columns)} cols")
        return df
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}")
        raise

def auto_label(df):
    """
    Tự động gán nhãn 'is_threat' (0 hoặc 1) dựa trên các quy tắc (Heuristics).
    Chỉ dùng bước này khi HUẤN LUYỆN (Training).
    """
    df = df.copy()
    # Tạo cột điểm rủi ro ban đầu là 0.0
    df['is_threat_score'] = 0.0

    # 1. Dựa vào Rule Level (Trọng số 0.5)
    # Level càng cao càng nguy hiểm
    if 'rule.level' in df.columns:
        levels = pd.to_numeric(df['rule.level'], errors='coerce').fillna(0)
        # Nếu level >= ngưỡng cài đặt (ví dụ 10) -> cộng 0.5 điểm
        df.loc[levels >= LABEL_RULES['rule_level_threshold'], 'is_threat_score'] += 0.5

    # 2. Dựa vào Rule ID cụ thể (Trọng số 1.0 - Chắc chắn)
    # Ví dụ: Rule ID 5710 (SSH brute force) luôn là threat
    if 'rule.id' in df.columns:
        overrides = LABEL_RULES.get('rule_id_overrides', {})
        rule_ids = df['rule.id'].astype(str)
        for rid, val in overrides.items():
             df.loc[rule_ids == str(rid), 'is_threat_score'] += float(val)

    # 3. Dựa vào từ khóa (Trọng số 0.7)
    # Tìm các từ như 'mimikatz', 'hacker' trong toàn bộ log
    text_fields = [c for c in df.columns if 'image' in c or 'command' in c or 'eventdata' in c or 'msg' in c or 'message' in c]
    keywords = LABEL_RULES['keyword_indicators']
    
    if text_fields:
        # Gộp nội dung các cột văn bản lại để tìm cho dễ
        combined_text = df[text_fields].fillna('').astype(str).agg(' '.join, axis=1)
        mask = combined_text.str.contains('|'.join(keywords), case=False, na=False)
        df.loc[mask, 'is_threat_score'] += 0.7

    # 4. Dựa vào tần suất IP (Anomaly) - IP hiếm gặp (Trọng số 0.2)
    # Nếu một IP xuất hiện quá ít (dưới 0.1%), có thể là bất thường
    if 'data.srcip' in df.columns:
        freqs = df['data.srcip'].fillna('unknown').astype(str).value_counts(normalize=True)
        # Map tần suất vào từng dòng
        df['srcip_freq'] = df['data.srcip'].fillna('unknown').astype(str).map(lambda x: freqs.get(x,0))
        df.loc[df['srcip_freq'] < 0.001, 'is_threat_score'] += 0.2

    # Chốt nhãn: Nếu tổng điểm >= 0.5 thì coi là Threat (1), ngược lại là Normal (0)
    df['is_threat'] = (df['is_threat_score'] >= 0.5).astype(int)
    
    threat_count = df['is_threat'].sum()
    logger.info(f"🏷️  Auto-labeling: {threat_count} Threats detected.")
    
    return df

def feature_engineer(df, is_training=False):
    """
    Tạo các đặc trưng (features) để đưa vào mô hình AI.
    Tham số is_training: 
      - True: Bắt buộc phải có cột 'is_threat' để trả về nhãn y (Dùng lúc Train).
      - False: Không cần cột 'is_threat' (Dùng lúc Predict/Inference).
    """
    df = df.copy()
    
    # 1. Kỹ thuật đặc trưng thời gian (Time-based Features)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df['hour'] = df['timestamp'].dt.hour.fillna(0).astype(int)
        df['weekday'] = df['timestamp'].dt.weekday.fillna(0).astype(int)
    else:
        df['hour'] = 0
        df['weekday'] = 0

    # 2. Nhóm dữ liệu số (Numeric Features)
    num_cols = ['hour', 'weekday']
    if 'rule.level' in df.columns:
        num_cols.append('rule.level')
    
    # Đảm bảo luôn đủ cột số, nếu thiếu thì tạo mới và điền 0
    for col in ['hour', 'weekday', 'rule.level']:
        if col not in num_cols and col not in df.columns:
             df[col] = 0
             if col not in num_cols: num_cols.append(col)
        
    X_num = df[num_cols].copy().fillna(0)
    X_num = X_num.apply(pd.to_numeric, errors='coerce').fillna(0)

    # 3. Nhóm dữ liệu danh mục (Categorical Features)
    cat_candidates = ['rule.id', 'agent.name', 'data.srcip']
    # Đảm bảo đủ cột, thiếu thì điền 'unknown'
    for col in cat_candidates:
        if col not in df.columns:
            df[col] = 'unknown'
            
    X_cat = df[cat_candidates].fillna('unknown').astype(str)

    # 4. Nhóm dữ liệu văn bản (Text Features for NLP)
    text_candidates = ['data.win.eventdata.image', 'data.command', 'message', 'full_log', 'data.win.eventdata.commandLine']
    text_cols = [c for c in text_candidates if c in df.columns]
    
    if text_cols:
        # Gộp tất cả cột text lại thành một chuỗi dài để NLP xử lý
        X_text = df[text_cols].fillna('').astype(str).agg(' '.join, axis=1)
    else:
        X_text = pd.Series([''] * len(df))

    # Xử lý nhãn y (chỉ khi training)
    y = None
    if is_training:
        if 'is_threat' not in df.columns:
            raise ValueError("Cột 'is_threat' bị thiếu trong chế độ Training. Hãy chạy auto_label trước.")
        y = df['is_threat'].astype(int)
    
    return X_num, X_cat, X_text, y

# Phần này để test chạy thử file này độc lập
if __name__ == '__main__':
    try:
        # Test đọc file
        df = read_csv_safe(DATA_PATH)
        # Test gán nhãn
        df = auto_label(df)
        # Test tạo feature
        X_num, X_cat, X_text, y = feature_engineer(df, is_training=True)
        print(f"✅ Test thành công! Shape: Num={X_num.shape}, Cat={X_cat.shape}, Text={X_text.shape}, Label={y.shape}")
    except Exception as e:
        print(f"❌ Error: {e}")