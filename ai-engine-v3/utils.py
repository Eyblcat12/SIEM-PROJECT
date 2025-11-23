import logging
from sklearn.preprocessing import LabelEncoder
import joblib
from config import MODEL_DIR
from pathlib import Path
import numpy as np
import sys

# Setup logging (có màu mè cho dễ nhìn nếu muốn, ở đây dùng basic)
def setup_logger(name='ai_engine', level=logging.INFO):
    # Fix lỗi font tiếng Việt trên Windows console
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8')
        
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler()
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(fmt)
        log.addHandler(handler)
    log.setLevel(level)
    return log

logger = setup_logger()

def safe_label_encode(series, encoder: LabelEncoder = None):
    """
    Mã hóa nhãn an toàn (Safe Label Encoding).
    Nếu gặp giá trị lạ (unseen), tự động map về 'unknown'.
    """
    s = series.fillna('unknown').astype(str)
    if encoder is None:
        le = LabelEncoder()
        vals = list(s.unique())
        if 'unknown' not in vals:
            vals.append('unknown')
        le.fit(vals)
        # Transform an toàn
        arr = le.transform(s.map(lambda x: x if x in le.classes_ else 'unknown'))
        return le, arr
    else:
        le = encoder
        known = set(le.classes_)
        # Map giá trị lạ về 'unknown' trước khi transform
        arr_mapped = s.map(lambda x: x if x in known else 'unknown')
        return le, le.transform(arr_mapped)

def save_artifacts(model, encoders: dict, vectorizer, model_path, encoders_path, vectorizer_path):
    joblib.dump(model, model_path)
    joblib.dump(encoders, encoders_path)
    if vectorizer is not None:
        joblib.dump(vectorizer, vectorizer_path)
    logger.info(f"💾 Saved model to {model_path}")

def load_artifacts(model_path, encoders_path, vectorizer_path):
    model = joblib.load(model_path)
    encoders = joblib.load(encoders_path)
    vectorizer = None
    if Path(vectorizer_path).exists():
        vectorizer = joblib.load(vectorizer_path)
    return model, encoders, vectorizer

def check_required_cols(df, required_cols):
    missing = [c for c in required_cols if c not in df.columns]
    return missing

def ensure_binary_labels(y):
    """Đảm bảo nhãn đầu ra là 0 hoặc 1"""
    arr = np.array(y)
    unique = np.unique(arr)
    if set(unique).issubset({0,1}):
        return arr.astype(int)
    return (arr != 0).astype(int)