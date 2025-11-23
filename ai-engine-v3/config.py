from pathlib import Path
import os

# --- CẤU HÌNH ĐƯỜNG DẪN (PATH CONFIGURATION) ---

# Xác định thư mục gốc của dự án dựa trên vị trí file config này
# File này nằm trong: SIEM-PROJECT/ai-engine-v3/config.py
# Nên BASE_DIR sẽ là: SIEM-PROJECT/ai-engine-v3/
BASE_DIR = Path(__file__).resolve().parent

# Đường dẫn đến file dữ liệu log (nằm ở thư mục gốc SIEM-PROJECT)
DATA_PATH = BASE_DIR.parent / 'wazuh_data.csv'

# Thư mục để lưu các model đã huấn luyện
MODEL_DIR = BASE_DIR / 'models'
# Tự động tạo thư mục models nếu chưa có
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Đường dẫn chi tiết cho từng file thành phần của model
MODEL_PATH = MODEL_DIR / 'ai_model_v3.joblib'       # File chứa model chính (XGBoost/LightGBM)
VECTORIZER_PATH = MODEL_DIR / 'tfidf_v3.joblib'     # File chứa bộ xử lý NLP (TF-IDF)
ENCODERS_PATH = MODEL_DIR / 'encoders_v3.joblib'    # File chứa bộ mã hóa số (LabelEncoders)

# --- THAM SỐ HUẤN LUYỆN (TRAINING PARAMS) ---
RANDOM_STATE = 42           # Hạt giống ngẫu nhiên để kết quả nhất quán
CV_FOLDS = 5                # Số lần kiểm tra chéo (Cross-validation folds)
TFIDF_MAX_FEATURES = 1000   # Số lượng từ vựng tối đa cho NLP (tăng lên nếu máy mạnh)

# --- CẤU HÌNH GÁN NHÃN TỰ ĐỘNG (AUTO-LABELING RULES) ---
# Đây là nơi bạn dạy cho AI biết thế nào là "Nguy hiểm" bước đầu
LABEL_RULES = {
    # 1. Dựa trên Rule Level của Wazuh
    'rule_level_threshold': 10,  # Level >= 10 thì coi là threat

    # 2. Dựa trên từ khóa trong log (Signature-based)
    'keyword_indicators': [
        'mimikatz', 'metasploit', 'cobalt', 'shadow', 
        'net user', 'net localgroup', 'whoami', 
        'powershell', 'cmd.exe', 'rundll32', 'wmic', 
        'suspicious', 'credential', 'hacker', 'attack', 'malware',
        'bypass', 'downloadstring'
    ],

    # 3. Gán cứng theo ID luật (Whitelist/Blacklist)
    # Format: 'Rule_ID': 1 (Threat) hoặc 0 (Safe)
    'rule_id_overrides': {
        # Ví dụ: '5710' (Logon failed) luôn là threat -> '5710': 1
        # Ví dụ: '100' (Log rác) luôn là safe -> '100': 0
    }
}

# --- CHỌN THUẬT TOÁN (BACKEND) ---
# Các lựa chọn: 'xgboost', 'lightgbm', 'catboost'
# Mặc định dùng XGBoost vì nó mạnh và phổ biến nhất
DEFAULT_BACKEND = 'xgboost'