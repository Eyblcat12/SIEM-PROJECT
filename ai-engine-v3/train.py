import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import make_scorer, accuracy_score, f1_score, precision_score, recall_score
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
import joblib
import argparse
import sys
import os

# Import cấu hình và hàm tiện ích từ các file bạn đã tạo trước đó
from config import RANDOM_STATE, CV_FOLDS, TFIDF_MAX_FEATURES, DEFAULT_BACKEND, MODEL_PATH, VECTORIZER_PATH, ENCODERS_PATH, DATA_PATH
from utils import logger, save_artifacts, ensure_binary_labels
from preprocess import read_csv_safe, auto_label, feature_engineer

# Sửa lỗi hiển thị tiếng Việt trên Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def get_model(backend='xgboost'):
    """
    Factory để tạo model dựa trên backend được chọn.
    Hỗ trợ XGBoost, LightGBM, CatBoost.
    """
    if backend == 'xgboost':
        from xgboost import XGBClassifier
        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            use_label_encoder=False,
            eval_metric='logloss',
            n_jobs=-1,
            random_state=RANDOM_STATE
        )
    elif backend == 'lightgbm':
        import lightgbm as lgb
        return lgb.LGBMClassifier(n_estimators=1000, random_state=RANDOM_STATE, n_jobs=-1)
    elif backend == 'catboost':
        from catboost import CatBoostClassifier
        return CatBoostClassifier(iterations=500, verbose=100, random_state=RANDOM_STATE)
    else:
        raise ValueError(f"Backend '{backend}' chưa được hỗ trợ hoặc chưa cài đặt.")

def train_pipeline(backend=DEFAULT_BACKEND):
    logger.info(f"🚀 Starting training pipeline with backend: {backend}")
    
    # --- 1. Load & Preprocess ---
    # Đọc dữ liệu từ file CSV (đường dẫn lấy từ config.py)
    logger.info(f"Reading data from: {DATA_PATH}")
    df = read_csv_safe(DATA_PATH)
    
    # Gán nhãn tự động (Auto-labeling) để có dữ liệu train
    df = auto_label(df)
    
    # Feature Engineering: Tạo đặc trưng và lấy nhãn y
    # is_training=True để hàm trả về cả y
    X_num, X_cat, X_text, y = feature_engineer(df, is_training=True)
    
    # Đảm bảo nhãn y là nhị phân (0/1)
    y = ensure_binary_labels(y)

    # Kiểm tra sơ bộ dữ liệu
    n_threats = sum(y)
    logger.info(f"Data shape: {len(df)} rows. Threat ratio: {n_threats}/{len(y)} ({n_threats/len(y):.2%})")

    if n_threats == 0:
        logger.warning("⚠️ CẢNH BÁO: Không có mẫu Threat nào trong dữ liệu! Model sẽ học không hiệu quả.")
        logger.warning("💡 Gợi ý: Hãy chạy tấn công giả lập (net user /add...) rồi chạy lại fetch_alerts.py")

    # --- 2. Xây dựng Transformers (Bộ biến đổi dữ liệu) ---
    numeric_features = list(X_num.columns)
    categorical_features = list(X_cat.columns)

    # Pipeline cho dữ liệu số: Chuẩn hóa (StandardScaler)
    num_transformer = Pipeline(steps=[
        ('scaler', StandardScaler())
    ])
    
    # Pipeline cho dữ liệu danh mục: One-Hot Encoding (biến chữ thành vector 0/1)
    # handle_unknown='ignore': Gặp giá trị lạ thì bỏ qua, không lỗi
    cat_transformer = Pipeline(steps=[
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=True)) 
    ])

    # Bộ xử lý cột (ColumnTransformer) để áp dụng riêng từng loại
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', num_transformer, numeric_features),
            ('cat', cat_transformer, categorical_features)
        ], remainder='drop'
    )

    # NLP: TF-IDF Vectorizer cho dữ liệu văn bản
    vectorizer = TfidfVectorizer(max_features=TFIDF_MAX_FEATURES, ngram_range=(1,2))

    # --- 3. Chuẩn bị dữ liệu Train ---
    logger.info("⚙️  Transforming features...")
    
    # Biến đổi số & category
    X_pre = preprocessor.fit_transform(X_num.join(X_cat))
    
    # Biến đổi text
    # Nếu không có text thì tạo ma trận rỗng
    if X_text is not None and not X_text.empty and not (X_text == '').all():
        X_text_tfidf = vectorizer.fit_transform(X_text)
    else:
        from scipy.sparse import csr_matrix
        X_text_tfidf = csr_matrix((X_pre.shape[0], 0))
        logger.warning("⚠️ No text data found for TF-IDF.")
    
    # Gộp lại thành ma trận lớn (Sparse Matrix)
    X_full = hstack([X_pre, X_text_tfidf])

    # --- 4. Cross-Validation (Kiểm tra chéo) ---
    model = get_model(backend)
    
    # Chia tập dữ liệu thành 5 phần để test chéo
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    
    # Các chỉ số đánh giá
    scoring = {
        'accuracy': make_scorer(accuracy_score),
        'f1': make_scorer(f1_score, zero_division=0)
    }

    logger.info('🔄 Running Cross-Validation...')
    
    # Kiểm tra xem có đủ dữ liệu để split không (ít nhất 2 class)
    if len(np.unique(y)) < 2:
        logger.warning("⚠️ Dữ liệu chỉ có 1 lớp (toàn an toàn hoặc toàn nguy hiểm). Bỏ qua Cross-Validation.")
    else:
        res = cross_validate(model, X_full, y, cv=cv, scoring=scoring, return_train_score=False, n_jobs=-1)
        for k, v in res.items():
            logger.info(f"   CV {k}: mean={np.mean(v):.4f} std={np.std(v):.4f}")

    # --- 5. Train Final Model (Trên toàn bộ dữ liệu) ---
    logger.info('🧠 Fitting final model...')
    model.fit(X_full, y)

    # --- 6. Lưu trữ (Save Artifacts) ---
    # Lưu preprocessor (chứa scaler và onehot) để dùng lại khi dự đoán
    artifacts = {
        'preprocessor': preprocessor,
        'numeric_features': numeric_features,
        'categorical_features': categorical_features
    }
    
    save_artifacts(model, artifacts, vectorizer, MODEL_PATH, ENCODERS_PATH, VECTORIZER_PATH)
    logger.info('🎉 Training complete!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', default=DEFAULT_BACKEND, help='xgboost|lightgbm|catboost')
    args = parser.parse_args()
    
    try:
        train_pipeline(backend=args.backend)
    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()