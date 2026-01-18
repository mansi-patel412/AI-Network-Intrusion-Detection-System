"""
Detection utilities for the AI NIDS with severity + database logging.

Public API:
    detect_anomaly(model, packet, feature_columns) -> (is_anomaly: bool, features_dict: dict)

features_dict includes:
  - src_ip, dst_ip, proto, len, src_port, dst_port, tcp_flags
  - If anomaly: attack_type (str), attack_confidence (float), severity (int)
"""

import os
import joblib
import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP
from datetime import datetime
import sqlite3

# ======================
# Database setup
# ======================
DB_PATH = "nids_logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            proto TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            attack_type TEXT,
            severity INTEGER,
            confidence REAL
        )
    """)
    conn.commit()
    conn.close()

def log_detection(timestamp, src_ip, dst_ip, proto, src_port, dst_port, attack_type, severity, confidence):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO detections (timestamp, src_ip, dst_ip, proto, src_port, dst_port, attack_type, severity, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, proto, src_port, dst_port, attack_type, severity, confidence))
    conn.commit()
    conn.close()

# Initialize DB on import
init_db()

# ======================
# Preprocessor & Classifiers
# ======================
try:
    import preprocessor
    _HAS_PREPROCESSOR_MODULE = True
except Exception:
    preprocessor = None
    _HAS_PREPROCESSOR_MODULE = False

PROCESSOR = None
if _HAS_PREPROCESSOR_MODULE:
    try:
        PROCESSOR = preprocessor.load_preprocessor("model/preprocessor.joblib")
    except Exception:
        PROCESSOR = None

ATTACK_CLASSIFIER = None
LABEL_ENCODER = None
try:
    clf_path = "model/attack_classifier.pkl"
    encoder_path = "model/label_encoder.joblib"
    if os.path.exists(clf_path):
        ATTACK_CLASSIFIER = joblib.load(clf_path)
    if os.path.exists(encoder_path):
        LABEL_ENCODER = joblib.load(encoder_path)
except Exception as e:
    print(f"Warning: couldn't load attack classifier/encoder: {e}")
    ATTACK_CLASSIFIER = None
    LABEL_ENCODER = None

# ======================
# Feature Extraction
# ======================
def extract_basic_features(packet):
    """Extract basic human-readable features from a Scapy packet."""
    features = {
        "src_ip": None,
        "dst_ip": None,
        "proto": None,
        "len": 0,
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0
    }

    if packet is None:
        return features

    try:
        if IP in packet:
            features["src_ip"] = packet[IP].src
            features["dst_ip"] = packet[IP].dst
            try:
                features["proto"] = int(packet[IP].proto)
            except Exception:
                features["proto"] = packet[IP].proto
            try:
                features["len"] = int(packet[IP].len)
            except Exception:
                features["len"] = 0

        if TCP in packet:
            features["src_port"] = int(packet[TCP].sport)
            features["dst_port"] = int(packet[TCP].dport)
            features["tcp_flags"] = int(packet[TCP].flags)
        elif UDP in packet:
            features["src_port"] = int(packet[UDP].sport)
            features["dst_port"] = int(packet[UDP].dport)
            features["tcp_flags"] = 0
    except Exception:
        pass

    return features

def heuristic_attack_type(features):
    """Fallback heuristic to guess attack type + confidence."""
    proto = features.get("proto")
    dst_port = features.get("dst_port")
    flags = features.get("tcp_flags", 0)
    length = features.get("len", 0)

    if proto == 6:  # TCP
        if (flags & 0x02) and not (flags & 0x10):
            return "SYN_FLOOD", 0.5
        if dst_port in (22, 2222):
            return "SSH_BRUTE_FORCE", 0.35
        if dst_port in (80, 443) and length > 1000:
            return "HTTP_FLOOD", 0.45

    if proto == 17:  # UDP
        if dst_port == 53:
            return "DNS_MISUSE", 0.25
        if length > 1200:
            return "UDP_FLOOD", 0.5

    return "UNKNOWN", 0.1

def calculate_severity(attack_type):
    """Assign severity (1=Low, 2=Medium, 3=High)."""
    mapping = {
        "SYN_FLOOD": 3,
        "HTTP_FLOOD": 3,
        "UDP_FLOOD": 3,
        "SSH_BRUTE_FORCE": 2,
        "DNS_MISUSE": 2,
        "UNKNOWN": 1
    }
    return mapping.get(attack_type, 1)

def packet_to_features_df(packet, feature_columns):
    """Convert packet to DataFrame for model input."""
    if not packet or not packet.haslayer(IP):
        return None

    base = {}
    try:
        base['src_ip'] = packet[IP].src
        base['dst_ip'] = packet[IP].dst
        base['proto'] = int(packet[IP].proto) if hasattr(packet[IP], 'proto') else 0
        base['len'] = int(packet[IP].len) if hasattr(packet[IP], 'len') else 0

        if packet.haslayer(TCP):
            base['src_port'] = int(packet[TCP].sport)
            base['dst_port'] = int(packet[TCP].dport)
            base['tcp_flags'] = int(packet[TCP].flags)
        elif packet.haslayer(UDP):
            base['src_port'] = int(packet[UDP].sport)
            base['dst_port'] = int(packet[UDP].dport)
            base['tcp_flags'] = 0
        else:
            base['src_port'] = 0
            base['dst_port'] = 0
            base['tcp_flags'] = 0
    except Exception:
        base = {k: base.get(k, 0) for k in ['src_ip','dst_ip','proto','len','src_port','dst_port','tcp_flags']}

    row = pd.DataFrame([base])
    for col in feature_columns:
        if col not in row.columns:
            row[col] = 0
    return row[feature_columns]

# ======================
# Prediction Helpers
# ======================
def _interpret_prediction_value(pred_val):
    """Convert model output into anomaly True/False."""
    try:
        if isinstance(pred_val, (int, np.integer, float, np.floating)):
            return int(pred_val) in (-1, 1)
        if isinstance(pred_val, (np.ndarray, pd.Series)):
            if len(pred_val) > 0:
                return _interpret_prediction_value(pred_val[0])
        if isinstance(pred_val, str):
            return pred_val.strip().lower() in ("anomaly", "malicious", "attack", "dos", "ddos", "true", "1")
    except Exception:
        pass
    return False

# ======================
# Main Detection
# ======================
def detect_anomaly(model, packet, feature_columns):
    if model is None:
        return False, {}

    try:
        live_df = packet_to_features_df(packet, feature_columns)
    except Exception:
        live_df = None
    if live_df is None:
        return False, {}

    if PROCESSOR is not None:
        try:
            X_for_model = PROCESSOR.transform(live_df)
        except Exception as e:
            print(f"Preprocessor.transform failed: {e}")
            X_for_model = live_df
    else:
        X_for_model = live_df

    try:
        prediction = model.predict(X_for_model)
    except Exception as e:
        print(f"Model predict failed: {e}")
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_for_model)
            best_idx = int(np.argmax(probs, axis=1)[0])
            pred_label = model.classes_[best_idx] if hasattr(model, "classes_") else best_idx
            prediction = [pred_label]
        else:
            return False, live_df.iloc[0].to_dict()

    pred_val = prediction[0] if isinstance(prediction, (list, tuple, pd.Series, np.ndarray)) else prediction
    is_anomaly = _interpret_prediction_value(pred_val)

    basic_features = extract_basic_features(packet)
    basic_features["attack_type"] = None
    basic_features["attack_confidence"] = 0.0
    basic_features["severity"] = 0

    if not is_anomaly:
        return False, basic_features

    # Attack classification
    if ATTACK_CLASSIFIER is not None:
        try:
            clf_input = pd.DataFrame([basic_features])
            if hasattr(ATTACK_CLASSIFIER, "predict_proba"):
                probs = ATTACK_CLASSIFIER.predict_proba(clf_input)
                best_idx = int(np.argmax(probs, axis=1)[0])
                confidence = float(probs[0][best_idx])
                label_encoded = ATTACK_CLASSIFIER.classes_[best_idx] if hasattr(ATTACK_CLASSIFIER, "classes_") else best_idx
                if LABEL_ENCODER is not None:
                    attack_label = LABEL_ENCODER.inverse_transform([label_encoded])[0]
                else:
                    attack_label = str(label_encoded)
                basic_features["attack_type"] = attack_label
                basic_features["attack_confidence"] = confidence
            else:
                label_pred = ATTACK_CLASSIFIER.predict(clf_input)[0]
                attack_label = LABEL_ENCODER.inverse_transform([label_pred])[0] if LABEL_ENCODER is not None else str(label_pred)
                basic_features["attack_type"] = attack_label
                basic_features["attack_confidence"] = 1.0
        except Exception as e:
            print(f"Attack classifier failed: {e}. Falling back to heuristic.")
            attack_label, conf = heuristic_attack_type(basic_features)
            basic_features["attack_type"], basic_features["attack_confidence"] = attack_label, conf
    else:
        attack_label, conf = heuristic_attack_type(basic_features)
        basic_features["attack_type"], basic_features["attack_confidence"] = attack_label, conf

    # Severity
    severity = calculate_severity(basic_features["attack_type"])
    basic_features["severity"] = severity

    # Log to DB
    log_detection(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        src_ip=basic_features["src_ip"],
        dst_ip=basic_features["dst_ip"],
        proto=str(basic_features["proto"]),
        src_port=int(basic_features["src_port"]),
        dst_port=int(basic_features["dst_port"]),
        attack_type=basic_features["attack_type"],
        severity=severity,
        confidence=basic_features["attack_confidence"]
    )

    return True, basic_features
