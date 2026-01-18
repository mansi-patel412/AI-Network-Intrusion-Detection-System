import sqlite3
from datetime import datetime

DB_FILE = "ids_logs.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Table for packets
    c.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        packet_summary TEXT,
        is_anomaly INTEGER,
        features TEXT
    )
    """)
    
    # Table for alerts
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        message TEXT,
        severity TEXT
    )
    """)

    # Table for email configuration (NEW)
    c.execute("""
    CREATE TABLE IF NOT EXISTS email_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        password TEXT,
        receiver TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


# ---------------------------
# Packet Logging Functions
# ---------------------------

def log_packet(packet_summary, is_anomaly, features):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO packets (timestamp, packet_summary, is_anomaly, features)
        VALUES (?, ?, ?, ?)
    """, (datetime.now().isoformat(), packet_summary, int(is_anomaly), str(features)))
    conn.commit()
    conn.close()


# ---------------------------
# Alert Logging Functions
# ---------------------------

def log_alert(message, severity="INFO"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (timestamp, message, severity)
        VALUES (?, ?, ?)
    """, (datetime.now().isoformat(), message, severity))
    conn.commit()
    conn.close()


def get_recent_alerts(limit=10):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, message, severity
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


# ---------------------------
# Statistics Functions
# ---------------------------

def get_anomaly_stats():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM packets WHERE is_anomaly=1")
    anomalies = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM packets")
    total = c.fetchone()[0]
    conn.close()
    return anomalies, total


# ---------------------------
# Email Configuration Functions (NEW)
# ---------------------------

def save_email_config(sender, password, receiver):
    """
    Save or update email credentials.
    Only keeps the latest one for security & simplicity.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            password TEXT,
            receiver TEXT,
            timestamp TEXT
        )
    """)
    # Delete old entries so only one config remains
    c.execute("DELETE FROM email_config")
    # Insert new credentials
    c.execute("""
        INSERT INTO email_config (sender, password, receiver, timestamp)
        VALUES (?, ?, ?, ?)
    """, (sender, password, receiver, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def get_email_config():
    """
    Fetch the most recently saved email credentials.
    Returns (sender, password, receiver) or (None, None, None)
    if not configured.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT sender, password, receiver
        FROM email_config
        ORDER BY id DESC
        LIMIT 1
    """)
    row = c.fetchone()
    conn.close()
    return row if row else (None, None, None)
