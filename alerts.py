import smtplib
import ssl
import os
from email.message import EmailMessage
import database as db  # <-- NEW: import DB to save/load credentials

# We use plyer for cross-platform desktop notifications.
# It needs to be installed via: pip install plyer
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    print("DEBUG: 'plyer' library not found. Desktop notifications will be disabled.")
    PLYER_AVAILABLE = False

# --- Email Configuration (Dynamic) ---
SENDER_EMAIL = None
SENDER_PASSWORD = None
RECIPIENT_EMAIL = None


# =========================================================
#   EMAIL CONFIGURATION FUNCTIONS
# =========================================================
def configure_email(sender, password, receiver, save_to_db=True):
    """
    Dynamically sets email credentials (from UI or bridge) and optionally saves to DB.
    """
    global SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL
    SENDER_EMAIL = sender
    SENDER_PASSWORD = password
    RECIPIENT_EMAIL = receiver

    print(f"DEBUG: Email configuration set — Sender: {SENDER_EMAIL}, Receiver: {RECIPIENT_EMAIL}")

    # Save the credentials to database if requested (default True)
    if save_to_db:
        try:
            db.save_email_config(sender, password, receiver)
            print("✅ Email credentials saved successfully in database.")
        except Exception as e:
            print(f"⚠️ Warning: Failed to save email credentials to DB: {e}")


def load_email_from_db():
    """
    Loads email credentials from database if not already configured.
    """
    global SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL
    if all([SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL]):
        print("DEBUG: Email credentials already loaded in memory.")
        return

    sender, password, receiver = db.get_email_config()
    if sender and password and receiver:
        SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL = sender, password, receiver
        print(f"✅ Loaded email credentials from database: {SENDER_EMAIL} → {RECIPIENT_EMAIL}")
    else:
        print("⚠️ No email credentials found in the database. Email alerts will be skipped.")


# =========================================================
#   DESKTOP NOTIFICATION
# =========================================================
def send_desktop_notification(title, message):
    """Sends a desktop notification with detailed debugging."""
    print("\n--- Attempting to send DESKTOP notification ---")
    if not PLYER_AVAILABLE:
        print("DEBUG: Cannot send notification because 'plyer' library is not installed.")
        return

    try:
        print("DEBUG: Calling notification.notify()...")
        notification.notify(
            title=title,
            message=message,
            app_name='NIDS Alerter',
            timeout=15
        )
        print("SUCCESS: Desktop notification sent successfully.")
        print("NOTE: Notification appears on the host system running Streamlit, not in the browser.")
    except Exception as e:
        print(f"ERROR: Failed to send desktop notification. Reason: {e}")


# =========================================================
#   EMAIL ALERT FUNCTIONS
# =========================================================
def send_email_alert(subject, body):
    """Sends an email alert using Gmail SMTP with detailed debugging."""
    print("\n--- Attempting to send EMAIL notification ---")

    # Load credentials if not already set
    load_email_from_db()

    # --- Step 1: Check Credentials ---
    print("DEBUG: Checking for email credentials...")
    if not all([SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL]):
        print("ERROR: Email credentials are not configured. Use configure_email() before sending.")
        return
    print("DEBUG: Credentials found.")

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL

    context = ssl.create_default_context()

    try:
        # --- Step 2: Connect & Login ---
        print("DEBUG: Connecting to SMTP server 'smtp.gmail.com' on port 465...")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            print("DEBUG: Connection successful. Attempting login...")
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)

            # --- Step 3: Send Email ---
            print("DEBUG: Login successful. Sending the email...")
            smtp.send_message(msg)
            print(f"✅ SUCCESS: Email alert sent successfully to {RECIPIENT_EMAIL}.")

    except smtplib.SMTPAuthenticationError as e:
        print(f"ERROR: SMTP Authentication Failed (Code: {getattr(e, 'smtp_code', 'Unknown')}).")
        print("TROUBLESHOOTING:")
        print("  1. Is the sender email correct?")
        print("  2. Is the app password correct (must be 16-digit Gmail App Password)?")
    except ConnectionRefusedError:
        print("ERROR: Connection refused by mail server. Check firewall or antivirus.")
    except Exception as e:
        print(f"ERROR: Unexpected error while sending email: {e}")


# =========================================================
#   FINAL SUMMARY EMAIL
# =========================================================
def send_final_report(final_rate, threshold, total_packets, anomalies):
    """
    Sends a summary email after scanning completes.
    """
    print("\n--- Preparing to send FINAL REPORT email ---")
    load_email_from_db()

    if not all([SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL]):
        print("ERROR: Email credentials not configured. Use configure_email() before sending.")
        return

    subject = "📊 Final Network Analysis Report"
    body = (
        "Network Analysis Session Summary:\n\n"
        f"🟢 Total Packets Analyzed: {total_packets}\n"
        f"🔴 Anomalies Detected: {anomalies}\n"
        f"📈 Final Anomaly Rate: {final_rate:.2%}\n"
        f"⚙️ Alert Threshold: {threshold:.2%}\n\n"
        "--------------------------------------------\n"
        "This is an automated summary from your AI-Powered NIDS.\n"
        "Immediate review of the dashboard is recommended if anomalies exceed the set threshold.\n\n"
        "Thank you for using the AI-Powered Network Intrusion Detection System 🛡️"
    )

    send_email_alert(subject, body)
    print("DEBUG: Final report email dispatched successfully.")


# =========================================================
#   ALERT MANAGER CLASS
# =========================================================
class AlertManager:
    """
    Tracks packet statistics and triggers alerts based on a defined threshold.
    """
    def __init__(self, threshold=0.5, min_packets=20):
        self.threshold = threshold
        self.min_packets = min_packets
        self.total_packets = 0
        self.anomaly_count = 0
        self.alert_triggered = False

    def reset(self):
        """Resets the counters and alert status."""
        self.total_packets = 0
        self.anomaly_count = 0
        self.alert_triggered = False

    def update_counts(self, is_anomaly):
        """Updates packet counts and checks if the alert threshold has been breached."""
        self.total_packets += 1
        if is_anomaly:
            self.anomaly_count += 1

        if self.total_packets >= self.min_packets and not self.alert_triggered:
            self._check_and_trigger_alert()

    def _check_and_trigger_alert(self):
        """Calculates the anomaly rate and dispatches alerts if threshold is met."""
        try:
            current_rate = self.anomaly_count / self.total_packets
        except ZeroDivisionError:
            current_rate = 0.0

        if current_rate >= self.threshold:
            self.alert_triggered = True
            print(f"\n!!! ALERT TRIGGERED: Anomaly rate is {current_rate:.2%} (>= threshold {self.threshold:.2%}) !!!")

            title = "⚠️ High Anomaly Rate Detected in Network Traffic!"
            message_body = (
                f"An anomaly rate of {current_rate:.2%} was detected, exceeding the set threshold of {self.threshold:.2%}.\n\n"
                f"Details:\n"
                f"- Anomalies Detected: {self.anomaly_count}\n"
                f"- Total Packets Analyzed: {self.total_packets}\n\n"
                "Immediate review of the system dashboard is recommended."
            )

            # Dispatch alerts
            send_desktop_notification(title, message_body)
            send_email_alert(subject=title, body=message_body)
