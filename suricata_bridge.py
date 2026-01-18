import json
import time
import os
import database as db  # Your existing database.py
import alerts  # To send emails and notifications

# Default Suricata log path on Windows
EVE_JSON_PATH = r"C:/Program Files/Suricata/log/eve.json"

def follow_file(file_handle):
    """Tail-like generator for continuous file read."""
    file_handle.seek(0, 2)
    while True:
        line = file_handle.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

if __name__ == "__main__":
    print("🚀 Starting the Suricata Integration Bridge...")

    # Initialize the database
    db.init_db()

    # Load email credentials from the database
    sender, password, receiver = db.get_email_config()
    if sender and password and receiver:
        alerts.configure_email(sender, password, receiver)
        print(f"✅ Email credentials loaded from database for sender: {sender}")
    else:
        print("⚠️ No email credentials found in database. Email alerts will be skipped.")

    try:
        with open(EVE_JSON_PATH, 'r', encoding='utf-8', errors='ignore') as log_file:
            print(f"✅ Successfully opened Suricata log file: {EVE_JSON_PATH}")
            print("👂 Listening for new attack alerts from Suricata...")

            log_lines = follow_file(log_file)

            for line in log_lines:
                try:
                    event = json.loads(line)

                    # Process Suricata alert events
                    if event.get('event_type') == 'alert':
                        alert_info = event.get('alert', {})

                        attack_type = alert_info.get('signature', 'Unknown Attack')
                        category = alert_info.get('category', 'Unknown Category')
                        severity = f"Suricata Severity {alert_info.get('severity', 3)}"
                        src_ip = event.get('src_ip', 'N/A')
                        dest_ip = event.get('dest_ip', 'N/A')

                        log_message = f"ATTACK DETECTED: {attack_type} ({category}) from {src_ip} to {dest_ip}"

                        print(f"  -> {log_message}")

                        # Log to DB
                        try:
                            db.log_alert(message=log_message, severity=severity)
                        except Exception as e:
                            print(f"⚠️ Failed to log alert to DB: {e}")

                        # Prepare email
                        subject = f"Suricata Alert: {attack_type}"
                        pretty_event = json.dumps(event, indent=2)
                        body = (
                            f"Suricata detected an alert.\n\n"
                            f"Signature: {attack_type}\n"
                            f"Category: {category}\n"
                            f"Severity: {severity}\n"
                            f"Source IP: {src_ip}\n"
                            f"Destination IP: {dest_ip}\n\n"
                            f"Full event JSON:\n{pretty_event}"
                        )

                        # Send desktop notification
                        try:
                            alerts.send_desktop_notification(subject, log_message)
                        except Exception as e:
                            print(f"⚠️ Failed to send desktop notification: {e}")

                        # Send email if credentials are configured
                        if sender and password and receiver:
                            try:
                                alerts.send_email_alert(subject=subject, body=body)
                            except Exception as e:
                                print(f"❌ Error sending email alert: {e}")
                        else:
                            print("⚠️ Skipping email alert (no credentials configured).")

                except json.JSONDecodeError:
                    continue  # Skip incomplete JSON lines
                except Exception as e:
                    print(f"❌ Error processing log entry: {e}")

    except FileNotFoundError:
        print(f"❌ Cannot find the log file at '{EVE_JSON_PATH}'. Ensure Suricata is running.")
    except KeyboardInterrupt:
        print("\n🛑 Suricata bridge stopped.")
