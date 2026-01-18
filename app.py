import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import os
import time
from scapy.all import sniff, wrpcap
import database as db  # assuming your database file is named database.py

# ==========================================================
#                  APP STARTS HERE
# ==========================================================

# Initialize DB
db.init_db()

# --- Backend Modules ---
try:
    import model
    import detection
    import alerts  # We now rely on alerts.py for all alert handling
except ImportError as e:
    st.error(f"Failed to import a backend module: {e}")
    st.stop()

# --- Streamlit Page Config ---
st.set_page_config(page_title="AI-Powered NIDS", page_icon="🛡️", layout="wide")

# --- Initialize Session State ---
defaults = {
    "model": None,
    "feature_columns": [],
    "predictions": pd.DataFrame(),
    "alert_manager": alerts.AlertManager(),  # Use AlertManager from alerts.py
    "live_total_packets": 0,
    "live_anomaly_count": 0,
    "capture_running": False,
    "show_app_pw_info": False  # session flag for the App Password info popup
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# --- UI Layout ---
st.title("🛡️ AI-Powered Network Intrusion Detection System")
st.caption(f"Current Time (IST): {time.strftime('%Y-%m-%d %H:%M:%S')}")

col1, col2, col3 = st.columns(3)
total_packets_placeholder = col1.empty()
anomaly_count_placeholder = col2.empty()
anomaly_rate_placeholder = col3.empty()
alert_status_placeholder = st.empty()
st.markdown("---")

# --- Sidebar Controls ---
st.sidebar.header("⚙️ Controls")
input_mode = st.sidebar.radio("Choose Mode", ('Live Capture', 'Upload CSV & Train'))

# --- Sidebar Email Config (with Info button for App Password) ---
st.sidebar.markdown("---")
st.sidebar.header("📧 Email Alert Settings")

# Layout password input and info button in columns (sidebar)
pw_col, info_col = st.sidebar.columns([8, 1])
sender_email = st.sidebar.text_input("Sender Email (Gmail)")
sender_password = pw_col.text_input("App Password", type="password")
receiver_email = st.sidebar.text_input("Receiver Email")

# Info button
if info_col.button("ℹ️"):
    # toggle the popup flag
    st.session_state.show_app_pw_info = True

# Show the popup (modal if available, else expander) with steps and a close button
if st.session_state.show_app_pw_info:
    info_title = "How to get a Gmail App Password"
    info_steps = [
        "1. Go to your Google Account: https://myaccount.google.com/",
        "2. Under 'Security', ensure 2-Step Verification is ON for your account.",
        "3. After enabling 2-Step Verification, go to 'App passwords' (also under Security).",
        "4. Under 'Select app' choose 'Other (Custom name)' and type a name like 'NIDS App'.",
        "5. Click 'Generate' — Google will show a 16-character app password.",
        "6. Copy that 16-character string and paste it into the 'App Password' field here.",
        "",
        "Notes:",
        "- Use this App Password (not your normal Google account password).",
        "- If you can't find 'App passwords', verify 2-Step Verification is enabled and you're using a Google account that allows app passwords (some accounts like Google Workspace may have restrictions).",
    ]
    # Prefer modal if available (newer Streamlit versions)
    if hasattr(st, "modal"):
        try:
            with st.modal(info_title):
                st.write("\n".join(info_steps))
                if st.button("Close"):
                    st.session_state.show_app_pw_info = False
        except Exception:
            # fallback to expander if modal fails
            exp = st.expander(info_title, expanded=True)
            with exp:
                st.write("\n".join(info_steps))
                if st.button("Close (close expander)"):
                    st.session_state.show_app_pw_info = False
    else:
        # Fallback: show an expander in the main area
        exp = st.expander(info_title, expanded=True)
        with exp:
            st.write("\n".join(info_steps))
            if st.button("Close (close expander)"):
                st.session_state.show_app_pw_info = False

# ✅ Configure alerts module with user credentials and save to DB
if sender_email and sender_password and receiver_email:
    alerts.configure_email(sender_email, sender_password, receiver_email)
    db.save_email_config(sender_email, sender_password, receiver_email)

# ==========================================================
#                     LIVE CAPTURE MODE
# ==========================================================
if input_mode == 'Live Capture':
    st.sidebar.markdown("---")
    st.sidebar.header("🔴 Live Capture Settings")

    is_model_trained = st.session_state.model is not None
    if not is_model_trained:
        st.sidebar.warning("Train a model before starting capture.")

    capture_duration = st.sidebar.number_input(
        "Capture Duration (seconds)", 10, 300, 30, disabled=not is_model_trained
    )

    st.sidebar.markdown("---")
    st.sidebar.header("🚨 Alert Settings")
    enable_alerts = st.sidebar.checkbox("Enable Real-time Alerts", True, disabled=not is_model_trained)
    alert_threshold = st.sidebar.slider("Anomaly Rate Threshold (%)", 1, 100, 25) / 100.0
    st.session_state.alert_manager.threshold = alert_threshold

    if st.sidebar.button("Start Live Capture", disabled=not is_model_trained, use_container_width=True):
        st.session_state.capture_running = True
        st.session_state.alert_manager.reset()
        st.session_state.predictions = pd.DataFrame()
        st.session_state.live_total_packets = 0
        st.session_state.live_anomaly_count = 0
        alert_status_placeholder.empty()

        if enable_alerts:
            alert_status_placeholder.info(f"Alerts trigger if anomaly rate > {alert_threshold:.0%}")
        else:
            alert_status_placeholder.warning("Alerting disabled.")

        packet_results, captured_packets = [], []
        progress_bar = st.progress(0, text="Initializing capture...")
        start_time = time.time()

        def packet_callback(packet):
            captured_packets.append(packet)
            is_anomaly, features = detection.detect_anomaly(
                st.session_state.model, packet, st.session_state.feature_columns
            )
            st.session_state.live_total_packets += 1
            if is_anomaly:
                st.session_state.live_anomaly_count += 1

            # Log packets
            db.log_packet(str(packet.summary()), is_anomaly, features)

            # Use AlertManager from alerts.py if alerts are enabled
            if enable_alerts:
                st.session_state.alert_manager.update_counts(is_anomaly)

            packet_results.append({"packet": str(packet.summary()), "is_anomaly": is_anomaly, **features})

        with st.spinner("Capturing and analyzing network traffic..."):
            while time.time() - start_time < capture_duration:
                sniff(prn=packet_callback, count=10, timeout=1, store=False)
                elapsed = time.time() - start_time
                progress = min(int((elapsed / capture_duration) * 100), 100)
                progress_bar.progress(progress, text=f"Capture in progress... {int(capture_duration - elapsed)}s left")
                total_packets_placeholder.metric("Total Packets", st.session_state.live_total_packets)
                anomaly_count_placeholder.metric("Anomalies", st.session_state.live_anomaly_count)
                if st.session_state.live_total_packets:
                    rate = (st.session_state.live_anomaly_count / st.session_state.live_total_packets) * 100
                    anomaly_rate_placeholder.metric("Anomaly Rate", f"{rate:.2f}%")
                if st.session_state.alert_manager.alert_triggered:
                    msg = f"🚨 ALERT TRIGGERED! Threshold {alert_threshold:.0%} breached."
                    alert_status_placeholder.error(msg)
                    db.log_alert(msg, "HIGH")

            progress_bar.progress(100, text="Capture complete.")
        st.success("✅ Capture finished.")
        st.session_state.capture_running = False

        # Store and allow download
        if packet_results:
            st.session_state.predictions = pd.DataFrame(packet_results)
        if captured_packets:
            wrpcap("captured_traffic.pcap", captured_packets)
            with open("captured_traffic.pcap", "rb") as f:
                st.download_button("Download PCAP", f, "captured_traffic.pcap", mime="application/vnd.tcpdump.pcap")

        # ==========================================================
        # ✅ SEND FINAL REPORT EMAIL AFTER CAPTURE
        # ==========================================================
        if not st.session_state.predictions.empty and enable_alerts:
            total_packets = len(st.session_state.predictions)
            anomaly_count = st.session_state.predictions['is_anomaly'].sum()
            final_rate = anomaly_count / total_packets if total_packets else 0

            # Send the final summary email using alerts.py
            alerts.send_final_report(final_rate, alert_threshold, total_packets, anomaly_count)

            # Log to database
            if final_rate > alert_threshold:
                db.log_alert("Final anomaly rate exceeded threshold.", "CRITICAL")
            else:
                db.log_alert("Final anomaly rate within safe range.", "INFO")

# ==========================================================
#                    MODEL TRAINING MODE
# ==========================================================
elif input_mode == 'Upload CSV & Train':
    st.header("🧠 Model Training")
    uploaded_file = st.file_uploader("Upload a network traffic CSV file", type=["csv"])
    if uploaded_file and st.button("Train Model", use_container_width=True):
        with st.spinner("Training model..."):
            try:
                with open("temp_train.csv", "wb") as f:
                    f.write(uploaded_file.getbuffer())
                st.session_state.model, st.session_state.feature_columns = model.train_model_from_csv("temp_train.csv")
                os.remove("temp_train.csv")
                st.success("✅ Model trained successfully!")
                st.balloons()
            except Exception as e:
                st.error(f"Training failed: {e}")

# ==========================================================
#                    VISUALIZATION
# ==========================================================
if not st.session_state.predictions.empty:
    st.markdown("---")
    st.header("📊 Analysis Results")
    fig_col1, fig_col2 = st.columns(2)
    with fig_col1:
        graph_df = pd.DataFrame({
            'Packet Number': np.arange(1, len(st.session_state.predictions) + 1),
            'Cumulative Anomalies': st.session_state.predictions['is_anomaly'].cumsum()
        }).set_index('Packet Number')
        st.line_chart(graph_df)
    with fig_col2:
        counts = st.session_state.predictions['is_anomaly'].value_counts().reset_index()
        counts.columns = ['type', 'count']
        counts['type'] = counts['type'].map({True: 'Anomaly', False: 'Normal'})
        fig = px.pie(counts, names='type', values='count', title='Normal vs Anomaly Traffic')
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Detected Anomalies Details")
    anomaly_df = st.session_state.predictions[st.session_state.predictions['is_anomaly']]
    if not anomaly_df.empty:
        display_cols = [c for c in st.session_state.feature_columns if c in anomaly_df.columns]
        st.dataframe(anomaly_df[['packet'] + display_cols])
    else:
        st.write("No anomalies detected in this session.")

# ==========================================================
#                  DATABASE SUMMARY
# ==========================================================
st.markdown("---")
st.header("📋 Recent Alerts")
recent_alerts = db.get_recent_alerts(limit=10)
if recent_alerts:
    for ts, msg, sev in recent_alerts:
        st.write(f"[{ts}] ({sev}) {msg}")
else:
    st.write("No alerts yet.")

st.markdown("---")
st.header("📊 Database Stats")
anomalies, total = db.get_anomaly_stats()
st.metric("Total Packets in DB", total)
st.metric("Anomalies in DB", anomalies)
st.metric("Anomaly Rate in DB", f"{(anomalies/total*100 if total else 0):.2f}%")
