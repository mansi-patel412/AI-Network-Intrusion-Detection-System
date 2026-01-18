import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import pandas as pd

import model
import capture
import detection
import visualization
import utils

class NIDS_GUI(tk.Tk):
    """
    The main Graphical User Interface for the Network Intrusion Detection System.
    """
    def __init__(self):
        super().__init__()
        self.title("AI-Powered Network Intrusion Detection System")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Class attributes
        self.nids_model = None
        self.is_capture_running = False
        self.capture_thread = None
        self.feature_columns = []

        # --- UI Setup ---
        self.create_widgets()

    def create_widgets(self):
        """Creates and arranges all the UI elements in the window."""
        # Main container frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Top Frame for Controls ---
        controls_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        controls_frame.pack(fill=tk.X, side=tk.TOP, pady=5)
        controls_frame.columnconfigure(4, weight=1) # Make status label expand

        # Control Buttons
        self.btn_generate_data = ttk.Button(controls_frame, text="Generate Sample CSV", command=self.generate_sample_csv)
        self.btn_generate_data.grid(row=0, column=0, padx=5)

        self.btn_train = ttk.Button(controls_frame, text="Load CSV & Train Model", command=self.load_and_train_model)
        self.btn_train.grid(row=0, column=1, padx=5)

        self.btn_start_capture = ttk.Button(controls_frame, text="Start Live Capture", command=self.start_capture, state=tk.DISABLED)
        self.btn_start_capture.grid(row=0, column=2, padx=5)

        self.btn_stop_capture = ttk.Button(controls_frame, text="Stop Live Capture", command=self.stop_capture, state=tk.DISABLED)
        self.btn_stop_capture.grid(row=0, column=3, padx=5)
        
        # Status Labels
        self.lbl_model_status = ttk.Label(controls_frame, text="Model Status: Not Trained", foreground="red")
        self.lbl_model_status.grid(row=0, column=4, padx=10, sticky=tk.E)

        self.lbl_capture_status = ttk.Label(controls_frame, text="Capture Status: Stopped", foreground="red")
        self.lbl_capture_status.grid(row=0, column=5, padx=10, sticky=tk.E)

        # --- Notebook for Tabs ---
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        dashboard_tab = ttk.Frame(notebook)
        alerts_tab = ttk.Frame(notebook)
        
        notebook.add(dashboard_tab, text='Dashboard')
        notebook.add(alerts_tab, text='Alerts & History')

        # --- Dashboard Tab Content ---
        # Anomaly Table
        self.anomaly_view = visualization.create_anomaly_table(dashboard_tab)
        self.anomaly_view.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- Alerts Tab Content (Placeholder for now) ---
        log_label = ttk.Label(alerts_tab, text="Historical alert data and detailed logs will be shown here.")
        log_label.pack(padx=10, pady=10)


    def generate_sample_csv(self):
        """Callback to generate a sample CSV file for training."""
        try:
            utils.generate_sample_data('sample_network_data.csv')
            messagebox.showinfo("Success", "Generated 'sample_network_data.csv' successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not generate sample data: {e}")

    def load_and_train_model(self):
        """Opens a file dialog to select a CSV and trains the NIDS model."""
        filepath = filedialog.askopenfilename(
            title="Select Training CSV",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )
        if not filepath:
            return

        try:
            self.nids_model, self.feature_columns, X_train = model.train_model_from_csv(filepath)
            self.lbl_model_status.config(text="Model Status: Trained", foreground="green")
            self.btn_start_capture.config(state=tk.NORMAL)
            messagebox.showinfo("Success", f"Model trained successfully on {len(X_train)} samples.")
        except Exception as e:
            self.lbl_model_status.config(text="Model Status: Error", foreground="red")
            messagebox.showerror("Model Training Error", str(e))

    def start_capture(self):
        """Starts the real-time packet capture in a separate thread."""
        self.is_capture_running = True
        self.btn_start_capture.config(state=tk.DISABLED)
        self.btn_stop_capture.config(state=tk.NORMAL)
        self.btn_train.config(state=tk.DISABLED) # Disable retraining while capturing
        self.lbl_capture_status.config(text="Capture Status: Running", foreground="green")

        # Start packet capture in a new thread to keep the GUI responsive
        self.capture_thread = threading.Thread(
            target=capture.start_sniffing,
            args=(self.process_packet,), # Callback function
            daemon=True
        )
        self.capture_thread.start()

    def stop_capture(self):
        """Stops the packet capture."""
        self.is_capture_running = False
        if self.capture_thread.is_alive():
             # The sniffing loop will see the flag and exit
             pass
        self.btn_start_capture.config(state=tk.NORMAL)
        self.btn_stop_capture.config(state=tk.DISABLED)
        self.btn_train.config(state=tk.NORMAL)
        self.lbl_capture_status.config(text="Capture Status: Stopped", foreground="red")

    def process_packet(self, packet):
        """
        Callback function passed to the capture module.
        This function is called for each captured packet.
        """
        if not self.is_capture_running:
            return # Stop processing if capture has been stopped
            
        # Perform anomaly detection
        is_anomaly, features = detection.detect_anomaly(self.nids_model, packet, self.feature_columns)
        
        # All GUI updates should be done on the main thread
        if is_anomaly:
            self.after(0, self.update_anomaly_table, features)

    def update_anomaly_table(self, features):
        """Updates the anomaly table in the GUI."""
        visualization.add_anomaly_to_table(self.anomaly_view, features)

    def on_closing(self):
        """Handles the window closing event."""
        if self.is_capture_running:
            messagebox.showwarning("Capture Running", "Please stop the live capture before closing the application.")
        else:
            self.destroy()
