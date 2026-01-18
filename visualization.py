import tkinter as tk
from tkinter import ttk
from datetime import datetime

def create_anomaly_table(parent_frame):
    """
    Creates and configures the Treeview widget for displaying anomalies.

    Args:
        parent_frame (tk.Frame): The parent widget to place the table in.

    Returns:
        ttk.Treeview: The configured Treeview widget.
    """
    columns = ('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'len')
    
    tree = ttk.Treeview(parent_frame, columns=columns, show='headings')
    
    # Define headings
    tree.heading('timestamp', text='Timestamp')
    tree.heading('src_ip', text='Source IP')
    tree.heading('dst_ip', text='Destination IP')
    tree.heading('src_port', text='Source Port')
    tree.heading('dst_port', text='Dest. Port')
    tree.heading('proto', text='Protocol')
    tree.heading('len', text='Length')
    
    # Configure column widths
    tree.column('timestamp', width=160)
    tree.column('src_ip', width=120)
    tree.column('dst_ip', width=120)
    tree.column('src_port', width=80)
    tree.column('dst_port', width=80)
    tree.column('proto', width=60)
    tree.column('len', width=60)
    
    return tree

def add_anomaly_to_table(treeview, features):
    """
    Inserts a new row into the anomaly table.

    Args:
        treeview (ttk.Treeview): The table widget to update.
        features (dict): A dictionary containing the feature data for the anomaly.
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    # Extract values, providing defaults if a key is missing
    src_ip = features.get('src_ip', 'N/A')
    dst_ip = features.get('dst_ip', 'N/A')
    src_port = features.get('src_port', 'N/A')
    dst_port = features.get('dst_port', 'N/A')
    proto = features.get('proto', 'N/A')
    length = features.get('len', 'N/A')
    
    values = (now, src_ip, dst_ip, src_port, dst_port, proto, length)
    
    # Insert at the beginning of the table
    treeview.insert('', 0, values=values)
