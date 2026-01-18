import pandas as pd
import numpy as np

def generate_sample_data(filename='sample_network_data.csv', num_rows=1000):
    """
    Generates a dummy CSV file with realistic network data for training.
    Includes both normal traffic and some anomalies.
    """
    # Normal Traffic
    src_ips = ['192.168.1.10', '192.168.1.12', '10.0.0.5', '10.0.0.6']
    dst_ips = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1']
    protocols = [6, 17] # TCP, UDP
    
    data = {
        'src_ip': [np.random.choice(src_ips) for _ in range(num_rows)],
        'dst_ip': [np.random.choice(dst_ips) for _ in range(num_rows)],
        'src_port': np.random.randint(1024, 65535, size=num_rows),
        'dst_port': [np.random.choice([80, 443, 53]) for _ in range(num_rows)],
        'proto': [np.random.choice(protocols) for _ in range(num_rows)],
        'len': np.random.randint(40, 1500, size=num_rows),
        'duration': np.random.uniform(0.1, 5.0, size=num_rows),
        'packet_count': np.random.randint(1, 20, size=num_rows)
    }
    
    df = pd.DataFrame(data)
    
    # Introduce some anomalies (e.g., port scanning, large packets)
    num_anomalies = int(num_rows * 0.05) # 5% anomalies
    for _ in range(num_anomalies):
        idx = np.random.randint(0, num_rows)
        anomaly_type = np.random.choice(['scan', 'large_packet'])
        
        if anomaly_type == 'scan':
            df.loc[idx, 'dst_port'] = np.random.randint(1, 1024)
            df.loc[idx, 'duration'] = 0.01
            df.loc[idx, 'packet_count'] = 1
        else: # large_packet
            df.loc[idx, 'len'] = np.random.randint(2000, 5000)
            df.loc[idx, 'src_ip'] = '172.16.50.100' # Suspicious IP
            
    df.to_csv(filename, index=False)
    print(f"Generated {num_rows} rows of sample data in '{filename}'")
