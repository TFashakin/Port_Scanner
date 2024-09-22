import socket
import threading
import csv
import random
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Initialization
def initialize_log_file():
    with open('scan_results.csv', mode='w') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "IP Address", "Port", "Status", "Banner"])

# results log with timestamps
def log_result(ip, port, status, banner="N/A"):
    with open('scan_results.csv', mode='a') as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), ip, port, status, banner])
#port scanning function with banner grabbing
def scan_port_and_grab_banner(ip, port, timeout, verbose=False):
    try:
        # Port scanning
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        
        if result == 0:
            # Port is open, attempt banner grabbing
            banner = "No banner"
            try:
                s.send(b"HEAD / HTTP/1.1\r\n\r\n")  # Sending a simple request
                banner = s.recv(1024).decode().strip()
            except socket.error:
                banner = "No banner or service detection failed"
            
            # Logging and output based on verbosity
            log_result(ip, port, "open", banner)
            if verbose:
                print(f"Port {port} is open: {banner}")
        else:
            log_result(ip, port, "closed")
            if verbose:
                print(f"Port {port} is closed")
    except socket.timeout:
        log_result(ip, port, "timeout")
        if verbose:
            print(f"Port {port} timed out")
    except socket.error as e:
        log_result(ip, port, f"error: {str(e)}")
        if verbose:
            print(f"Error scanning port {port}: {str(e)}")
    finally:
        s.close()

# Function to manage port scanning with randomized order and modes
def start_scan(target_ip, start_port, end_port, max_threads=100, timeout=1, verbose=False, mode="full"):
    # Create a list of ports to scan and randomize if needed
    ports = list(range(start_port, end_port + 1))
    
    # Adjust scan mode
    if mode == "quick":
        # For a quick scan, scan fewer ports (e.g., top 100 common ports)
        ports = random.sample(ports, min(100, len(ports)))
    random.shuffle(ports)  # Randomize the scan order

    print(f"Starting {mode} scan on {target_ip} for ports {start_port}-{end_port}...")

    total_ports = len(ports)
    progress = 0
    #Moderate performance
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for port in ports:
            futures.append(executor.submit(scan_port_and_grab_banner, target_ip, port, timeout, verbose))
            
            # Simple progress indicator
            progress += 1
            print(f"Progress: {progress}/{total_ports} ports scanned", end='\r')

    print(f"\nScan complete. Results saved to 'scan_results.csv'.")

# Initialize the log file once at the start
initialize_log_file()

# Customize your scan here
target_ip = "90.221.232.109"  # Replace with your target IP address
start_port = 1
end_port = 1024
max_threads = 100
timeout = 1  # Timeout in seconds
verbose = True  # Set to False for less console output
scan_mode = "full"  # Choose between "full" or "quick" scan mode

# Start the scan
start_scan(target_ip, start_port, end_port, max_threads=max_threads, timeout=timeout, verbose=verbose, mode=scan_mode)
