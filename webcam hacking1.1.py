import socket
import psutil
import hashlib
import os
import subprocess
import platform
import time

# For Android ADB interaction
try:
    from ppadb.client import Client
    ADB_AVAILABLE = True
except ImportError:
    ADB_AVAILABLE = False
    print("Install pure-python-adb: pip install pure-python-adb")

# Function to scan open ports on the local machine
def scan_ports(start_port=1, end_port=1024):
    print(f"\nScanning open ports ({start_port}-{end_port})...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex(('127.0.0.1', port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports found.")
    return open_ports

# Function to list running processes
def list_processes():
    print("\nListing running processes...")
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(f"PID: {proc.info['pid']}, Name: {proc.info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    for proc in processes[:5]:  # Show top 5 for brevity
        print(proc)
    print(f"Total processes: {len(processes)}")
    return processes

# Function to check file integrity (hash of critical files)
def check_file_integrity(file_path):
    if not os.path.exists(file_path):
        print(f"\nFile {file_path} does not exist.")
        return None
    print(f"\nChecking integrity of {file_path}...")
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    file_hash = hasher.hexdigest()
    print(f"SHA-256: {file_hash}")
    return file_hash

# Function to check Android device security (requires ADB)
def check_android_security():
    if not ADB_AVAILABLE:
        print("\nADB library not installed. Skipping Android checks.")
        return
    try:
        adb = Client(host='127.0.0.1', port=5037)
        devices = adb.devices()
        if not devices:
            print("\nNo Android devices connected via ADB.")
            return
        device = devices[0]
        print(f"\nConnected to Android device: {device.serial}")

        # Check if USB debugging is enabled
        debug_status = device.shell('getprop ro.debuggable')
        print(f"USB Debugging Enabled: {'Yes' if '1' in debug_status else 'No'}")

        # Check installed packages with dangerous permissions
        packages = device.shell('pm list packages').splitlines()
        print(f"\nTotal apps installed: {len(packages)}")
        for pkg in packages[:5]:  # Show top 5 for brevity
            pkg = pkg.replace('package:', '').strip()
            perms = device.shell(f'dumpsys package {pkg} | grep permission')
            print(f"App: {pkg}, Permissions: {perms[:100]}...")

    except Exception as e:
        print(f"Error checking Android device: {e}")

# Main function to run security checks
def run_security_tool():
    print("=== Security Check Tool ===")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Laptop security checks
    print("Running laptop security checks...")
    scan_ports()
    list_processes()
    
    # Check a sample critical file (modify path as needed)
    sample_file = "/etc/passwd" if platform.system() != "Windows" else "C:\\Windows\\System32\\drivers\\etc\\hosts"
    check_file_integrity(sample_file)

    # Android security checks (if ADB is set up)
    print("\nRunning Android security checks...")
    check_android_security()

if __name__ == "__main__":
    try:
        run_security_tool()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")