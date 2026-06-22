import socket
import subprocess
import platform
import re
import uuid
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import lookup_vendor, normalize_mac

def get_local_ip():
    """
    Attempts to auto-detect the local IPv4 address by opening a dummy socket.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't send packets, just registers local interface routing to public target
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        # Fallback to standard hostname resolution
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def get_default_subnet():
    """
    Retrieves a recommended /24 subnet based on the detected local IP.
    """
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return "192.168.1.0/24"
    parts = local_ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"

def get_self_mac():
    """
    Gets the MAC address of the local machine running the scan.
    """
    try:
        mac_num = uuid.getnode()
        mac_hex = f"{mac_num:012x}"
        mac_str = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
        return normalize_mac(mac_str)
    except Exception:
        return "unknown"

def get_mac_from_arp(ip):
    """
    Resolves the MAC address corresponding to an IP using the local ARP table.
    Works without root privileges on macOS, Linux, and Windows.
    """
    # Loopback or local machine check
    local_ip = get_local_ip()
    if ip == local_ip:
        self_mac = get_self_mac()
        if self_mac != "unknown":
            return self_mac

    try:
        # Run arp -a and parse the output
        result = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            for line in lines:
                # Search for the exact IP wrapped in parentheses or bounds
                if f"({ip})" in line or f" {ip} " in line:
                    # Match standard hex characters
                    match = re.search(r"([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})", line)
                    if match:
                        return normalize_mac(match.group(1))
        
        # macOS specific fallback: query arp directly for the IP
        # Format: "arp <ip>"
        result_direct = subprocess.run(["arp", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result_direct.returncode == 0:
            match = re.search(r"([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})", result_direct.stdout)
            if match:
                return normalize_mac(match.group(1))
    except Exception:
        pass
    
    return "Unknown"

def get_hostname(ip):
    """
    Performs a reverse DNS lookup to get the hostname of the IP.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "Unknown"
    except Exception:
        return "Unknown"

def ping_ip(ip):
    """
    Sends a single ICMP Echo Request (ping) to check if an IP is active.
    Adapts flags for macOS, Windows, and Linux.
    """
    system = platform.system().lower()
    
    if "darwin" in system:
        # macOS: -c 1 (count), -t 1 (timeout in seconds)
        cmd = ["ping", "-c", "1", "-t", "1", ip]
    elif "windows" in system:
        # Windows: -n 1 (count), -w 1000 (timeout in ms)
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        # Linux: -c 1 (count), -W 1 (timeout in seconds)
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        
    try:
        # Use short timeout so command cannot block indefinitely
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        return res.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def parse_subnet(subnet_str):
    """
    Parses range notations (e.g. 192.168.1.0/24, 192.168.1.50-100, 192.168.1.10)
    and returns a list of target IP addresses as strings.
    """
    ips = []
    cleaned = subnet_str.strip()
    
    # 1. CIDR notation
    if "/" in cleaned:
        try:
            network = ipaddress.ip_network(cleaned, strict=False)
            for ip in network.hosts():
                ips.append(str(ip))
        except ValueError:
            pass
            
    # 2. Host ranges (e.g., 192.168.1.1-254)
    elif "-" in cleaned:
        parts = cleaned.split("-")
        if len(parts) == 2:
            start_str = parts[0].strip()
            end_str = parts[1].strip()
            
            # Sub-case: end range is a single number (e.g., "192.168.1.10-50")
            if "." not in end_str:
                ip_parts = start_str.split(".")
                if len(ip_parts) == 4:
                    base = ".".join(ip_parts[:3])
                    try:
                        start = int(ip_parts[3])
                        end = int(end_str)
                        for host in range(start, end + 1):
                            ips.append(f"{base}.{host}")
                    except ValueError:
                        pass
            else:
                # Sub-case: full IP range (e.g., "192.168.1.50-192.168.1.100")
                try:
                    start_ip = ipaddress.IPv4Address(start_str)
                    end_ip = ipaddress.IPv4Address(end_str)
                    curr = start_ip
                    while curr <= end_ip:
                        ips.append(str(curr))
                        curr += 1
                except ValueError:
                    pass
    # 3. Single IP
    else:
        try:
            ipaddress.IPv4Address(cleaned)
            ips.append(cleaned)
        except ValueError:
            pass
            
    return ips

def scan_single_ip(ip):
    """
    Scans a single IP address: pings it, resolves MAC/vendor, and gets hostname.
    """
    if ping_ip(ip):
        mac = get_mac_from_arp(ip)
        vendor = lookup_vendor(mac)
        hostname = get_hostname(ip)
        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "status": "Active"
        }
    return None

def scan_network(subnet_str, progress_callback=None, thread_count=50):
    """
    Runs a multi-threaded network scan over the parsed subnet/IP range.
    Triggers progress_callback (progress_dict) as each IP is processed.
    """
    ips = parse_subnet(subnet_str)
    if not ips:
        return []
        
    total_ips = len(ips)
    active_devices = []
    scanned_count = 0
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        # Submit all ping jobs
        futures = {executor.submit(scan_single_ip, ip): ip for ip in ips}
        
        for future in as_completed(futures):
            scanned_count += 1
            device = future.result()
            if device:
                active_devices.append(device)
            
            # Send status update if callback is specified
            if progress_callback:
                progress_callback({
                    "scanned": scanned_count,
                    "total": total_ips,
                    "percentage": int((scanned_count / total_ips) * 100),
                    "current_device": device  # Returns the device if active, None if inactive
                })
                
    # Sort active devices by numerical IP value
    try:
        active_devices.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    except Exception:
        pass
        
    return active_devices
