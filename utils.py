import os
import platform
import subprocess
import re

def find_exe_in_dir(directory, name=""):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".exe") and (not name or name in file.lower()):
                return os.path.join(root, file)
    return ""

def get_creation_flags():
    if platform.system() == "Windows":
        return subprocess.CREATE_NO_WINDOW
    return 0

def is_valid_ip(ip):
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    return all(0 <= int(part) <= 255 for part in match.groups())

def parse_ip_range(ip_range):
    """Parse IP range like 192.168.1.1-100"""
    if '-' not in ip_range:
        return [ip_range]
    
    try:
        base_ip, range_part = ip_range.rsplit('.', 1)
        start, end = range_part.split('-')
        start = int(start)
        end = int(end)
        return [f"{base_ip}.{i}" for i in range(start, end + 1)]
    except (ValueError, IndexError):
        return [ip_range]