import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
os.makedirs(WORDLISTS_DIR, exist_ok=True)

# Default service ports
SERVICE_PORTS = {
    "SOCKS5": "1080",
    "SSH": "22",
    "RDP": "3389",
    "FTP": "21",
    "HTTP": "80",
    "HTTPS": "443",
    "SMTP": "25",
    "TELNET": "23",
    "MYSQL": "3306",
    "POSTGRESQL": "5432",
    "VNC": "5900"
}