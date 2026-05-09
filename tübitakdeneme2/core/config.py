import os
from dotenv import load_dotenv

load_dotenv()

# --- API Anahtarları (.env dosyasından okunur) ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
HIBP_API_KEY   = os.getenv("HIBP_API_KEY", "")

# --- Kritik Portlar (tek kaynak — artık iki dosyaya dağılmıyor) ---
# risk_engine.py ve collector.py her ikisi de buradan import eder
CRITICAL_PORTS = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    445,   # SMB
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    6379,  # Redis
    8080,  # HTTP alternatif
    27017, # MongoDB
}

# --- Risk Ağırlıkları ---
RISK_WEIGHT_WHOIS  = 10   # WHOIS açıksa
RISK_WEIGHT_LEAK   = 30   # Her sızıntı için (max 90)
RISK_WEIGHT_PORT   = 20   # Her kritik port için (max 60)
RISK_WEIGHT_SOCIAL = 8    # Her sosyal hesap için (max 40)

RISK_MAX_LEAK   = 90
RISK_MAX_PORT   = 60
RISK_MAX_SOCIAL = 40

# --- Risk Seviyeleri ---
RISK_LEVEL_CRITICAL = 150
RISK_LEVEL_HIGH     = 80
RISK_LEVEL_MEDIUM   = 40

# --- Dış Servisler ---
GO_SCANNER_URL  = "http://localhost:8765/scan"
GO_SCANNER_PORT = 8765

# --- DNS Risk Ağırlığı ---
RISK_WEIGHT_DNS = 5     # Her DNS risk notu için (max 20)
RISK_MAX_DNS    = 20