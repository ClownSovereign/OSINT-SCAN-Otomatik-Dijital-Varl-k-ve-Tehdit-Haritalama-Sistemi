import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
HIBP_API_KEY   = os.getenv("HIBP_API_KEY", "")

CRITICAL_PORTS = {
    21,   
    22,   
    23,    
    25,  
    53,  
    445,   
    1433, 
    3306,  
    3389,
    5432, 
    6379, 
    8080,  
    27017,
}

RISK_WEIGHT_WHOIS  = 10 
RISK_WEIGHT_LEAK   = 30   
RISK_WEIGHT_PORT   = 20   
RISK_WEIGHT_SOCIAL = 8   

RISK_MAX_LEAK   = 90
RISK_MAX_PORT   = 60
RISK_MAX_SOCIAL = 40

RISK_LEVEL_CRITICAL = 150
RISK_LEVEL_HIGH     = 80
RISK_LEVEL_MEDIUM   = 40

GO_SCANNER_URL  = "http://localhost:8765/scan"
GO_SCANNER_PORT = 8765

RISK_WEIGHT_DNS = 5   
RISK_MAX_DNS    = 20
