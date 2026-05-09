"""
Subdomain Tarayıcı
------------------
Yaygın subdomain'leri DNS çözümlemesiyle keşfeder.
dnspython gerektirmez — socket kullanır.
Paralel tarama için ThreadPoolExecutor kullanır.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.db import get_conn


# ─── DB tablosu ─────────────────────────────────────────────────────────────

SUBDOMAIN_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS subdomain_results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER REFERENCES scans(id),
    subdomain  TEXT,
    ip         TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

# Hassas subdomain'ler — admin panelleri, geliştirme ortamları vs.
SENSITIVE_KEYWORDS = {
    "admin", "panel", "dev", "test", "staging", "beta",
    "api", "internal", "vpn", "mail", "ftp", "ssh",
    "jenkins", "gitlab", "jira", "confluence", "grafana",
    "kibana", "elastic", "mongo", "redis", "db", "database",
}

# Yaygın subdomain wordlist'i (500 adet — hızlı ama kapsamlı)
WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "api", "api2", "api3", "v1", "v2", "rest",
    "admin", "administrator", "panel", "dashboard", "manager",
    "dev", "develop", "development", "staging", "stage", "beta",
    "test", "testing", "uat", "qa", "sandbox",
    "shop", "store", "pay", "checkout", "billing", "invoice",
    "blog", "news", "media", "static", "assets", "cdn",
    "img", "images", "upload", "uploads", "files", "docs",
    "vpn", "remote", "citrix", "rdp", "ssh", "sftp",
    "git", "gitlab", "github", "bitbucket", "svn",
    "jenkins", "ci", "cd", "deploy", "build",
    "jira", "confluence", "wiki", "intranet", "internal",
    "monitor", "grafana", "kibana", "elastic", "prometheus",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "backup", "bak", "old", "archive", "legacy",
    "secure", "ssl", "auth", "login", "sso", "oauth",
    "support", "help", "helpdesk", "ticket", "crm",
    "erp", "hrm", "portal", "extranet",
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "smtp1", "smtp2",
    "app", "app1", "app2", "web", "web1", "web2",
    "mobile", "m", "wap", "pwa",
    "status", "health", "ping", "monitor",
    "chat", "slack", "teams", "meet",
    "download", "update", "patch",
    "cpanel", "whm", "plesk", "directadmin",
    "phpmyadmin", "adminer", "webmin",
    "proxy", "gateway", "lb", "load", "haproxy", "nginx",
    "cloud", "aws", "azure", "gcp",
    "s3", "storage", "blob", "bucket",
    "uat1", "uat2", "preprod", "pre-prod", "prod",
    "server", "srv", "server1", "server2",
    "host", "hosting", "vps", "vm",
    "office", "outlook", "exchange",
    "analytics", "stats", "metrics", "data",
    "search", "solr", "elasticsearch",
    "queue", "rabbit", "kafka", "celery",
    "socket", "ws", "websocket",
    "hook", "webhook", "callback",
    "partner", "partners", "affiliate",
    "ads", "ad", "track", "tracking", "pixel",
    "survey", "form", "forms",
]


def ensure_subdomain_table():
    with get_conn() as conn:
        conn.execute(SUBDOMAIN_TABLE_SQL)


def _check_subdomain(domain: str, sub: str) -> dict | None:
    """Tek bir subdomain'i kontrol eder. Varsa dict döner, yoksa None."""
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        is_sensitive = any(kw in sub.lower() for kw in SENSITIVE_KEYWORDS)
        return {
            "subdomain":    fqdn,
            "ip":           ip,
            "is_sensitive": is_sensitive,
        }
    except socket.gaierror:
        return None


def collect_subdomains(scan_id: int, domain: str, max_workers: int = 50) -> list:
    """
    Wordlist bazlı subdomain taraması.
    Paralel çalışır — max_workers ile eş zamanlı DNS sorgu sayısı ayarlanır.

    Döndürdüğü liste:
        [{"subdomain": str, "ip": str, "is_sensitive": bool}, ...]
    """
    ensure_subdomain_table()
    found = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_subdomain, domain, sub): sub
            for sub in WORDLIST
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                with get_conn() as conn:
                    conn.execute("""
                        INSERT INTO subdomain_results
                        (scan_id, subdomain, ip, is_sensitive)
                        VALUES (?, ?, ?, ?)
                    """, (
                        scan_id,
                        result["subdomain"],
                        result["ip"],
                        result["is_sensitive"],
                    ))

    # Hassas olanları başa al
    found.sort(key=lambda x: (not x["is_sensitive"], x["subdomain"]))
    return found