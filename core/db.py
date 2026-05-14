import sqlite3
from contextlib import contextmanager

DB_PATH = "osint_scan.db"


def init_db():
    with _get_raw_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT NOT NULL,
            scan_type   TEXT NOT NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS whois_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER REFERENCES scans(id),
            registrar   TEXT,
            admin_email TEXT,
            country     TEXT,
            is_private  BOOLEAN DEFAULT FALSE,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS port_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER REFERENCES scans(id),
            ip          TEXT,
            port        INTEGER,
            service     TEXT,
            is_critical BOOLEAN DEFAULT FALSE
        );

        CREATE TABLE IF NOT EXISTS leak_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER REFERENCES scans(id),
            email        TEXT,
            breach_name  TEXT,
            breach_date  TEXT,
            data_classes TEXT
        );

        CREATE TABLE IF NOT EXISTS social_links (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id   INTEGER REFERENCES scans(id),
            platform  TEXT,
            username  TEXT,
            url       TEXT,
            found     BOOLEAN DEFAULT FALSE
        );

        CREATE TABLE IF NOT EXISTS risk_scores (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER REFERENCES scans(id),
            score_w     INTEGER DEFAULT 0,
            score_s     INTEGER DEFAULT 0,
            score_p     INTEGER DEFAULT 0,
            score_l     INTEGER DEFAULT 0,
            total       INTEGER DEFAULT 0,
            risk_level  TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)


def _get_raw_conn() -> sqlite3.Connection:
    """
    Düşük seviye bağlantı — sadece init_db() içinde kullanılır.
    sqlite3.Connection kendi context manager'ını sağlar:
    __exit__ başarılı → commit, hata → rollback.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  
    return conn


@contextmanager
def get_conn():
    """
    Güvenli bağlantı context manager'ı.

    Kullanım:
        with get_conn() as conn:
            conn.execute("INSERT ...")
            # bloğun sonunda otomatik commit yapılır
            # hata olursa otomatik rollback yapılır

    sqlite3.Connection.__exit__ davranışı:
      - İstisna YOK → commit()
      - İstisna VAR → rollback()
    Ancak bu davranış sadece 'with conn:' ile aktif olur,
    ham conn döndürmek bunu sağlamaz. Bu wrapper her iki
    durumu da garantiler.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
