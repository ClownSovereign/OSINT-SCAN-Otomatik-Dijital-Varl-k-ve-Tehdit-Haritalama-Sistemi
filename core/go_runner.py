import subprocess
import sys
import time
import os
import requests
from pathlib import Path

GO_SCANNER_DIR = Path(__file__).parent.parent / "scanner"
GO_SCANNER_URL = "http://localhost:8765/scan"
GO_HEALTH_URL  = "http://localhost:8765/scan"

_go_process = None


def _is_running() -> bool:
    """Go servisinin ayakta olup olmadığını kontrol eder."""
    try:
        requests.post(GO_HEALTH_URL, json={"host": "__healthcheck__"}, timeout=2)
        return True
    except requests.exceptions.ConnectionError:
        return False
    except Exception:
        return True 

def _find_go_binary() -> str | None:
    """Sistemde 'go' komutunun yerini bulur."""
    import shutil
    return shutil.which("go")


def ensure_go_scanner() -> dict:
    """
    Go tarayıcısının çalıştığını garantiler.
    Çalışmıyorsa başlatır, başlatılamazsa açıklayıcı hata döner.

    Dönüş:
        {"ok": True}  — servis hazır
        {"ok": False, "error": "..."}  — başlatılamadı
    """
    global _go_process

    if _is_running():
        return {"ok": True}

    go_bin = _find_go_binary()
    if not go_bin:
        return {
            "ok": False,
            "error": (
                "Go kurulu değil. Kurmak için: https://go.dev/dl/\n"
                "Kurulumdan sonra terminali yeniden başlatın."
            )
        }

    if not GO_SCANNER_DIR.exists():
        return {
            "ok": False,
            "error": f"scanner/ klasörü bulunamadı: {GO_SCANNER_DIR}"
        }

    try:
        _go_process = subprocess.Popen(
            [go_bin, "run", "main.go"],
            cwd=str(GO_SCANNER_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        return {"ok": False, "error": f"Go servisi başlatılamadı: {e}"}

    for _ in range(20):
        time.sleep(0.5)
        if _is_running():
            return {"ok": True}

    return {
        "ok": False,
        "error": (
            "Go servisi başlatıldı ama yanıt vermiyor.\n"
            "Manuel başlatmak için: cd scanner && go run main.go"
        )
    }


def stop_go_scanner():
    """Uygulama kapanırken Go servisini durdurur."""
    global _go_process
    if _go_process and _go_process.poll() is None:
        _go_process.terminate()
        _go_process = None
