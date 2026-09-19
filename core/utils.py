import winreg
import subprocess
import ctypes
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict


def is_admin_user() -> bool:
    """Kullanıcının yönetici (Administrator) yetkilerine sahip olup olmadığını denetler."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def read_registry_value(hive: int, subkey: str, value_name: str) -> Optional[Any]:
    """
    Windows Kayıt Defterinden (Registry) güvenli bir şekilde değer okur.
    Bulunamazsa veya hata olursa None döner.
    """
    access_flags = [winreg.KEY_READ | winreg.KEY_WOW64_64KEY, winreg.KEY_READ]
    for access in access_flags:
        try:
            with winreg.OpenKey(hive, subkey, 0, access) as key:
                val, val_type = winreg.QueryValueEx(key, value_name)
                return val
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return None


def registry_key_exists(hive: int, subkey: str) -> bool:
    """Belirtilen registry anahtarının mevcut olup olmadığını denetler."""
    access_flags = [winreg.KEY_READ | winreg.KEY_WOW64_64KEY, winreg.KEY_READ]
    for access in access_flags:
        try:
            with winreg.OpenKey(hive, subkey, 0, access) as key:
                return True
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return False


def decode_output(raw_bytes: bytes) -> str:
    """
    Windows sistem komut çıktısını (UTF-8, CP1254, CP857 veya Latin1)
    karakter hatası fırlatmadan güvenle string'e dönüştürür.
    """
    if not raw_bytes:
        return ""
    for enc in ("utf-8", "cp1254", "cp857", "latin1"):
        try:
            return raw_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def run_powershell(script: str, timeout: int = 5) -> str:
    """
    Hızlı ve güvenli bir şekilde PowerShell komutunu çalıştırır ve çıktısını döner.
    Unicode hatalarını engellemek için raw byte okur.
    """
    try:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script
        ]
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        return decode_output(res.stdout).strip()
    except Exception:
        return ""


def run_command(args: list, timeout: int = 5) -> str:
    """
    Sistem komutunu (cmd, netsh, sc, manage-bde vb.) çalıştırır.
    """
    try:
        res = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        return decode_output(res.stdout).strip()
    except Exception:
        return ""


_UPGRADES_CACHE = {"timestamp": 0.0, "data": []}

def get_pending_software_upgrades(force_refresh: bool = False) -> list:
    """
    Windows Package Manager (winget) kullanarak sistemdeki güncelleme bekleyen
    3. parti yazılımları listeler. Tarama performansı için 60 saniyelik dahili önbellek kullanır.
    """
    import time
    global _UPGRADES_CACHE

    now = time.time()
    if not force_refresh and (now - _UPGRADES_CACHE["timestamp"] < 60) and _UPGRADES_CACHE["data"]:
        return _UPGRADES_CACHE["data"]

    try:
        res = subprocess.run(
            ["winget", "upgrade"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        output = decode_output(res.stdout)
        lines = output.splitlines()

        if len(lines) < 2:
            return []

        # Sütun başlıklarını bul
        hdr = ""
        sep_idx = -1
        for idx, l in enumerate(lines[:6]):
            if "------" in l and idx > 0:
                hdr = lines[idx - 1]
                sep_idx = idx
                break

        if not hdr or sep_idx == -1:
            return []

        p_name = hdr.find("Name")
        p_id = hdr.find("Id")
        p_ver = hdr.find("Version")
        p_avail = hdr.find("Available")
        p_src = hdr.find("Source")

        if p_name == -1 or p_id == -1 or p_ver == -1 or p_avail == -1:
            return []

        results = []
        for line in lines[sep_idx + 1:]:
            line_str = line.strip()
            if not line_str or "upgrade" in line_str.lower() and ("available" in line_str.lower() or "mevcut" in line_str.lower()):
                continue

            name = line[p_name:p_id].strip()
            pkg_id = line[p_id:p_ver].strip()
            ver = line[p_ver:p_avail].strip()
            avail = line[p_avail:p_src].strip() if p_src != -1 else line[p_avail:].strip()
            src = line[p_src:].strip() if p_src != -1 else ""

            if name and pkg_id and ver and avail:
                results.append({
                    "name": name,
                    "id": pkg_id,
                    "installed": ver,
                    "available": avail,
                    "source": src
                })

        _UPGRADES_CACHE["timestamp"] = now
        _UPGRADES_CACHE["data"] = results
        return results
    except Exception:
        return []


_WU_CACHE = {"timestamp": 0.0, "data": []}


def get_pending_windows_updates(timeout_seconds: int = 15) -> List[Dict[str, Any]]:
    """
    Windows Update Agent (WUA) COM API üzerinden sistemde bekleyen,
    henüz yüklenmemiş tüm Windows, Microsoft Defender Güvenlik Zekası ve platform güncellemelerini listeler.
    """
    now = time.time()
    if now - _WU_CACHE["timestamp"] < 60.0:
        return _WU_CACHE["data"]

    def _query_wua():
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        updates = []
        try:
            session = win32com.client.Dispatch("Microsoft.Update.Session")
            searcher = session.CreateUpdateSearcher()
            searcher.ServerSelection = 0  # Varsayılan / yerel arama
            searcher.IncludePotentiallySupersededUpdates = False
            res = searcher.Search("IsInstalled=0 and IsHidden=0")
            for i in range(res.Updates.Count):
                u = res.Updates.Item(i)
                title = u.Title or "Bilinmeyen Güncelleme"
                kbs = [str(u.KBArticleIDs.Item(k)) for k in range(u.KBArticleIDs.Count)]
                kb_str = f"KB{kbs[0]}" if kbs else ""
                cats = [str(u.Categories.Item(k).Name) for k in range(u.Categories.Count)]

                is_defender = (
                    "defender" in title.lower()
                    or "security intelligence" in title.lower()
                    or "antimalware" in title.lower()
                    or "2267602" in kb_str
                    or "4052623" in kb_str
                    or any("definition" in c.lower() or "defender" in c.lower() for c in cats)
                )

                is_security = (
                    is_defender
                    or any("security" in c.lower() or "critical" in c.lower() for c in cats)
                    or (u.MsrcSeverity and u.MsrcSeverity in ("Critical", "Important"))
                )

                sev = u.MsrcSeverity or ("Critical" if is_defender else "Important" if is_security else "Standard")

                updates.append({
                    "title": title,
                    "kb": kb_str,
                    "categories": cats,
                    "severity": sev,
                    "is_defender": is_defender,
                    "is_security": is_security
                })
                del u
            del res
            del searcher
            del session
            return updates
        except Exception:
            return []
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_query_wua)
            updates = fut.result(timeout=timeout_seconds)
            _WU_CACHE["timestamp"] = now
            _WU_CACHE["data"] = updates
            return updates
    except Exception:
        return _WU_CACHE.get("data", [])


def get_defender_detailed_status() -> Dict[str, Any]:
    """
    Microsoft Defender'ın gerçek zamanlı koruma, virüs tanım sürümü (Security Intelligence),
    motor sürümü, son güncelleme tarihi ve güncellik durumunu WMI/CIM üzerinden okur.
    """
    try:
        import win32com.client
        import pythoncom
        pythoncom.CoInitialize()
        res_data = None
        try:
            wmi = win32com.client.GetObject(r"winmgmts:\\.\root\Microsoft\Windows\Defender")
            items = wmi.ExecQuery("SELECT * FROM MSFT_MpComputerStatus")
            for item in items:
                sig_ver = str(getattr(item, "AntivirusSignatureVersion", "") or "")
                eng_ver = str(getattr(item, "AMEngineVersion", "") or "")
                prod_ver = str(getattr(item, "AMProductVersion", "") or "")
                nis_ver = str(getattr(item, "NISSignatureVersion", "") or "")
                out_of_date = bool(getattr(item, "DefenderSignaturesOutOfDate", False))
                sig_age_days = int(getattr(item, "AntivirusSignatureAge", 0) or 0)
                is_tamper_protected = bool(getattr(item, "IsTamperProtected", False))

                raw_updated = str(getattr(item, "AntivirusSignatureLastUpdated", "") or "")
                formatted_updated = ""
                hours_ago = 0.0
                if len(raw_updated) >= 14:
                    try:
                        year = int(raw_updated[0:4])
                        month = int(raw_updated[4:6])
                        day = int(raw_updated[6:8])
                        hour = int(raw_updated[8:10])
                        minute = int(raw_updated[10:12])
                        second = int(raw_updated[12:14])
                        dt_utc = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
                        dt_now = datetime.now(timezone.utc)
                        hours_ago = max(0.0, (dt_now - dt_utc).total_seconds() / 3600.0)
                        formatted_updated = f"{day:02d}.{month:02d}.{year} {hour:02d}:{minute:02d}"
                    except Exception:
                        formatted_updated = raw_updated

                res_data = {
                    "available": True,
                    "signature_version": sig_ver,
                    "engine_version": eng_ver,
                    "product_version": prod_ver,
                    "nis_version": nis_ver,
                    "out_of_date": out_of_date,
                    "days_old": sig_age_days,
                    "hours_old": round(hours_ago, 1),
                    "last_updated": formatted_updated,
                    "is_tamper_protected": is_tamper_protected
                }
                del item
                break
            del items
            del wmi
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
        if res_data:
            return res_data
    except Exception:
        pass

    # PowerShell fallback
    try:
        ps_script = "(Get-MpComputerStatus | Select-Object AntivirusSignatureVersion,AMEngineVersion,AMProductVersion,DefenderSignaturesOutOfDate,AntivirusSignatureAge,IsTamperProtected) | ConvertTo-Json -Compress"
        out = run_powershell(ps_script, timeout=4)
        if out and "{" in out:
            import json
            d = json.loads(out)
            return {
                "available": True,
                "signature_version": str(d.get("AntivirusSignatureVersion", "")),
                "engine_version": str(d.get("AMEngineVersion", "")),
                "product_version": str(d.get("AMProductVersion", "")),
                "nis_version": "",
                "out_of_date": bool(d.get("DefenderSignaturesOutOfDate", False)),
                "days_old": int(d.get("AntivirusSignatureAge", 0) or 0),
                "hours_old": 0.0,
                "last_updated": "",
                "is_tamper_protected": bool(d.get("IsTamperProtected", False))
            }
    except Exception:
        pass

    return {
        "available": False,
        "signature_version": "",
        "engine_version": "",
        "product_version": "",
        "nis_version": "",
        "out_of_date": False,
        "days_old": 0,
        "hours_old": 0.0,
        "last_updated": "",
        "is_tamper_protected": False
    }
