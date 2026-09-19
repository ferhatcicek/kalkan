import json
import os
from pathlib import Path
from typing import Dict, Any

from core.base import ScanReport

BASE_DIR = Path(__file__).resolve().parent.parent
LOCALES_DIR = BASE_DIR / "locales"

# Bellekte çeviri dosyasını cache'leyelim
_translations = None

def load_translations() -> Dict[str, Any]:
    global _translations
    if _translations is not None:
        return _translations
        
    en_file = LOCALES_DIR / "en.json"
    if en_file.exists():
        try:
            with open(en_file, "r", encoding="utf-8") as f:
                _translations = json.load(f)
        except Exception:
            _translations = {}
    else:
        _translations = {}
        
    return _translations

def translate_report(report: ScanReport, lang: str = "tr") -> ScanReport:
    """Rapor içeriğini belirtilen dile çevirir (varsayılan tr olduğu için işlem yapmaz)."""
    if lang == "tr":
        return report
        
    trans = load_translations()
    if not trans:
        return report

    # Rapor nesnesini kopyalamadan in-place değiştirebiliriz ya da alanlarını güncelleyebiliriz
    for cat in report.categories:
        # Modül adını çevir
        mod_key = f"MOD_{cat.module_id.upper()}"
        if mod_key in trans:
            cat.module_name = trans[mod_key].get("name", cat.module_name)
            
        for check in cat.checks:
            c_key = check.id.upper()
            if c_key in trans:
                t_check = trans[c_key]
                check.title = t_check.get("title", check.title)
                check.description = t_check.get("description", check.description)
                check.remediation = t_check.get("remediation", check.remediation)
                check.recommended_value = t_check.get("recommended_value", check.recommended_value)
                
            # Ortak değerleri (current_value vs) çevir
            common = trans.get("common", {})
            for tr_k, tr_v in common.items():
                if tr_k in check.current_value:
                    check.current_value = check.current_value.replace(tr_k, tr_v)
                if tr_k in check.recommended_value:
                    check.recommended_value = check.recommended_value.replace(tr_k, tr_v)

    return report
