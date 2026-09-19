import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE_DIR / "history.json"


class HistoryManager:
    """
    Geçmiş güvenlik taramalarını kaydeden, skor trendini ve zaman içindeki
    iyileşmeyi takip eden yöneticidir.
    """
    def __init__(self, file_path: Path = HISTORY_FILE):
        self.file_path = file_path

    def save_scan(self, report_dict: Dict[str, Any]) -> None:
        """Yeni bir tarama özetini geçmişe ekler."""
        history = self.get_history()

        summary = {
            "scan_id": report_dict.get("scan_id"),
            "timestamp": report_dict.get("timestamp"),
            "hostname": report_dict.get("hostname"),
            "total_score": report_dict.get("total_score"),
            "total_checks": report_dict.get("total_checks"),
            "passed_count": report_dict.get("passed_count"),
            "critical_count": report_dict.get("critical_count"),
            "high_count": report_dict.get("high_count"),
            "medium_count": report_dict.get("medium_count"),
            "low_count": report_dict.get("low_count"),
            "duration_seconds": report_dict.get("duration_seconds")
        }

        # En son 50 taramayı sakla
        history.insert(0, summary)
        history = history[:50]

        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Geçmiş kaydedilemedi: {e}")

    def get_history(self) -> List[Dict[str, Any]]:
        """Geçmiş taramaların listesini döner."""
        if not self.file_path.exists():
            return []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def get_trend(self) -> Dict[str, Any]:
        """En son iki tarama arasındaki puan farkını ve trendi döner."""
        history = self.get_history()
        if len(history) < 2:
            return {"has_trend": False, "diff": 0, "previous_score": None}

        current = history[0].get("total_score", 0)
        previous = history[1].get("total_score", 0)
        diff = current - previous

        return {
            "has_trend": True,
            "diff": diff,
            "current_score": current,
            "previous_score": previous,
            "direction": "up" if diff > 0 else ("down" if diff < 0 else "neutral")
        }
