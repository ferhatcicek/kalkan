import winreg
import os
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import run_powershell


class PersistenceServicesModule(BaseModule):
    id: str = "persistence"
    name: str = "Kalıcılık, Başlangıç & Servis Zafiyetleri"
    description: str = "Tırnaksız Servis Yolları (Unquoted Service Paths) ve başlangıç (Run/RunOnce) analizi."
    category: str = "Ayrıcalık Yükseltme & Kalıcılık"
    weight: int = 8
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_unquoted_service_paths())
        checks.append(self._check_startup_run_keys())
        return checks

    def _check_unquoted_service_paths(self) -> CheckItem:
        # PowerShell ile boşluk içeren ve tırnak içinde olmayan servis binary yollarını bul
        ps_cmd = (
            "Get-CimInstance -ClassName Win32_Service | "
            "Where-Object { $_.PathName -and $_.PathName -notmatch '^\"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^C:\\\\Windows\\\\' } | "
            "Select-Object -ExpandProperty Name"
        )
        out = run_powershell(ps_cmd, timeout=4)
        vulnerable_services = [s.strip() for s in out.splitlines() if s.strip()]

        if not vulnerable_services:
            return CheckItem(
                id="PER-01",
                title="Tırnaksız Servis Yolları (Unquoted Service Paths - CWE-428)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Zafiyetli servis bulunamadı (Temiz)",
                recommended_value="Tüm Servis Yolları Tırnak İçinde Olmalı",
                description="Yolunda boşluk bulunan servislerin tırnaksız olması durumunda saldırganlar araya zararlı .exe yerleştirerek SYSTEM yetkisi elde edebilir.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CWE-428 / MITRE T1574.009"
            )
        else:
            return CheckItem(
                id="PER-01",
                title="Tırnaksız Servis Yolları (Unquoted Service Paths - CWE-428)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value=f"Zafiyetli Servisler Tespit Edildi: {', '.join(vulnerable_services[:4])}",
                recommended_value="Tüm Servis Yolları Tırnak İçinde Olmalı",
                description="Bu servislerin çalışma yollarında boşluk karakteri var ancak çift tırnak içine alınmamış! Yerel kullanıcılar bu yola dosya atarak yönetici haklarına yükselebilir.",
                remediation=f"Yönetici CMD ile servisin yolunu tırnak içine alın:\nsc config \"{vulnerable_services[0]}\" binPath= \"\\\"C:\\Program Files\\...\\app.exe\\\"\"",
                standard_ref="CWE-428 / MITRE T1574.009"
            )

    def _check_startup_run_keys(self) -> CheckItem:
        suspicious_entries = []
        run_paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ]

        for hive, subkey in run_paths:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        name, val, _ = winreg.EnumValue(key, i)
                        val_lower = str(val).lower()
                        # Temp, AppData/Local/Temp veya bat/vbs uzantıları şüpheli sayılır
                        if "temp" in val_lower or ".vbs" in val_lower or ".bat" in val_lower or "powershell" in val_lower:
                            suspicious_entries.append(f"{name} -> {val}")
            except Exception:
                continue

        if not suspicious_entries:
            return CheckItem(
                id="PER-02",
                title="Başlangıç (Run/RunOnce) Otomatik Çalıştırma Kayıtları",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Şüpheli başlangıç girdisi bulunamadı (Temiz)",
                recommended_value="Güvenilir Program Yolları",
                description="Windows açılışında otomatik çalışan kayıt defteri girdilerini analiz eder; Temp veya şüpheli dizinlerden çalışan zararlıları arar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="MITRE T1547.001"
            )
        else:
            return CheckItem(
                id="PER-02",
                title="Başlangıç (Run/RunOnce) Otomatik Çalıştırma Kayıtları",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value=f"Şüpheli Başlangıç Girdisi: {', '.join(suspicious_entries)}",
                recommended_value="Güvenilir Program Yolları",
                description="Geçici klasörlerden veya script olarak otomatik başlayan girdiler tespit edildi. Kalıcılık sağlayan bir zararlı olabilir.",
                remediation="Görev Yöneticisi > Başlangıç Uygulamaları sekmesinden veya Kayıt Defterinden şüpheli girdiyi kaldırın.",
                standard_ref="MITRE T1547.001"
            )
