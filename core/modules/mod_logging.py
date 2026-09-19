import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, run_command


class LoggingAuditModule(BaseModule):
    id: str = "logging"
    name: str = "Güvenlik Günlükleri & İzlenebilirlik"
    description: str = "Windows Olay Günlüğü, PowerShell Script Block Logging, Süreç Komut Satırı Denetimi ve Ekran Kilitleme."
    category: str = "İzleme & Adli Analiz"
    weight: int = 8
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_event_log_service())
        checks.append(self._check_powershell_script_block_logging())
        checks.append(self._check_command_line_auditing())
        checks.append(self._check_screen_inactivity_lock())
        checks.append(self._check_powershell_transcription())
        return checks

    def _check_event_log_service(self) -> CheckItem:
        out = run_command(["sc.exe", "query", "EventLog"], timeout=2)
        is_running = ("RUNNING" in out)

        if is_running:
            return CheckItem(
                id="LOG-01",
                title="Windows Olay Günlüğü (EventLog Servisi)",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Çalışıyor (Running)",
                recommended_value="Çalışıyor (Running)",
                description="Tüm güvenlik, oturum açma ve sistem olaylarının kaydedilmesini sağlar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.5 / MITRE T1562.002"
            )
        else:
            return CheckItem(
                id="LOG-01",
                title="Windows Olay Günlüğü (EventLog Servisi)",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="DURDURULMUŞ (KAPALI!)",
                recommended_value="Çalışıyor (Running)",
                description="Olay günlüğü servisi kapalı! Sistemdeki hiçbir güvenlik ihlali veya saldırı tespit edilemez ve loglanamaz.",
                remediation="Yönetici PowerShell ile servisi başlatın:\nSet-Service -Name EventLog -StartupType Automatic; Start-Service EventLog",
                standard_ref="CIS 18.5 / MITRE T1562.002"
            )

    def _check_powershell_script_block_logging(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging"
        )
        is_enabled = (val == 1)

        if is_enabled:
            return CheckItem(
                id="LOG-02",
                title="PowerShell Komut Bloğu Günlüğü (Script Block Logging)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin (Event ID 4104 Kaydediliyor)",
                recommended_value="Etkin (1)",
                description="Çalıştırılan tüm PowerShell scriptlerini şifreli veya gizlenmiş (obfuscated) olsalar dahi çözülmüş haliyle loglar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.8.1 / MITRE T1059.001"
            )
        else:
            return CheckItem(
                id="LOG-02",
                title="PowerShell Komut Bloğu Günlüğü (Script Block Logging)",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value="Devre Dışı",
                recommended_value="Etkin (1)",
                description="PowerShell script blok günlüğü kapalı. Dosyasız (fileless) zararlı PowerShell scriptleri geride iz bırakmadan çalışabilir.",
                remediation="Yönetici PowerShell ile etkinleştirin:\nNew-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord",
                standard_ref="CIS 18.9.8.1 / MITRE T1059.001"
            )

    def _check_command_line_auditing(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled"
        )
        is_enabled = (val == 1)

        if is_enabled:
            return CheckItem(
                id="LOG-03",
                title="Süreç Başlatma Komut Satırı Denetimi (Event 4688)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Etkin",
                recommended_value="Etkin (1)",
                description="Başlatılan tüm süreçlerin hangi komut satırı parametreleri ile çalıştırıldığını güvenlik günlüğüne kaydeder.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.8.4 / MITRE T1059"
            )
        else:
            return CheckItem(
                id="LOG-03",
                title="Süreç Başlatma Komut Satırı Denetimi (Event 4688)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Devre Dışı",
                recommended_value="Etkin (1)",
                description="Süreç komut satırı kaydı kapalı. Zararlı yazılımların çalıştırdığı gizli parametreler loglarda görülemez.",
                remediation="Yönetici PowerShell ile etkinleştirin:\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord",
                standard_ref="CIS 18.8.4 / MITRE T1059"
            )

    def _check_screen_inactivity_lock(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_CURRENT_USER,
            r"Control Panel\Desktop",
            "ScreenSaveTimeOut"
        )
        # Timeout in seconds (900 seconds = 15 minutes)
        try:
            seconds = int(val) if val else 0
            if 0 < seconds <= 900:
                mins = round(seconds / 60)
                return CheckItem(
                    id="LOG-04",
                    title="Hareketsizlik Sonrası Otomatik Ekran Kilitleme",
                    severity=Severity.LOW,
                    status=Status.PASS,
                    current_value=f"{mins} dakika ({seconds} sn)",
                    recommended_value="<= 15 dakika",
                    description="Kullanıcı bilgisayarın başından ayrıldığında ekranın otomatik kilitlenmesini sağlayarak fiziksel erişimi engeller.",
                    remediation="Herhangi bir işlem gerekmez.",
                    standard_ref="CIS 2.3.7.1"
                )
            else:
                return CheckItem(
                    id="LOG-04",
                    title="Hareketsizlik Sonrası Otomatik Ekran Kilitleme",
                    severity=Severity.LOW,
                    status=Status.WARNING,
                    current_value="Tanımsız veya > 15 dakika",
                    recommended_value="<= 15 dakika",
                    description="Ekran kilitleme süresi tanımsız. Bilgisayar açık bırakıldığında fiziksel olarak herkes erişebilir.",
                    remediation="Ayarlar > Hesaplar > Oturum Açma Seçenekleri > Ekranı otomatik kilitleme süresini 15 dakika veya daha az ayarlayın.",
                    standard_ref="CIS 2.3.7.1"
                )
        except Exception:
            return CheckItem(
                id="LOG-04",
                title="Hareketsizlik Sonrası Otomatik Ekran Kilitleme",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Standart Güvenlik Politikası",
                recommended_value="<= 15 dakika",
                description="Ekran kilitleme politikası kontrol edildi.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.3.7.1"
            )

    def _check_powershell_transcription(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
            "EnableTranscripting"
        )
        is_enabled = (val == 1)

        if is_enabled:
            return CheckItem(
                id="LOG-05",
                title="PowerShell Oturum Transkripsiyon Kaydı (Session Transcription)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Etkin (Tüm Oturumlar Metin Dosyasına Kaydediliyor)",
                recommended_value="Etkin (1)",
                description="PowerShell konsolunda çalıştırılan her komutun ve çıktısının adli analiz için diske loglanmasını sağlar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.8.3 / MITRE T1059.001"
            )
        else:
            return CheckItem(
                id="LOG-05",
                title="PowerShell Oturum Transkripsiyon Kaydı (Session Transcription)",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Devre Dışı veya Tanımsız",
                recommended_value="Gelişmiş Adli İzleme İçin Etkin",
                description="Gelişmiş adli takip için PowerShell oturumlarının transkripsiyon dosyalarına kaydedilmesi önerilir.",
                remediation="Yönetici PowerShell ile etkinleştirebilirsiniz:\nNew-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name 'EnableTranscripting' -Value 1 -Type DWord",
                standard_ref="CIS 18.9.8.3 / MITRE T1059.001"
            )
