import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, run_command, run_powershell


class AttackSurfaceReductionModule(BaseModule):
    id: str = "asr"
    name: str = "Saldırı Yüzeyi Azaltma (ASR) & Zafiyetli Servisler"
    description: str = "Windows Script Host, PowerShell v2, AutoRun, Remote Registry ve Print Spooler denetimleri."
    category: str = "Sistem Sıkılaştırma"
    weight: int = 9
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_wsh())
        checks.append(self._check_powershell_v2())
        checks.append(self._check_autorun())
        checks.append(self._check_remote_registry())
        checks.append(self._check_print_spooler())
        checks.append(self._check_remote_assistance())
        return checks

    def _check_wsh(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Script Host\Settings",
            "Enabled"
        )
        is_disabled = (val == 0)

        if is_disabled:
            return CheckItem(
                id="ASR-01",
                title="Windows Script Host (WSH - .vbs/.js Çalıştırma)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Devre Dışı (Korumalı)",
                recommended_value="Devre Dışı (0)",
                description="Oltalama (Phishing) e-postalarıyla gelen VBScript ve JScript dosyalarının çift tıklanarak çalışmasını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="MITRE T1059.005"
            )
        else:
            return CheckItem(
                id="ASR-01",
                title="Windows Script Host (WSH - .vbs/.js Çalıştırma)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Etkin (Varsayılan Açık)",
                recommended_value="Devre Dışı (0)",
                description="WSH açık. Kullanıcılar zararlı .vbs, .js veya .vbe dosyalarına tıkladığında doğrudan kod çalıştırılabilir.",
                remediation="Yönetici PowerShell ile WSH'yi devre dışı bırakın:\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name 'Enabled' -Value 0 -Type DWord",
                standard_ref="MITRE T1059.005"
            )

    def _check_powershell_v2(self) -> CheckItem:
        out = run_powershell(
            "(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State",
            timeout=4
        )
        is_enabled = ("Enabled" in out)

        if not is_enabled:
            return CheckItem(
                id="ASR-02",
                title="PowerShell v2 Motoru (Downgrade Saldırı Vektörü)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Yüklü Değil / Devre Dışı (Güvenli)",
                recommended_value="Devre Dışı (Disabled)",
                description="Eski PowerShell v2 yüklü değil. Saldırganların modern AMSI (Antimalware) ve loglama mekanizmalarını atlatması engellenmiştir.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.8 / MITRE T1562"
            )
        else:
            return CheckItem(
                id="ASR-02",
                title="PowerShell v2 Motoru (Downgrade Saldırı Vektörü)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="ETKİN / YÜKLÜ (Güvensiz!)",
                recommended_value="Devre Dışı (Disabled)",
                description="PowerShell v2 aktif! Saldırganlar powershell.exe -version 2 ile AMSI korumasını ve komut loglamasını baypas edebilir.",
                remediation="Yönetici PowerShell ile kaldırın:\nDisable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
                standard_ref="CIS 18.9.8 / MITRE T1562"
            )

    def _check_autorun(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun"
        )
        # 255 (0xFF) = All drives disabled
        is_disabled = (val == 255 or val == 145)

        if is_disabled:
            return CheckItem(
                id="ASR-03",
                title="AutoRun / AutoPlay (Harici Medya Otomatik Çalıştırma)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Devre Dışı (Korumalı)",
                recommended_value="Devre Dışı (255)",
                description="USB bellek veya harici diskler takıldığında zararlı yazılımların otomatik çalışmasını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.8.2 / MITRE T1091"
            )
        else:
            return CheckItem(
                id="ASR-03",
                title="AutoRun / AutoPlay (Harici Medya Otomatik Çalıştırma)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Kısmi veya Etkin",
                recommended_value="Devre Dışı (255)",
                description="AutoRun açık. Takılan bir USB sürücüden otomatik olarak zararlı kod yürütülmesi riski mevcuttur.",
                remediation="Yönetici PowerShell ile kapatın:\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord",
                standard_ref="CIS 18.8.2 / MITRE T1091"
            )

    def _check_remote_registry(self) -> CheckItem:
        out = run_command(["sc.exe", "qc", "RemoteRegistry"], timeout=2)
        is_disabled = ("DISABLED" in out or "DEMAND_START" in out)

        if is_disabled or "FAILED 1060" in out:
            return CheckItem(
                id="ASR-04",
                title="Remote Registry (Uzak Kayıt Defteri) Servisi",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Devre Dışı / Manuel (Güvenli)",
                recommended_value="Devre Dışı (Disabled)",
                description="Ağ üzerinden Kayıt Defterinin uzaktan okunmasını veya değiştirilmesini engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 5.23"
            )
        else:
            return CheckItem(
                id="ASR-04",
                title="Remote Registry (Uzak Kayıt Defteri) Servisi",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Otomatik / Çalışıyor",
                recommended_value="Devre Dışı (Disabled)",
                description="Remote Registry servisi açık. Ağdaki yöneticiler veya saldırganlar kayıt defterinize uzaktan erişebilir.",
                remediation="Yönetici PowerShell ile servisi kapatın:\nSet-Service -Name RemoteRegistry -StartupType Disabled; Stop-Service RemoteRegistry",
                standard_ref="CIS 5.23"
            )

    def _check_print_spooler(self) -> CheckItem:
        out = run_command(["sc.exe", "query", "Spooler"], timeout=2)
        is_running = ("RUNNING" in out)

        if is_running:
            return CheckItem(
                id="ASR-05",
                title="Yazdırma Biriktiricisi (Print Spooler Servisi)",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Çalışıyor (Yazıcı Desteği Aktif)",
                recommended_value="Yazıcı Yoksa Devre Dışı",
                description="Yazıcı kullanmayan sistemlerde PrintNightmare zafiyet vektörünü engellemek için kapatılması önerilir.",
                remediation="Bilgisayarınızda yazıcı kullanmıyorsanız servisi kapatabilirsiniz:\nSet-Service -Name Spooler -StartupType Disabled; Stop-Service Spooler",
                standard_ref="CVE-2021-34527"
            )
        else:
            return CheckItem(
                id="ASR-05",
                title="Yazdırma Biriktiricisi (Print Spooler Servisi)",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Durdurulmuş / Devre Dışı (Sıkılaştırılmış)",
                recommended_value="Devre Dışı",
                description="Print Spooler kapalı olduğu için yazdırma tabanlı ayrıcalık yükseltme zafiyetleri engellenmiştir.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CVE-2021-34527"
            )

    def _check_remote_assistance(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
            "fAllowToGetHelp"
        )
        is_disabled = (val == 0)

        if is_disabled:
            return CheckItem(
                id="ASR-06",
                title="Windows Uzaktan Yardım (Remote Assistance)",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Devre Dışı (Korumalı)",
                recommended_value="Devre Dışı (0)",
                description="Uzaktan yardım davetiyelerinin oluşturulmasını engelleyerek yetkisiz ekran paylaşımını önler.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.8.3"
            )
        else:
            return CheckItem(
                id="ASR-06",
                title="Windows Uzaktan Yardım (Remote Assistance)",
                severity=Severity.LOW,
                status=Status.WARNING,
                current_value="Etkin (Açık)",
                recommended_value="Devre Dışı (0)",
                description="Uzaktan yardım aktif. Sosyal mühendislik saldırılarıyla uzaktan oturum açılması riski mevcuttur.",
                remediation="Yönetici PowerShell ile kapatın:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0 -Type DWord",
                standard_ref="CIS 18.8.3"
            )
