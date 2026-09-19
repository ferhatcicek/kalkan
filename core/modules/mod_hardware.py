import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, run_powershell, run_command


class HardwareIntegrityModule(BaseModule):
    id: str = "hardware"
    name: str = "Donanım, Önyükleme & Çekirdek Bütünlüğü"
    description: str = "UEFI Secure Boot, BitLocker, TPM 2.0, LSA RunAsPPL, HVCI ve VBS güvenlik denetimleri."
    category: str = "Sistem & Donanım Bütünlüğü"
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_secure_boot())
        checks.append(self._check_bitlocker())
        checks.append(self._check_tpm())
        checks.append(self._check_lsa_protection())
        checks.append(self._check_hvci_memory_integrity())
        checks.append(self._check_vbs())
        return checks

    def _check_secure_boot(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled"
        )
        is_enabled = (val == 1)

        if is_enabled:
            return CheckItem(
                id="HW-01",
                title="UEFI Secure Boot (Güvenli Önyükleme)",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Etkin (Aktif)",
                recommended_value="Etkin (1)",
                description="Sistem açılışında bootkit ve yetkisiz işletim sistemi/sürücü yüklemelerini donanım seviyesinde engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.1.1.1 / MITRE T1542"
            )
        else:
            return CheckItem(
                id="HW-01",
                title="UEFI Secure Boot (Güvenli Önyükleme)",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="Devre Dışı",
                recommended_value="Etkin (1)",
                description="Secure Boot kapalı! Rootkit/Bootkit zararlıları işletim sistemi başlamadan önce belleğe yerleşebilir.",
                remediation="Bilgisayarı yeniden başlatıp BIOS/UEFI ayarlarına girin ve 'Secure Boot' seçeneğini 'Enabled' yapın.",
                standard_ref="CIS 18.1.1.1 / MITRE T1542"
            )

    def _check_bitlocker(self) -> CheckItem:
        out = run_command(["manage-bde.exe", "-status", "C:"], timeout=4)
        is_protected = ("Protection On" in out or "Koruma Açık" in out or "Percentage Encrypted: 100" in out or "Yüzde 100" in out)

        if is_protected:
            return CheckItem(
                id="HW-02",
                title="BitLocker C: Disk Şifreleme",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Şifreli & Koruma Açık",
                recommended_value="Koruma Açık (Protection On)",
                description="Bilgisayar çalındığında veya diski söküldüğünde verilerin okunmasını engeller.",
                remediation="Herhangi bir işlem gerekmez, disk tam şifrelenmiş.",
                standard_ref="CIS 18.1.2.1"
            )
        else:
            return CheckItem(
                id="HW-02",
                title="BitLocker C: Disk Şifreleme",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="Koruma Kapalı (Şifresiz)",
                recommended_value="Koruma Açık (Protection On)",
                description="C: sistem sürücüsü şifrelenmemiş! Fiziksel erişimle diskinizdeki tüm verilere şifresiz ulaşılabilir.",
                remediation="Yönetici PowerShell ile BitLocker'ı açın:\nEnable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly",
                standard_ref="CIS 18.1.2.1"
            )

    def _check_tpm(self) -> CheckItem:
        ps_out = run_powershell(
            "(Get-Tpm).TpmPresent -and (Get-Tpm).TpmReady",
            timeout=3
        )
        is_ready = ("True" in ps_out)

        if is_ready:
            return CheckItem(
                id="HW-03",
                title="TPM 2.0 Donanım Güvenlik Yongası",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Mevcut ve Hazır (Ready)",
                recommended_value="Mevcut ve Hazır",
                description="Kriptografik anahtarların donanımsal olarak izole bir yongada saklanmasını sağlar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="Windows 11 Hardware Security"
            )
        else:
            return CheckItem(
                id="HW-03",
                title="TPM 2.0 Donanım Güvenlik Yongası",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value="Kullanılamıyor veya Devre Dışı",
                recommended_value="Mevcut ve Hazır",
                description="TPM yongası bulunamadı veya BIOS üzerinden etkinleştirilmemiş.",
                remediation="BIOS/UEFI menüsünden Intel PTT veya AMD fTPM özelliğini etkinleştirin.",
                standard_ref="Windows 11 Hardware Security"
            )

    def _check_lsa_protection(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL"
        )
        is_protected = (val in (1, 2))

        if is_protected:
            return CheckItem(
                id="HW-04",
                title="LSA Koruma Modu (RunAsPPL - LSASS Savunması)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value=f"Etkin (RunAsPPL={val})",
                recommended_value="Etkin (1 veya 2)",
                description="LSASS.exe sürecini PPL (Protected Process Light) korumasına alarak Mimikatz vb. parola çalma araçlarını engeller.",
                remediation="Herhangi bir işlem gerekmez, LSASS belleği koruma altında.",
                standard_ref="CIS 18.2.1 / MITRE T1003.001"
            )
        else:
            return CheckItem(
                id="HW-04",
                title="LSA Koruma Modu (RunAsPPL - LSASS Savunması)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="Devre Dışı",
                recommended_value="Etkin (1)",
                description="LSA koruması kapalı! Yerel yönetici yetkisi elde eden bir zararlı LSASS belleğindeki Windows parolalarını dökebilir.",
                remediation="Yönetici PowerShell ile etkinleştirin:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord",
                standard_ref="CIS 18.2.1 / MITRE T1003.001"
            )

    def _check_hvci_memory_integrity(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled"
        )
        is_enabled = (val == 1)

        if is_enabled:
            return CheckItem(
                id="HW-05",
                title="HVCI / Bellek Bütünlüğü (Core Isolation)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin (Aktif)",
                recommended_value="Etkin (1)",
                description="Windows çekirdeğinde (Kernel) imzasız veya zararlı kod çalıştırılmasını donanım seviyesinde engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.1.3 / MITRE T1562"
            )
        else:
            return CheckItem(
                id="HW-05",
                title="HVCI / Bellek Bütünlüğü (Core Isolation)",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value="Devre Dışı",
                recommended_value="Etkin (1)",
                description="Bellek bütünlüğü kapalı. Çekirdek düzeyinde (Ring 0) çalışan sürücü saldırılarına karşı risk mevcuttur.",
                remediation="Windows Güvenliği > Cihaz Güvenliği > Çekirdek Yalıtımı > Bellek Bütünlüğü seçeneğini açın.",
                standard_ref="CIS 18.1.3 / MITRE T1562"
            )

    def _check_vbs(self) -> CheckItem:
        ps_out = run_powershell(
            "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard).VirtualizationBasedSecurityStatus",
            timeout=3
        )
        is_running = ("2" in ps_out)

        if is_running:
            return CheckItem(
                id="HW-06",
                title="VBS (Sanallaştırma Tabanlı Güvenlik)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Çalışıyor (Running)",
                recommended_value="Çalışıyor (2)",
                description="Güvenli bellek bölgelerini işletim sisteminden izole eden donanım sanallaştırma altyapısı.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.1.4"
            )
        else:
            return CheckItem(
                id="HW-06",
                title="VBS (Sanallaştırma Tabanlı Güvenlik)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Çalışmıyor",
                recommended_value="Çalışıyor (2)",
                description="VBS aktif değil. Donanım sanallaştırma destekleniyorsa etkinleştirilmesi tavsiye edilir.",
                remediation="BIOS üzerinden sanallaştırmayı (Intel VT-x / AMD-V) açın ve Windows Özelliklerinden 'Hyper-V Platformunu' etkinleştirin.",
                standard_ref="CIS 18.1.4"
            )
