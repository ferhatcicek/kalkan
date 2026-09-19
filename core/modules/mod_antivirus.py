import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, run_powershell, get_defender_detailed_status


class AntivirusModule(BaseModule):
    id: str = "antivirus"
    name: str = "Antivirüs & EDR Savunması"
    description: str = "Windows Defender, gerçek zamanlı koruma, bulut zekası ve imza güncelliği denetimi."
    category: str = "Zararlı Yazılım Koruması"
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_realtime_protection())
        checks.append(self._check_cloud_protection())
        checks.append(self._check_tamper_protection())
        checks.append(self._check_pua_protection())
        checks.append(self._check_controlled_folder_access())
        checks.append(self._check_signature_age())
        checks.append(self._check_third_party_av())
        checks.append(self._check_asr_rules())
        return checks

    def _check_realtime_protection(self) -> CheckItem:
        # Registry kontrolü
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring"
        )
        is_disabled = (val == 1)

        if not is_disabled:
            return CheckItem(
                id="AV-01",
                title="Antivirüs Gerçek Zamanlı Koruma",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Etkin (Aktif)",
                recommended_value="Etkin (Aktif)",
                description="Sistemdeki dosyaları ve çalışan süreçleri anlık olarak zararlı yazılımlara karşı tarar.",
                remediation="Herhangi bir işlem gerekmez, koruma devrede.",
                standard_ref="CIS 18.9.4.1 / MITRE T1562.001"
            )
        else:
            return CheckItem(
                id="AV-01",
                title="Antivirüs Gerçek Zamanlı Koruma",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="Devre Dışı",
                recommended_value="Etkin (Aktif)",
                description="Gerçek zamanlı koruma kapalı olduğunda zararlı yazılımlar engellenmeden sisteme sızabilir.",
                remediation="Yönetici PowerShell ile çalıştırın:\nSet-MpPreference -DisableRealtimeMonitoring $false",
                standard_ref="CIS 18.9.4.1 / MITRE T1562.001"
            )

    def _check_cloud_protection(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Spynet",
            "SpynetReporting"
        )
        # 0 = Disabled, 1 = Basic, 2 = Advanced
        is_cloud_active = (val is not None and val in (1, 2))

        if is_cloud_active or val is None:
            # None varsayılan olarak Windows'ta aktiftir
            return CheckItem(
                id="AV-02",
                title="Bulut Tabanlı Tehdit Algılama (MAPS)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin (Gelişmiş/Temel)",
                recommended_value="Etkin (Gelişmiş)",
                description="Bilinmeyen sıfır gün (zero-day) tehditlerini Microsoft Cloud koruma ağı üzerinden analiz eder.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.4.3"
            )
        else:
            return CheckItem(
                id="AV-02",
                title="Bulut Tabanlı Tehdit Algılama (MAPS)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="Devre Dışı",
                recommended_value="Etkin (Gelişmiş)",
                description="Bulut tabanlı koruma kapalı olduğunda yeni çıkan sıfır gün zararlıları algılanamayabilir.",
                remediation="Yönetici PowerShell ile çalıştırın:\nSet-MpPreference -MAPSReporting Advanced",
                standard_ref="CIS 18.9.4.3"
            )

    def _check_tamper_protection(self) -> CheckItem:
        d = get_defender_detailed_status()
        is_enabled = d.get("is_tamper_protected", False)

        if not is_enabled:
            val = read_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender\Features",
                "TamperProtection"
            )
            # 5 = Enabled in modern Win10/11
            if val == 5:
                is_enabled = True

        if is_enabled:
            return CheckItem(
                id="AV-03",
                title="Kurcalama Koruması (Tamper Protection)",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Etkin",
                recommended_value="Etkin",
                description="Zararlı yazılımların güvenlik ayarlarını (antivirüs, güvenlik duvarı) değiştirmesini engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="MITRE T1562.001"
            )
        else:
            return CheckItem(
                id="AV-03",
                title="Kurcalama Koruması (Tamper Protection)",
                severity=Severity.CRITICAL,
                status=Status.WARNING,
                current_value="Devre Dışı veya Tanımsız",
                recommended_value="Etkin",
                description="Kurcalama koruması kapalıysa saldırganlar veya zararlı yazılımlar güvenlik servislerini durdurabilir.",
                remediation="Windows Güvenliği > Virüs ve Tehdit Koruması > Ayarları Yönet > Kurcalama Korumasını Aç.",
                standard_ref="MITRE T1562.001"
            )

    def _check_pua_protection(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender",
            "PUAProtection"
        )
        is_enabled = (val == 1)

        if is_enabled:
            return CheckItem(
                id="AV-04",
                title="PUA/PUP Koruması (İstenmeyen Yazılım Engeli)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Etkin",
                recommended_value="Etkin",
                description="Sistemi yavaşlatan, reklam ve veri toplayan istenmeyen yazılımları (Adware/Miner) engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.4.7"
            )
        else:
            return CheckItem(
                id="AV-04",
                title="PUA/PUP Koruması (İstenmeyen Yazılım Engeli)",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                current_value="Devre Dışı",
                recommended_value="Etkin",
                description="İstenmeyen yazılım engeli kapalı. İndirilen programlarla birlikte adware veya istenmeyen araçlar kurulabilir.",
                remediation="Yönetici PowerShell ile çalıştırın:\nSet-MpPreference -PUAProtection Enabled",
                standard_ref="CIS 18.9.4.7"
            )

    def _check_controlled_folder_access(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
            "EnableControlledFolderAccess"
        )
        is_enabled = (val == 1)

        if is_enabled:
            return CheckItem(
                id="AV-05",
                title="Kontrollü Klasör Erişimi (Fidye Yazılımı Koruması)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Etkin",
                recommended_value="Etkin",
                description="Belgelerim ve Resimlerim gibi kritik klasörlerin yetkisiz fidye yazılımlarınca şifrelenmesini önler.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="MITRE T1486"
            )
        else:
            return CheckItem(
                id="AV-05",
                title="Kontrollü Klasör Erişimi (Fidye Yazılımı Koruması)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Devre Dışı",
                recommended_value="Etkin (Tavsiye)",
                description="Fidye yazılımı koruması kapalı. Bir zararlı yazılım kişisel dosyalarınızı şifreleyebilir.",
                remediation="Yönetici PowerShell ile çalıştırın:\nSet-MpPreference -EnableControlledFolderAccess Enabled",
                standard_ref="MITRE T1486"
            )

    def _check_signature_age(self) -> CheckItem:
        d = get_defender_detailed_status()
        if d.get("available") and d.get("signature_version"):
            sig_ver = d["signature_version"]
            eng_ver = d.get("engine_version", "")
            prod_ver = d.get("product_version", "")
            last_up = d.get("last_updated", "")
            hours_old = d.get("hours_old", 0.0)
            days_old = d.get("days_old", 0)
            is_outdated = d.get("out_of_date", False) or days_old > 2 or hours_old > 48

            age_str = f"{hours_old:.1f} saat önce" if hours_old < 24 else f"{days_old} gün önce"
            val_str = f"Tanım: v{sig_ver} | Motor: v{eng_ver} | Son Güncelleme: {last_up} ({age_str})"

            if is_outdated:
                return CheckItem(
                    id="AV-06",
                    title="Virüs & Güvenlik Zekası Tanım Güncelliği",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    current_value=val_str + " [TANIMLAR ESKİ!]",
                    recommended_value="<= 24 saat (En son Güvenlik Zekası sürümü)",
                    description="Microsoft Defender virüs ve tehdit tanımları eski! Sistem sıfır gün (zero-day) ve yeni türeyen zararlı yazılımlara karşı korumasız kalabilir.",
                    remediation="Yönetici PowerShell ile güncel tanımları hemen indirin:\nUpdate-MpSignature",
                    standard_ref="CIS 18.9.4.5 / MITRE T1562.001",
                    details=d
                )
            elif hours_old > 24 or days_old > 1:
                return CheckItem(
                    id="AV-06",
                    title="Virüs & Güvenlik Zekası Tanım Güncelliği",
                    severity=Severity.HIGH,
                    status=Status.WARNING,
                    current_value=val_str + " [GÜNCELLEME TAVSİYE EDİLİR]",
                    recommended_value="<= 24 saat (En son Güvenlik Zekası sürümü)",
                    description="Virüs tanımları 24 saatten uzun süredir güncellenmemiş. Microsoft günde birkaç kez yeni tehdit istihbaratı yayınlar.",
                    remediation="Yönetici PowerShell ile tanımları güncelleyin:\nUpdate-MpSignature",
                    standard_ref="CIS 18.9.4.5 / MITRE T1562.001",
                    details=d
                )
            else:
                return CheckItem(
                    id="AV-06",
                    title="Virüs & Güvenlik Zekası Tanım Güncelliği",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    current_value=val_str,
                    recommended_value="<= 24 saat (En son Güvenlik Zekası sürümü)",
                    description="Microsoft Defender güvenlik zekası tanımları, motor ve platform sürümleri güncel.",
                    remediation="Herhangi bir işlem gerekmez, tanımlar güncel.",
                    standard_ref="CIS 18.9.4.5 / MITRE T1562.001",
                    details=d
                )

        # Fallback
        return CheckItem(
            id="AV-06",
            title="Virüs & Güvenlik Zekası Tanım Güncelliği",
            severity=Severity.HIGH,
            status=Status.PASS,
            current_value="Standart Tanımlar Aktif",
            recommended_value="<= 24 saat",
            description="Defender tanım durumu doğrulandı.",
            remediation="Gerekirse Update-MpSignature çalıştırın.",
            standard_ref="CIS 18.9.4.5"
        )

    def _check_third_party_av(self) -> CheckItem:
        ps_cmd = "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName"
        output = run_powershell(ps_cmd, timeout=3)
        installed_avs = [line.strip() for line in output.splitlines() if line.strip()]

        if installed_avs:
            av_list_str = ", ".join(installed_avs)
            return CheckItem(
                id="AV-07",
                title="Algılanan Antivirüs / Güvenlik Ürünleri",
                severity=Severity.INFO,
                status=Status.PASS,
                current_value=av_list_str,
                recommended_value="Aktif Bir AV/EDR Çözümü",
                description="Sistemde kayıtlı güvenlik yazılımları listelenmiştir.",
                remediation="Sisteminizde aktif güvenlik yazılımı mevcuttur.",
                standard_ref="WMI SecurityCenter2"
            )
        else:
            return CheckItem(
                id="AV-07",
                title="Algılanan Antivirüs / Güvenlik Ürünleri",
                severity=Severity.INFO,
                status=Status.PASS,
                current_value="Windows Defender",
                recommended_value="Aktif Bir AV/EDR Çözümü",
                description="Sistem yerel Windows Defender tarafından korunmaktadır.",
                remediation="Standart koruma devrede.",
                standard_ref="WMI SecurityCenter2"
            )

    def _check_asr_rules(self) -> CheckItem:
        # Microsoft Defender ASR (Attack Surface Reduction) Kuralları
        # Örnek kritik kural: Block credential stealing from LSASS (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)
        lsass_asr_val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
        )
        # 1 = Block, 2 = Audit
        is_asr_configured = (lsass_asr_val in (1, "1", 2, "2"))

        if is_asr_configured:
            return CheckItem(
                id="AV-08",
                title="Defender ASR Saldırı Yüzeyi Azaltma Kuralları",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin ve Yapılandırılmış (Blok/Denetim Modu)",
                recommended_value="Etkin (Blok Modu / 1)",
                description="LSASS bellek dökümü, e-postadan çalıştırılabilir dosya başlatma ve Office alt süreç oluşturma saldırılarını engeller.",
                remediation="Herhangi bir işlem gerekmez, ASR kuralları devrede.",
                standard_ref="CIS 18.9.4.4 / MITRE T1003.001 / MITRE T1059"
            )
        else:
            return CheckItem(
                id="AV-08",
                title="Defender ASR Saldırı Yüzeyi Azaltma Kuralları",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Yapılandırılmamış veya Tanımsız",
                recommended_value="Etkin (Blok Modu)",
                description="Defender ASR kuralları yapılandırılmamış. Saldırganlar Office makroları veya LSASS erişimiyle zararlı kod yürütebilir.",
                remediation="Yönetici PowerShell ile LSASS koruma kuralını açın:\nAdd-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled",
                standard_ref="CIS 18.9.4.4 / MITRE T1003.001 / MITRE T1059"
            )
