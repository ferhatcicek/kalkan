import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, registry_key_exists, run_powershell


class CredentialGuardModule(BaseModule):
    id: str = "credguard"
    name: str = "Kimlik Bilgisi, LSA & LAPS Koruması"
    description: str = "Windows Defender Credential Guard, WDigest plaintext parola önleme, Windows LAPS ve NTLM politikaları."
    category: str = "Kimlik Bilgisi & LSA İzolasyonu"
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_credential_guard())
        checks.append(self._check_wdigest_plain_passwords())
        checks.append(self._check_windows_laps())
        checks.append(self._check_lm_compatibility_level())
        checks.append(self._check_lsass_audit_mode())
        return checks

    def _check_credential_guard(self) -> CheckItem:
        # LsaCfgFlags: 1 = Enabled with UEFI lock, 2 = Enabled without lock
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LsaCfgFlags"
        )
        is_active = (val in (1, 2))

        if is_active:
            return CheckItem(
                id="CG-01",
                title="Windows Defender Credential Guard",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value=f"Etkin (LsaCfgFlags={val})",
                recommended_value="Etkin (1 veya 2)",
                description="NTLM hash'leri ve Kerberos biletlerini işletim sisteminden izole sanallaştırılmış bellek bölgesinde saklar.",
                remediation="Herhangi bir işlem gerekmez, Credential Guard devrede.",
                standard_ref="CIS 18.2.2 / MITRE T1003.001"
            )
        else:
            return CheckItem(
                id="CG-01",
                title="Windows Defender Credential Guard",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value="Devre Dışı veya Tanımsız",
                recommended_value="Etkin (1)",
                description="Credential Guard kapalı. VBS destekleniyorsa LSASS kimlik bilgilerinin donanım izolasyonuyla korunması tavsiye edilir.",
                remediation="Yönetici PowerShell ile etkinleştirin:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LsaCfgFlags' -Value 1 -Type DWord",
                standard_ref="CIS 18.2.2 / MITRE T1003.001"
            )

    def _check_wdigest_plain_passwords(self) -> CheckItem:
        # UseLogonCredential: 0 = Plaintext cache disabled (secure), 1 = Enabled (vulnerable)
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential"
        )
        is_safe = (val == 0 or val is None)

        if is_safe:
            return CheckItem(
                id="CG-02",
                title="WDigest Düz Metin (Plaintext) Parola Önbellekleme",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Devre Dışı (Açık Parola Bellekte Saklanmıyor)",
                recommended_value="Devre Dışı (0)",
                description="WDigest protokolünün kullanıcı oturum açma parolalarını RAM üzerinde şifresiz tutmasını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="MITRE T1003.001 / Pass-the-Hash"
            )
        else:
            return CheckItem(
                id="CG-02",
                title="WDigest Düz Metin (Plaintext) Parola Önbellekleme",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="ETKİN (Parolalar Bellekte Açık Tutuluyor!)",
                recommended_value="Devre Dışı (0)",
                description="WDigest açık! Bellek dökümü (LSASS dump) alındığında Windows parolanız düz metin olarak okunabilir.",
                remediation="Yönetici PowerShell ile hemen kapatın:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord",
                standard_ref="MITRE T1003.001 / Pass-the-Hash"
            )

    def _check_windows_laps(self) -> CheckItem:
        # Modern Windows LAPS (Win11 Dahili) veya Legacy LAPS kontrolü
        has_modern_laps = registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
        )
        has_legacy_laps = registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        )

        if has_modern_laps or has_legacy_laps:
            return CheckItem(
                id="CG-03",
                title="Windows LAPS (Yerel Yönetici Parola Çözümü)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin ve Yapılandırılmış",
                recommended_value="Yapılandırılmış Olmalı",
                description="Yerel yönetici parolasını her bilgisayarda benzersiz ve rastgele yaparak yatay sıçrama (lateral movement) saldırılarını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.3.1.5 / MITRE T1078"
            )
        else:
            return CheckItem(
                id="CG-03",
                title="Windows LAPS (Yerel Yönetici Parola Çözümü)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Yapılandırılmamış",
                recommended_value="LAPS Etkinleştirilmeli",
                description="LAPS politikası tanımlanmamış. Yerel yönetici parolaları elle yönetiliyorsa tüm cihazlarda aynı olma riski doğar.",
                remediation="Windows 11 Dahili LAPS politikasını Grup İlkesi (GPO) üzerinden yapılandırın.",
                standard_ref="CIS 2.3.1.5 / MITRE T1078"
            )

    def _check_lm_compatibility_level(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel"
        )
        # 5 = Send NTLMv2 response only. Refuse LM & NTLM
        is_ntlmv2_enforced = (val == 5)

        if is_ntlmv2_enforced:
            return CheckItem(
                id="CG-04",
                title="LAN Manager & NTLMv1 Engelleme (NTLMv2 Zorunluluğu)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Yalnızca NTLMv2 (LM ve NTLMv1 Reddediliyor)",
                recommended_value="Seviye 5 (NTLMv2)",
                description="Eski, kolayca kırılabilen LAN Manager ve NTLMv1 protokollerini tamamen devre dışı bırakır.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.3.11.5 / MITRE T1557"
            )
        else:
            return CheckItem(
                id="CG-04",
                title="LAN Manager & NTLMv1 Engelleme (NTLMv2 Zorunluluğu)",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value=f"Seviye {val if val is not None else 'Varsayılan (Güvensiz NTLMv1 Kabul Edilebilir)'}",
                recommended_value="Seviye 5 (NTLMv2)",
                description="Sistem eski NTLMv1 kimlik doğrulamasına izin veriyor olabilir. Ağdaki dinleyiciler NTLMv1 hash'lerini kolayca kırabilir.",
                remediation="Yönetici PowerShell ile NTLMv2'yi zorunlu kılın:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord",
                standard_ref="CIS 2.3.11.5 / MITRE T1557"
            )

    def _check_lsass_audit_mode(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe",
            "AuditLevel"
        )
        is_audited = (val == 8)

        if is_audited:
            return CheckItem(
                id="CG-05",
                title="LSASS Süreci Yetkisiz Erişim Denetim Modu",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Etkin (AuditLevel=8)",
                recommended_value="Etkin (8)",
                description="LSASS.exe sürecine belleğini okumak amacıyla bağlanan tüm şüpheli uygulamaları denetler ve loglar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="MITRE T1003.001"
            )
        else:
            return CheckItem(
                id="CG-05",
                title="LSASS Süreci Yetkisiz Erişim Denetim Modu",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Devre Dışı veya Tanımsız",
                recommended_value="Etkin (8)",
                description="LSASS erişim denetimi kapalı. Şüpheli bir sürecin LSASS belleğine erişim talepleri Olay Günlüğüne kaydedilmez.",
                remediation="Yönetici PowerShell ile denetim modunu açın:\nNew-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe' -Name 'AuditLevel' -Value 8 -Type DWord",
                standard_ref="MITRE T1003.001"
            )
