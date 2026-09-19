import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, registry_key_exists, run_powershell


class AppControlIntegrityModule(BaseModule):
    id: str = "appcontrol"
    name: str = "Uygulama İzin Verme & Kod Bütünlüğü (WDAC/AppLocker)"
    description: str = "WDAC, AppLocker beyaz liste politikaları, AMSI sağlayıcı bütünlüğü, Geliştirici Modu ve PowerShell CLM."
    category: str = "Uygulama Güvenliği & Kod Bütünlüğü"
    weight: int = 9
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_wdac_applocker())
        checks.append(self._check_amsi_integrity())
        checks.append(self._check_developer_mode())
        checks.append(self._check_powershell_clm())
        return checks

    def _check_wdac_applocker(self) -> CheckItem:
        # AppLocker / WDAC politika anahtarları
        has_applocker = registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\SrpV2"
        )
        has_wdac = registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\CI\Policy"
        )

        if has_wdac or has_applocker:
            return CheckItem(
                id="AC-01",
                title="Uygulama Beyaz Liste İlkesi (WDAC / AppLocker)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin ve İlke Tanımlı",
                recommended_value="Tanımlı Olmalı (Sıkılaştırılmış)",
                description="Yalnızca şirket veya sistem tarafından onaylanmış dijital imzalı uygulamaların çalışmasına izin verir.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.27 / MITRE T1204"
            )
        else:
            return CheckItem(
                id="AC-01",
                title="Uygulama Beyaz Liste İlkesi (WDAC / AppLocker)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Yapılandırılmamış (Varsayılan Her .exe Çalışabilir)",
                recommended_value="İlke Tanımlı (Tavsiye)",
                description="Uygulama kontrolü tanımlanmamış. Kullanıcı yetkisindeki herhangi bir dizinden zararlı yazılım çalıştırılabilir.",
                remediation="Grup İlkesi (AppLocker) veya Intune üzerinden WDAC uygulama denetim politikasını yapılandırın.",
                standard_ref="CIS 18.9.27 / MITRE T1204"
            )

    def _check_amsi_integrity(self) -> CheckItem:
        # AMSI Sağlayıcılarının kayıt defteri bütünlüğü kontrolü
        # Kötü amaçlı yazılımlar genellikle HKLM\SOFTWARE\Microsoft\AMSI\Providers anahtarını siler veya bozar
        amsi_path = r"SOFTWARE\Microsoft\AMSI\Providers"
        has_amsi_key = registry_key_exists(winreg.HKEY_LOCAL_MACHINE, amsi_path)

        provider_count = 0
        if has_amsi_key:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, amsi_path, 0, winreg.KEY_READ) as key:
                    provider_count = winreg.QueryInfoKey(key)[0]
            except Exception:
                pass

        if has_amsi_key and provider_count > 0:
            return CheckItem(
                id="AC-02",
                title="AMSI (Antimalware Scan Interface) Sağlayıcı Bütünlüğü",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value=f"Sağlıklı ({provider_count} Aktif Güvenlik Sağlayıcısı Kayıtlı)",
                recommended_value="Bütünlük Doğrulanmış (>= 1 Sağlayıcı)",
                description="Script dilleri (PowerShell, VBScript, Office VBA) çalıştırılmadan önce kodun antivirüse taranması köprüsüdür.",
                remediation="Herhangi bir işlem gerekmez, AMSI bütünlüğü sağlam.",
                standard_ref="MITRE T1562.001 / AMSI Bypass Savunması"
            )
        else:
            return CheckItem(
                id="AC-02",
                title="AMSI (Antimalware Scan Interface) Sağlayıcı Bütünlüğü",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="BOZULMUŞ VEYA SAĞLAYICI YOK!",
                recommended_value="Bütünlük Doğrulanmış",
                description="AMSI sağlayıcı anahtarı silinmiş veya boş! Zararlı yazılımlar antivirüs taramasına yakalanmadan script çalıştırabilir.",
                remediation="Windows Defender'ı yeniden kaydedin veya 'sfc /scannow' çalıştırarak sistem dosyası bütünlüğünü onarın.",
                standard_ref="MITRE T1562.001 / AMSI Bypass Savunması"
            )

    def _check_developer_mode(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
            "AllowDevelopmentWithoutDevLicense"
        )
        # 0 = Developer Mode Disabled (Secure), 1 = Enabled (Permits unverified sideloading)
        is_dev_mode_enabled = (val == 1)

        if not is_dev_mode_enabled:
            return CheckItem(
                id="AC-03",
                title="Windows Geliştirici Modu (Developer Mode)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Devre Dışı (Güvenli)",
                recommended_value="Devre Dışı (0)",
                description="İmzasız ve doğrulanmamış UWP paketlerinin dışarıdan yüklenmesini (sideloading) engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.2 / MITRE T1204"
            )
        else:
            return CheckItem(
                id="AC-03",
                title="Windows Geliştirici Modu (Developer Mode)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="ETKİN (Geliştirici Modu Açık)",
                recommended_value="Devre Dışı (0)",
                description="Geliştirici Modu aktif. Yazılımcı bilgisayarı değilse, imzasız zararlı Windows paketlerinin kurulma riski bulunur.",
                remediation="Yazılım geliştirmiyorsanız Ayarlar > Gizlilik ve Güvenlik > Geliştiriciler İçin > Geliştirici Modunu kapatın.",
                standard_ref="CIS 18.9.2 / MITRE T1204"
            )

    def _check_powershell_clm(self) -> CheckItem:
        ps_out = run_powershell(
            "$ExecutionContext.SessionState.LanguageMode",
            timeout=3
        )
        lang_mode = ps_out.strip()

        if "ConstrainedLanguage" in lang_mode:
            return CheckItem(
                id="AC-04",
                title="PowerShell Kısıtlı Dil Modu (Constrained Language Mode)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="ConstrainedLanguage (Sıkılaştırılmış)",
                recommended_value="ConstrainedLanguage (Kritik Sistemlerde)",
                description="PowerShell içerisinden Win32 API'leri çağrılmasını ve bellek manipülasyonu yapan saldırı fonksiyonlarını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.9.8.2 / MITRE T1059.001"
            )
        else:
            return CheckItem(
                id="AC-04",
                title="PowerShell Kısıtlı Dil Modu (Constrained Language Mode)",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value=f"FullLanguage (Standart)",
                recommended_value="FullLanguage (Normal) / ConstrainedLanguage (Kritik)",
                description="Standart PowerShell ortamı. İhtiyaç durumunda sistem değişkeniyle kısıtlı moda alınabilir.",
                remediation="Kritik sistemlerde ortam değişkeni ekleyebilirsiniz:\n[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')",
                standard_ref="CIS 18.9.8.2 / MITRE T1059.001"
            )
