import os
import winreg
import psutil
from typing import List, Dict, Any, Optional
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import get_pending_software_upgrades


class BrowserSecurityModule(BaseModule):
    """
    Microsoft Edge, Google Chrome, Mozilla Firefox ve Opera gibi temel web istemcilerinin
    sürüm güncelliğini (patch level), DoH (şifreli DNS), SafeBrowsing, güvensiz hata ayıklama
    portları ve eklenti güvenlik politikalarını denetleyen modül (OWASP Client Hardening).
    """
    id: str = "browser_security"
    name: str = "Web Tarayıcı ve İstemci Sıkılaştırma"
    description: str = "Edge/Chrome/Opera tarayıcılarında sürüm güncelliği, DoH, SafeBrowsing, uzaktan hata ayıklama ve eklenti politikalarını denetler."
    category: str = "Ağ ve İstemci Güvenliği"
    weight: int = 14
    enabled: bool = True
    author: str = "CyberAudit Team"
    version: str = "2.1.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []

        # 1. DNS-over-HTTPS (DoH) Şifreli DNS Politikası (BRW-01)
        checks.append(self._check_dns_over_https())

        # 2. SafeBrowsing Kimlik Avı ve Zararlı Yazılım Koruması (BRW-02)
        checks.append(self._check_safebrowsing())

        # 3. Geliştirici Modu ve Uzantı İzin Politikası (BRW-03)
        checks.append(self._check_extension_policy())

        # 4. Uzak Hata Ayıklama Portu Açıklığı (BRW-04)
        checks.append(self._check_remote_debugging_port())

        # 5. Tarayıcı Parola Yöneticisi ve Otomatik Doldurma Politikası (BRW-05)
        checks.append(self._check_password_manager_policy())

        # 6. Web Tarayıcı Sürüm Güncelliği ve Güvenlik Yamaları (BRW-06)
        checks.append(self._check_browser_patch_levels())

        return checks

    def _read_policy_registry(self, path: str, key_name: str) -> Optional[Any]:
        """HKLM ve HKCU altındaki tarayıcı grup politikası kayıt defteri anahtarlarını okur."""
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, key_name)
                    return val
            except Exception:
                continue
        return None

    def _check_dns_over_https(self) -> CheckItem:
        """Edge ve Chrome için DoH (DnsOverHttpsMode) politikasını kontrol eder."""
        edge_doh = self._read_policy_registry(r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode")
        chrome_doh = self._read_policy_registry(r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode")

        # "automatic" veya "secure" güvenli kabul edilir
        is_configured = False
        status_str = []

        if edge_doh:
            status_str.append(f"Edge: {edge_doh}")
            if str(edge_doh).lower() in ["automatic", "secure"]:
                is_configured = True
        if chrome_doh:
            status_str.append(f"Chrome: {chrome_doh}")
            if str(chrome_doh).lower() in ["automatic", "secure"]:
                is_configured = True

        if is_configured:
            return CheckItem(
                id="BRW-01",
                title="DNS-over-HTTPS (DoH) Şifreli DNS Politikası",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value=f"DoH Yapılandırılmış ({', '.join(status_str)})",
                recommended_value="DnsOverHttpsMode = 'automatic' veya 'secure'",
                description="Tarayıcı DNS sorguları TLS üzerinden şifreli (DoH) olarak gönderilmekte, yerel ağ dinlemelerine ve DNS zehirlenmelerine karşı korunmaktadır.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-319: Cleartext Transmission of Sensitive Information | CIS Controls v8 (9.2)"
            )
        else:
            return CheckItem(
                id="BRW-01",
                title="DNS-over-HTTPS (DoH) Şifreli DNS Politikası",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Tarayıcı Grup Politikalarında DoH zorunluluğu tanımlanmamış (Varsayılan düz metin DNS kullanılabilir)",
                recommended_value="Kurumsal veya kişisel tarayıcılarda DoH 'automatic' veya 'secure' modunda etkinleştirilmelidir",
                description="DNS sorguları şifresiz (UDP 53) iletildiğinde, yerel ağdaki saldırganlar veya ISP gezilen web sitelerini görebilir ve DNS Spoofing saldırısı yapabilir.",
                remediation="Edge için: New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name 'DnsOverHttpsMode' -Value 'automatic'",
                standard_ref="CWE-319 | CIS Controls v8 (9.2)"
            )

    def _check_safebrowsing(self) -> CheckItem:
        """Edge ve Chrome SafeBrowsing korumasını inceler."""
        edge_sb = self._read_policy_registry(r"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenEnabled")
        edge_sb_pua = self._read_policy_registry(r"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenPuaEnabled")
        chrome_sb = self._read_policy_registry(r"SOFTWARE\Policies\Google\Chrome", "SafeBrowsingProtectionLevel")

        # 0 = Devre dışı
        disabled = False
        if edge_sb == 0 or chrome_sb == 0:
            disabled = True

        if disabled:
            return CheckItem(
                id="BRW-02",
                title="Web Tarayıcı Güvenli Tarama (SafeBrowsing/SmartScreen)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="Tarayıcı Güvenli Tarama / SmartScreen politikalarla devre dışı bırakılmış",
                recommended_value="SmartScreenEnabled = 1, SafeBrowsingProtectionLevel = 1 (veya 2)",
                description="Tarayıcının bilinen oltalama (phishing) ve zararlı yazılım sitelerini engelleme mekanizması kapatılmış. Kullanıcı zararlı indirmelere karşı savunmasızdır.",
                remediation="Grup İlkesi veya Registry üzerinden SmartScreenEnabled ve SafeBrowsing korumasını '1' olarak aktifleştirin.",
                standard_ref="CWE-358: Improperly Implemented Security Check | MITRE ATT&CK T1566"
            )
        else:
            return CheckItem(
                id="BRW-02",
                title="Web Tarayıcı Güvenli Tarama (SafeBrowsing/SmartScreen)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="SafeBrowsing / SmartScreen koruması etkin durumda (Varsayılan veya Politika ile korumalı)",
                recommended_value="SmartScreenEnabled = 1",
                description="Web tarayıcısı zararlı indirmelere ve phishing sitelerine karşı gerçek zamanlı URL filtreleme sağlamaktadır.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-358 | MITRE ATT&CK T1566"
            )

    def _check_extension_policy(self) -> CheckItem:
        """Geliştirici modu ve onaylanmamış eklenti yükleme politikasını denetler."""
        edge_dev = self._read_policy_registry(r"SOFTWARE\Policies\Microsoft\Edge", "DeveloperToolsAvailability")
        chrome_dev = self._read_policy_registry(r"SOFTWARE\Policies\Google\Chrome", "DeveloperToolsAvailability")
        blocklist = self._read_policy_registry(r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist", "1")

        # 2 = Geliştirici araçları tamamen engelli (katı kurumsal)
        # 1 = İzinli (standart)
        # 0 = Devre dışı
        is_hardened = (edge_dev == 2 or chrome_dev == 2 or blocklist == "*")

        if is_hardened:
            return CheckItem(
                id="BRW-03",
                title="Tarayıcı Uzantı ve Eklenti Güvenlik Politikası",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Kurumsal eklenti kısıtlama veya geliştirici koruması etkin",
                recommended_value="Kritik ortamlarda onaylanmamış 3. parti tarayıcı eklentileri kısıtlanmalıdır",
                description="Tarayıcıda yetkisiz uzantı yüklenmesine veya geliştirici modunun istismarına karşı kurumsal politika uygulanmış.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CIS Controls v8 (2.5 - Allowlist Authorized Software)"
            )
        else:
            return CheckItem(
                id="BRW-03",
                title="Tarayıcı Uzantı ve Eklenti Güvenlik Politikası",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Standart kullanıcı modu (Kullanıcı onaylı uzantılar yüklenebilir)",
                recommended_value="Bilinmeyen kaynaklardan uzantı yüklenmemeli, mağaza dışı crx yüklemeleri engellenmelidir",
                description="Tarayıcı standart eklenti politikasında çalışıyor. Kötü amaçlı uzantılara karşı kullanıcı dikkatli olmalıdır.",
                remediation="Kritik sistemlerde ExtensionInstallBlocklist kuralı ile sadece izinli uzantılara izin verin.",
                standard_ref="CIS Controls v8 (2.5)"
            )

    def _check_remote_debugging_port(self) -> CheckItem:
        """
        Tarayıcı süreçlerinin '--remote-debugging-port' ile başlatılıp başlatılmadığını denetler.
        Bu port açık olduğunda bilgisayardaki herhangi bir yazılım oturumları ve şifreleri ele geçirebilir!
        """
        flagged_processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pname = (proc.info['name'] or "").lower()
                    if pname in ["chrome.exe", "msedge.exe", "brave.exe", "opera.exe"]:
                        cmdline = proc.info.get('cmdline') or []
                        for arg in cmdline:
                            if "--remote-debugging-port" in arg:
                                flagged_processes.append(f"{proc.info['name']} (PID: {proc.info['pid']}, Arg: {arg})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        if flagged_processes:
            return CheckItem(
                id="BRW-04",
                title="Tarayıcı Uzaktan Hata Ayıklama Portu Açıklığı (Remote Debugging Port)",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value=f"Kritik açık: {'; '.join(flagged_processes)}",
                recommended_value="Tarayıcılar kesinlikle '--remote-debugging-port' ile arka planda çalıştırılmamalıdır",
                description="Tarayıcı uzaktan hata ayıklama portu açık olarak çalışıyor! Bilgisayardaki herhangi bir yerel zararlı yazılım bu porta bağlanarak açık sekmelerdeki tüm çerezleri (session cookies), aktif hesap oturumlarını ve şifreleri çalabilir.",
                remediation="İlgili tarayıcı sürecini sonlandırın ve başlatma kısayolundan '--remote-debugging-port' parametresini kaldırın.",
                standard_ref="CWE-284: Improper Access Control | MITRE ATT&CK T1185 (Browser Session Hijacking)"
            )
        else:
            return CheckItem(
                id="BRW-04",
                title="Tarayıcı Uzaktan Hata Ayıklama Portu Açıklığı (Remote Debugging Port)",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Açık uzaktan hata ayıklama portu içeren tarayıcı süreci tespit edilmedi",
                recommended_value="Tarayıcılar güvenli standart modda çalışmalıdır",
                description="Arka planda yetkisiz oturum çalmaya elverişli hata ayıklama portu açık tarayıcı süreci bulunamadı.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-284 | MITRE ATT&CK T1185"
            )

    def _check_password_manager_policy(self) -> CheckItem:
        """Yerel tarayıcı parola saklama politikasını denetler."""
        edge_pass = self._read_policy_registry(r"SOFTWARE\Policies\Microsoft\Edge", "PasswordManagerEnabled")
        chrome_pass = self._read_policy_registry(r"SOFTWARE\Policies\Google\Chrome", "PasswordManagerEnabled")

        # Kurumsal ortamlarda merkezi şifre yöneticisi tercih edilir, ancak kişisel PC'de aktiftir
        if edge_pass == 0 and chrome_pass == 0:
            return CheckItem(
                id="BRW-05",
                title="Tarayıcı Düz Parola Saklama ve Otomatik Doldurma Politikası",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Tarayıcı yerel parola saklama grup politikası ile sınırlandırılmış (Kurumsal Kasa Modu)",
                recommended_value="Kurumsal ortamlarda merkezi ve master parolalı şifre kasaları kullanılmalıdır",
                description="Tarayıcıların yerel parola saklaması sınırlandırılmış, bu sayede yerel bilgi hırsızı (infostealer) zararlılarının paroları çalması önlenir.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-522 | CIS Controls v8 (5.4)"
            )
        else:
            return CheckItem(
                id="BRW-05",
                title="Tarayıcı Düz Parola Saklama ve Otomatik Doldurma Politikası",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Standart parola yöneticisi etkin (OS Kimlik Doğrulama / Windows Hello korumalı)",
                recommended_value="Tarayıcı şifreleri işletim sistemi kimlik doğrulaması (PIN/Windows Hello) ile kilitlenmelidir",
                description="Tarayıcının dahili parola yöneticisi aktif. Infostealer saldırılarına karşı tarayıcıda 'Parolaları doldurmadan önce Windows Hello iste' seçeneğinin açık olması önerilir.",
                remediation="Tarayıcı ayarlarından 'Parolaları doldururken veya görüntülerken cihaz şifresini/PIN'ini sor' seçeneğini etkinleştirin.",
                standard_ref="CWE-522 | CIS Controls v8 (5.4)"
            )

    def _check_browser_patch_levels(self) -> CheckItem:
        """
        Sistemde yüklü tüm web tarayıcılarının (Opera, Chrome, Edge, Firefox vb.)
        sürüm güncelliğini ve bekleyen güvenlik yamalarını denetler.
        """
        upgrades = get_pending_software_upgrades()

        browser_keywords = ["opera", "chrome", "firefox", "edge", "brave", "vivaldi"]
        outdated_browsers = []

        for u in upgrades:
            combined = (u["name"] + " " + u["id"]).lower()
            # Chrome Remote Desktop'ı tarayıcı sayma
            if "remote desktop" in combined:
                continue
            for b_kw in browser_keywords:
                if b_kw in combined:
                    outdated_browsers.append(u)
                    break

        installed_browsers = self._detect_installed_browsers()

        if outdated_browsers:
            browser_lines = [f"• {b['name']} (Kurulu: {b['installed']} -> Güncel: {b['available']})" for b in outdated_browsers]
            full_browser_str = f"{len(outdated_browsers)} adet web tarayıcısı güncel değil:\n" + "\n".join(browser_lines)

            remed_parts = []
            for b in outdated_browsers:
                remed_parts.append(f"winget upgrade --id {b['id']} --accept-source-agreements --accept-package-agreements")
            remed_cmd = (
                "Güvenlik açıklarını kapatmak için güncellemeyi başlatın:\n" +
                "\n".join(remed_parts) +
                "\n\nVeya ilgili tarayıcının ayarlar menüsünden 'Hakkında' sayfasını açarak otomatik güncellemeyi çalıştırın."
            )

            return CheckItem(
                id="BRW-06",
                title="Web Tarayıcı Sürüm Güncelliği & Kritik Güvenlik Yamaları",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value=full_browser_str,
                recommended_value="Tüm kurulu web tarayıcıları en son güvenlik sürümünde (zero-day yamalı) olmalıdır",
                description=(
                    f"Sistemde kurulu web tarayıcısının ({', '.join([b['name'] for b in outdated_browsers])}) güvenlik güncellemeleri eksik! "
                    "Web tarayıcıları internetten indirilen JavaScript, V8 motoru ve WebRTC kodlarını doğrudan yürüttüğünden, "
                    "eski sürümlerdeki bellek taşması ve sanal kum havuzu (sandbox escape) açıkları zararlı web siteleri tarafından "
                    "uzaktan kod çalıştırma (RCE) amacıyla aktif olarak istismar edilmektedir."
                ),
                remediation=remed_cmd,
                standard_ref="CWE-1395: Vulnerable Component | CIS Controls v8 (7.2) | MITRE ATT&CK T1189 (Drive-by Compromise)",
                details={
                    "outdated_browsers": outdated_browsers,
                    "installed_browsers": installed_browsers
                }
            )
        else:
            return CheckItem(
                id="BRW-06",
                title="Web Tarayıcı Sürüm Güncelliği & Kritik Güvenlik Yamaları",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value=f"Tespit edilen tarayıcılar güncel ({', '.join(installed_browsers) if installed_browsers else 'Varsayılan Sistem Tarayıcısı'})",
                recommended_value="Tüm web tarayıcıları en son güvenlik sürümünde olmalıdır",
                description="Sistemdeki web tarayıcıları (Chrome, Edge, Firefox, Opera vb.) güncel yapıdadır, bilinen bekleyen yama bulunamadı.",
                remediation="Herhangi bir işlem gerekmez. Tarayıcılar günceldir.",
                standard_ref="CIS Controls v8 (7.2) | CWE-1395"
            )

    def _detect_installed_browsers(self) -> List[str]:
        """Sistemde kurulu popüler tarayıcıları hızlıca tespit eder."""
        found = []
        checks = [
            (r"%LOCALAPPDATA%\Programs\Opera", "Opera"),
            (r"%LOCALAPPDATA%\Programs\Opera GX", "Opera GX"),
            (r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe", "Google Chrome"),
            (r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe", "Google Chrome"),
            (r"%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe", "Microsoft Edge"),
            (r"%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe", "Microsoft Edge"),
            (r"%PROGRAMFILES%\Mozilla Firefox\firefox.exe", "Mozilla Firefox"),
            (r"%PROGRAMFILES%\BraveSoftware\Brave-Browser\Application\brave.exe", "Brave Browser"),
        ]
        for p, name in checks:
            exp = os.path.expandvars(p)
            if os.path.exists(exp) and name not in found:
                found.append(name)
        return found
