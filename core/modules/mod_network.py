import winreg
from typing import List, Dict, Any
import psutil
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, run_command, run_powershell


class NetworkExposureModule(BaseModule):
    id: str = "network"
    name: str = "Ağ Maruziyeti, Portlar & Protokoller"
    description: str = "Dinlenen açık ağ portları, SMBv1, LLMNR, NetBIOS, Uzak Masaüstü NLA ve Wi-Fi güvenliği denetimi."
    category: str = "Ağ & İletişim Güvenliği"
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    DANGEROUS_PORTS = {
        21: ("FTP", "Şifresiz dosya transferi."),
        23: ("Telnet", "Şifresiz uzaktan komut satırı."),
        80: ("HTTP", "Şifresiz web servisi."),
        135: ("RPC", "Windows Uzaktan Yordam Çağrısı (WMI/DCOM saldırı vektörü)."),
        137: ("NetBIOS Name", "NetBIOS isim çözümleme yayını."),
        138: ("NetBIOS Datagram", "NetBIOS veri yayını."),
        139: ("NetBIOS Session", "NetBIOS oturum servisi."),
        445: ("SMB", "Dosya paylaşım servisi (Saldırganlar için ilk hedef)."),
        3389: ("RDP", "Uzak Masaüstü Protokolü (Brute-force ve sızma riski)."),
        5985: ("WinRM HTTP", "Windows Uzaktan Yönetim (Şifresiz)."),
        5986: ("WinRM HTTPS", "Windows Uzaktan Yönetim."),
    }

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_listening_ports())
        checks.append(self._check_smbv1())
        checks.append(self._check_llmnr())
        checks.append(self._check_netbios())
        checks.append(self._check_rdp_nla())
        checks.append(self._check_open_wifi_profiles())
        checks.append(self._check_smb_signing())
        return checks

    def _check_listening_ports(self) -> CheckItem:
        exposed_services = {}
        critical_ports_found = []

        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if conn.status == "LISTEN":
                    ip, port = conn.laddr
                    if ip in ("0.0.0.0", "::"):
                        proc_name = "Bilinmeyen"
                        if conn.pid:
                            try:
                                proc = psutil.Process(conn.pid)
                                proc_name = proc.name()
                            except Exception:
                                pass
                                
                        svc_key = f"{port}-{conn.pid}-{proc_name}"
                        if svc_key not in exposed_services:
                            exposed_services[svc_key] = {
                                "port": port,
                                "pid": conn.pid,
                                "process": proc_name,
                                "bindings": [ip]
                            }
                        else:
                            if ip not in exposed_services[svc_key]["bindings"]:
                                exposed_services[svc_key]["bindings"].append(ip)

            services_list = list(exposed_services.values())
            services_list.sort(key=lambda x: x["port"])

            for svc in services_list:
                port = svc["port"]
                proc_name = svc["process"]
                if port in self.DANGEROUS_PORTS:
                    name, desc = self.DANGEROUS_PORTS[port]
                    critical_ports_found.append(f"{port} ({name} - {proc_name})")
                    svc["service_name"] = name
                    svc["description"] = desc
                else:
                    svc["service_name"] = "Bilinmeyen/Genel"
                    svc["description"] = "Özel Servis"

        except Exception as e:
            return CheckItem(
                id="NET-01",
                title="Dış Dünyaya Açık Dinlenen Portlar",
                severity=Severity.INFO,
                status=Status.WARNING,
                current_value=f"Yetki yetersizliği veya hata: {e}",
                recommended_value="Yalnızca Gerekli Portlar Açık Olmalı",
                description="Yerel makinede 0.0.0.0 ve :: adreslerinden dış bağlantı kabul eden servislerin denetimi.",
                remediation="Yönetici yetkisi ile çalıştırarak tam port haritasını inceleyin.",
                standard_ref="CIS 18.4"
            )

        if not critical_ports_found:
            return CheckItem(
                id="NET-01",
                title="Dış Dünyaya Açık Dinlenen Portlar",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value=f"{len(services_list)} port dinleniyor (Kritik riskli port yok)",
                recommended_value="Asgari Dinlenen Port",
                description="Dış dünyadan bağlantı dinleyen servisler analiz edildi, kritik veya tehlikeli bir port tespit edilmedi.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.4",
                details={"ports": services_list}
            )
        else:
            return CheckItem(
                id="NET-01",
                title="Dış Dünyaya Açık Dinlenen Portlar",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value=f"Riskli Portlar Açık: {', '.join(critical_ports_found)}",
                recommended_value="Asgari Dinlenen Port",
                description="Ağda doğrudan dinleme yapan ve saldırganların hedefi olabilecek açık portlar tespit edildi.",
                remediation="İhtiyaç duyulmayan servisleri durdurun veya Windows Güvenlik Duvarı üzerinden bu portları gelen bağlantılara kapatın.",
                standard_ref="CIS 18.4",
                details={"ports": services_list}
            )

    def _check_smbv1(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1"
        )
        # 0 = Disabled, 1 = Enabled
        is_smbv1_enabled = (val == 1)

        if not is_smbv1_enabled:
            return CheckItem(
                id="NET-02",
                title="SMBv1 Protokolü (EternalBlue / WannaCry Riski)",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Devre Dışı (Güvenli)",
                recommended_value="Devre Dışı (0)",
                description="SMBv1 30 yıllık eski ve zafiyet dolu bir protokoldür; EternalBlue ve WannaCry gibi fidye yazılımlarının yayılma yoludur.",
                remediation="Herhangi bir işlem gerekmez, SMBv1 kapalı.",
                standard_ref="CIS 18.4.1 / MITRE T1210"
            )
        else:
            return CheckItem(
                id="NET-02",
                title="SMBv1 Protokolü (EternalBlue / WannaCry Riski)",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="ETKİN (Çok Tehlikeli!)",
                recommended_value="Devre Dışı (0)",
                description="SMBv1 açık! Sistem yerel ağdaki fidye yazılımlarının ve uzaktan kod çalıştırma zafiyetlerinin (EternalBlue) doğrudan hedefidir.",
                remediation="Yönetici PowerShell ile hemen kapatın:\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                standard_ref="CIS 18.4.1 / MITRE T1210"
            )

    def _check_llmnr(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "EnableMulticast"
        )
        is_llmnr_disabled = (val == 0)

        if is_llmnr_disabled:
            return CheckItem(
                id="NET-03",
                title="LLMNR Protokolü (NTLM Hash Hırsızlığı Riski)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Devre Dışı (Korumalı)",
                recommended_value="Devre Dışı (0)",
                description="Link-Local Multicast Name Resolution protokolü kapalı, yerel ağda sahte isim çözümleme (Responder atağı) engellenmiş.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.4.2 / MITRE T1557.001"
            )
        else:
            return CheckItem(
                id="NET-03",
                title="LLMNR Protokolü (NTLM Hash Hırsızlığı Riski)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="Etkin (Varsayılan Açık)",
                recommended_value="Devre Dışı (0)",
                description="LLMNR açık! Yerel ağdaki bir saldırgan (Responder aracıyla) bilgisayarınızın NTLMv2 parola hash'lerini çalabilir.",
                remediation="Yönetici PowerShell ile kapatın:\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord",
                standard_ref="CIS 18.4.2 / MITRE T1557.001"
            )

    def _check_netbios(self) -> CheckItem:
        ps_out = run_powershell(
            "(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True').TcpipNetbiosOptions",
            timeout=3
        )
        # 2 = Disabled NetBIOS over TCP/IP
        options = [x.strip() for x in ps_out.splitlines() if x.strip()]
        has_netbios_enabled = any(opt != "2" for opt in options)

        if not has_netbios_enabled and options:
            return CheckItem(
                id="NET-04",
                title="NetBIOS over TCP/IP Yayını",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Devre Dışı (Kapalı)",
                recommended_value="Devre Dışı (2)",
                description="Eski NetBIOS ağ yayınları engellenmiş, yerel ağ zehirleme saldırılarına karşı koruma sağlanmış.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.4.3"
            )
        else:
            return CheckItem(
                id="NET-04",
                title="NetBIOS over TCP/IP Yayını",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Etkin veya DHCP Varsayılanı",
                recommended_value="Devre Dışı (2)",
                description="NetBIOS yayını açık. Ağdaki saldırganlar NetBIOS isim sorgularını dinleyip yanıltabilir.",
                remediation="Ağ Bağdaştırıcı Özellikleri > IPv4 > Gelişmiş > WINS > 'TCP/IP üzerinden NetBIOS'u devre dışı bırak' seçeneğini işaretleyin.",
                standard_ref="CIS 18.4.3"
            )

    def _check_rdp_nla(self) -> CheckItem:
        deny_ts = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections"
        )
        is_rdp_enabled = (deny_ts == 0)

        if not is_rdp_enabled:
            return CheckItem(
                id="NET-05",
                title="Uzak Masaüstü (RDP) & NLA Güvenliği",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="RDP Tamamen Kapalı (En Güvenli)",
                recommended_value="Kapalı veya NLA Zorunlu",
                description="Uzak masaüstü bağlantıları kapalı olduğu için RDP portu üzerinden saldırı yüzeyi sıfırdır.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.8.1 / MITRE T1021.001"
            )

        # RDP açıksa NLA durumuna bak
        nla_val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication"
        )
        is_nla_enforced = (nla_val == 1)

        if is_nla_enforced:
            return CheckItem(
                id="NET-05",
                title="Uzak Masaüstü (RDP) & NLA Güvenliği",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="RDP Açık, Ağ Düzeyinde Kimlik Doğrulama (NLA) ZORUNLU",
                recommended_value="NLA Zorunlu (1)",
                description="RDP açık ancak bağlantı kurulmadan önce kimlik doğrulaması (NLA) şart koşulduğu için oturum güvenlidir.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.8.1 / MITRE T1021.001"
            )
        else:
            return CheckItem(
                id="NET-05",
                title="Uzak Masaüstü (RDP) & NLA Güvenliği",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="RDP Açık, NLA DEVRE DIŞI!",
                recommended_value="NLA Zorunlu (1)",
                description="RDP açık ve NLA kapalı! Bilgisayar doğrudan BlueKeep vb. kritik RDP zafiyetlerine maruz kalabilir.",
                remediation="Yönetici PowerShell ile NLA'yı zorunlu yapın:\nSet-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord",
                standard_ref="CIS 18.8.1 / MITRE T1021.001"
            )

    def _check_open_wifi_profiles(self) -> CheckItem:
        out = run_command(["netsh.exe", "wlan", "show", "profiles"], timeout=3)
        if "All User Profile" not in out and "Tüm Kullanıcı Profili" not in out:
            return CheckItem(
                id="NET-06",
                title="Kayıtlı Kablosuz Ağ (Wi-Fi) Profilleri",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Kayıtlı Wi-Fi profili bulunmuyor (veya Wi-Fi yok)",
                recommended_value="Yalnızca Şifreli Ağlar",
                description="Sistemde daha önce bağlanılan açık veya şifresiz Wi-Fi profillerinin olup olmadığını denetler.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="Saldırı Maruziyeti"
            )

        # Şifresiz profil kontrolü
        open_profiles = []
        lines = [line.split(":")[-1].strip() for line in out.splitlines() if ":" in line and ("All User Profile" in line or "Tüm Kullanıcı Profili" in line)]
        for profile_name in lines[:5]:
            detail = run_command(["netsh.exe", "wlan", "show", "profile", f"name={profile_name}"], timeout=2)
            if "Open" in detail or "Açık" in detail:
                open_profiles.append(profile_name)

        if not open_profiles:
            return CheckItem(
                id="NET-06",
                title="Kayıtlı Kablosuz Ağ (Wi-Fi) Profilleri",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value=f"{len(lines)} adet Wi-Fi profili incelendi, açık/şifresiz profil yok",
                recommended_value="Yalnızca Şifreli Ağlar (WPA2/WPA3)",
                description="Kayıtlı tüm Wi-Fi ağları şifreli güvenli protokollere sahiptir.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="Saldırı Maruziyeti"
            )
        else:
            return CheckItem(
                id="NET-06",
                title="Kayıtlı Kablosuz Ağ (Wi-Fi) Profilleri",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value=f"Şifresiz Kayıtlı Ağlar: {', '.join(open_profiles)}",
                recommended_value="Yalnızca Şifreli Ağlar",
                description="Cihazınız şifresiz açık bir Wi-Fi ağına otomatik bağlanmaya çalışabilir (Evil Twin saldırı riski).",
                remediation=f"Şifresiz profilleri silin:\nnetsh wlan delete profile name='{open_profiles[0]}'",
                standard_ref="Saldırı Maruziyeti"
            )

    def _check_smb_signing(self) -> CheckItem:
        val_srv = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "RequireSecuritySignature"
        )
        val_wks = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "RequireSecuritySignature"
        )
        is_server_signing = (val_srv == 1)
        is_client_signing = (val_wks == 1)

        if is_server_signing and is_client_signing:
            return CheckItem(
                id="NET-07",
                title="SMB Paket İmzalama Zorunluluğu (SMB Signing Mandatory)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Sunucu ve İstemci İçin Zorunlu (Korumalı)",
                recommended_value="Zorunlu (RequireSecuritySignature=1)",
                description="SMB trafiğindeki paketlerin dijital imzalanmasını şart koşarak NTLM Relay ve Man-in-the-Middle saldırılarını engeller.",
                remediation="Herhangi bir işlem gerekmez, SMB imzalama devrede.",
                standard_ref="CIS 2.3.7.3 / MITRE T1557.001"
            )
        else:
            return CheckItem(
                id="NET-07",
                title="SMB Paket İmzalama Zorunluluğu (SMB Signing Mandatory)",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value="Zorunlu Değil (İsteğe Bağlı veya Kapalı)",
                recommended_value="Zorunlu (1)",
                description="SMB imzalama zorunlu değil. Ağdaki saldırganlar SMB oturumlarını araya girerek ele geçirebilir (NTLM Relay / PetitPotam riski).",
                remediation="Yönetici PowerShell ile SMB imzalamayı zorunlu kılın:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord",
                standard_ref="CIS 2.3.7.3 / MITRE T1557.001"
            )
