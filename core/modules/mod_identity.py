import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, run_command


class IdentityAccountsModule(BaseModule):
    id: str = "identity"
    name: str = "Kimlik, Hesaplar & UAC Politikaları"
    description: str = "Kullanıcı Hesap Denetimi (UAC), Misafir hesabı, boş parola kısıtı, kilitlenme politikası ve yerel yöneticiler."
    category: str = "Kimlik & Erişim Yönetimi"
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_uac_enabled())
        checks.append(self._check_uac_secure_desktop())
        checks.append(self._check_guest_account())
        checks.append(self._check_blank_password_limit())
        checks.append(self._check_account_lockout())
        checks.append(self._check_local_administrators())
        return checks

    def _check_uac_enabled(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA"
        )
        is_uac_active = (val == 1)

        if is_uac_active:
            return CheckItem(
                id="ID-01",
                title="Kullanıcı Hesap Denetimi (UAC)",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Etkin (Açık)",
                recommended_value="Etkin (1)",
                description="Uygulamaların yönetici yetkilerini sessizce ele geçirmesini engelleyerek kullanıcı onayı ister.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.3.17.1 / MITRE T1548.002"
            )
        else:
            return CheckItem(
                id="ID-01",
                title="Kullanıcı Hesap Denetimi (UAC)",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="DEVRE DIŞI (KAPALI!)",
                recommended_value="Etkin (1)",
                description="UAC kapalı! Çalıştırılan her zararlı yazılım hiçbir onay istemeden anında en yüksek sistem yetkilerini kazanır.",
                remediation="Yönetici Kayıt Defteri ile UAC'yi açın:\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord",
                standard_ref="CIS 2.3.17.1 / MITRE T1548.002"
            )

    def _check_uac_secure_desktop(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "PromptOnSecureDesktop"
        )
        is_secure_desktop = (val == 1 or val is None)

        if is_secure_desktop:
            return CheckItem(
                id="ID-02",
                title="UAC Güvenli Masaüstü Karartması (Secure Desktop)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin",
                recommended_value="Etkin (1)",
                description="UAC uyarıları izole bir oturumda (ekran karararak) gösterilir, zararlıların kullanıcı yerine 'Evet' tıklamasını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.3.17.4"
            )
        else:
            return CheckItem(
                id="ID-02",
                title="UAC Güvenli Masaüstü Karartması (Secure Desktop)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="Devre Dışı",
                recommended_value="Etkin (1)",
                description="UAC güvenli masaüstü modu kapalı! Arka plandaki zararlı yazılımlar sahte tıklamalarla yetki yükseltebilir.",
                remediation="Yönetici PowerShell ile açın:\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord",
                standard_ref="CIS 2.3.17.4"
            )

    def _check_guest_account(self) -> CheckItem:
        out = run_command(["net.exe", "user", "Guest"], timeout=3)
        if not out:
            # Türkçe Windows kontrolü: "Konuk"
            out = run_command(["net.exe", "user", "Konuk"], timeout=3)

        is_active = ("Account active               Yes" in out or "Hesap etkin                  Evet" in out)

        if not is_active:
            return CheckItem(
                id="ID-03",
                title="Dahili Misafir (Guest) Hesabı",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Devre Dışı (Korumalı)",
                recommended_value="Devre Dışı (No)",
                description="Parolasız misafir kullanıcı hesabının kapalı olması, kimliği belirsiz kişilerin erişimini engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.3.1.2"
            )
        else:
            return CheckItem(
                id="ID-03",
                title="Dahili Misafir (Guest) Hesabı",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="ETKİN (AÇIK!)",
                recommended_value="Devre Dışı (No)",
                description="Misafir hesabı etkin! Saldırganlar veya yetkisiz kullanıcılar şifresiz oturum açabilir.",
                remediation="Yönetici CMD ile hesabı kapatın:\nnet user Guest /active:no",
                standard_ref="CIS 2.3.1.2"
            )

    def _check_blank_password_limit(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LimitBlankPasswordUse"
        )
        is_limited = (val == 1 or val is None)

        if is_limited:
            return CheckItem(
                id="ID-04",
                title="Boş Parola Ağ Oturumu Sınırlaması",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Sınırlı (Boş parola ile ağdan bağlanılamaz)",
                recommended_value="Sınırlı (1)",
                description="Parolası olmayan yerel hesapların ağ üzerinden (SMB/RDP) oturum açmasını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.3.1.4"
            )
        else:
            return CheckItem(
                id="ID-04",
                title="Boş Parola Ağ Oturumu Sınırlaması",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="Sınırsız (Güvensiz!)",
                recommended_value="Sınırlı (1)",
                description="Boş parolaya sahip yerel hesaplar yerel ağdan bilgisayara kolayca bağlanabilir.",
                remediation="Yönetici PowerShell ile etkinleştirin:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord",
                standard_ref="CIS 2.3.1.4"
            )

    def _check_account_lockout(self) -> CheckItem:
        out = run_command(["net.exe", "accounts"], timeout=3)
        # Lockout threshold / Kilitleme eşiği
        threshold = None
        for line in out.splitlines():
            if "Lockout threshold" in line or "Kilitleme eşiği" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    val_str = parts[1].strip()
                    try:
                        threshold = int(val_str)
                    except ValueError:
                        if "Never" in val_str or "Hiçbir zaman" in val_str:
                            threshold = 0

        if threshold and threshold > 0:
            return CheckItem(
                id="ID-05",
                title="Hesap Kilitleme Politikası (Brute-Force Savunması)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value=f"{threshold} hatalı denemede kilitlenir",
                recommended_value="3 - 10 hatalı deneme",
                description="Belirli sayıda yanlış parola girildiğinde hesabı kilitleyerek kaba kuvvet (brute-force) saldırılarını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 1.2.1 / MITRE T1110"
            )
        else:
            return CheckItem(
                id="ID-05",
                title="Hesap Kilitleme Politikası (Brute-Force Savunması)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Tanımsız (Hiçbir zaman kilitlenmez)",
                recommended_value="5 hatalı deneme",
                description="Hesap kilitleme eşiği kapalı. Saldırganlar sınırsız parola denemesi yaparak şifreyi kırabilir.",
                remediation="Yönetici CMD ile 5 deneme eşiği ayarlayın:\nnet accounts /lockoutthreshold:5 /lockoutduration:30",
                standard_ref="CIS 1.2.1 / MITRE T1110"
            )

    def _check_local_administrators(self) -> CheckItem:
        out = run_command(["net.exe", "localgroup", "Administrators"], timeout=3)
        if not out:
            out = run_command(["net.exe", "localgroup", "Yöneticiler"], timeout=3)

        members = []
        is_parsing = False
        for line in out.splitlines():
            if "---" in line:
                is_parsing = True
                continue
            if is_parsing:
                if "The command completed successfully" in line or "Komut başarıyla tamamlandı" in line:
                    break
                stripped = line.strip()
                if stripped:
                    members.append(stripped)

        member_count = len(members)
        if member_count <= 2:
            return CheckItem(
                id="ID-06",
                title="Yerel Yöneticiler (Administrators) Grubu Üyeleri",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value=f"{member_count} yönetici: {', '.join(members)}",
                recommended_value="Yalnızca Yetkili Hesaplar (<= 2)",
                description="Yerel yönetici haklarına sahip hesap sayısı incelenmiştir.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 2.2 / Ayrıcalık Yönetimi"
            )
        else:
            return CheckItem(
                id="ID-06",
                title="Yerel Yöneticiler (Administrators) Grubu Üyeleri",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value=f"{member_count} yönetici mevcut: {', '.join(members)}",
                recommended_value="En Az Ayrıcalık İlkesi (<= 2)",
                description="Sistemde fazla sayıda yönetici hesabı bulunuyor. Gereksiz yönetici hakları güvenlik riskini artırır.",
                remediation="Gerekli olmayan kullanıcıları Yöneticiler grubundan standart kullanıcı seviyesine indirin.",
                standard_ref="CIS 2.2 / Ayrıcalık Yönetimi"
            )
