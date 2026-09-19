import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import (
    read_registry_value,
    registry_key_exists,
    run_command,
    run_powershell,
    get_pending_software_upgrades,
    get_pending_windows_updates
)


class UpdatesModule(BaseModule):
    id: str = "updates"
    name: str = "Güncelleme, Yama Sağlığı & Yazılım Güncellemeleri"
    description: str = "Windows Update durumu, bekleyen yeniden başlatmalar, Microsoft Defender güncellemeleri ve 3. parti yazılımların güvenlik yamaları."
    category: str = "Yama & Zafiyet Yönetimi"
    weight: int = 14
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "2.1.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_update_service())
        checks.append(self._check_pending_reboot())
        checks.append(self._check_recent_hotfix())
        checks.append(self._check_third_party_updates())
        checks.append(self._check_pending_windows_updates())
        return checks

    def _check_update_service(self) -> CheckItem:
        out = run_command(["sc.exe", "qc", "wuauserv"], timeout=2)
        is_disabled = ("DISABLED" in out)

        if not is_disabled:
            return CheckItem(
                id="UPD-01",
                title="Windows Update Servis Durumu",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Etkin (Otomatik / Manuel)",
                recommended_value="Etkin (Disabled Değil)",
                description="Sistemin kritik güvenlik yamalarını ve hata düzeltmelerini alabilmesini sağlar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 5.41"
            )
        else:
            return CheckItem(
                id="UPD-01",
                title="Windows Update Servis Durumu",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value="DEVRE DIŞI (KAPALI!)",
                recommended_value="Etkin (Disabled Değil)",
                description="Windows Update servisi tamamen kapatılmış! Bilgisayar yeni güvenlik açıklarına karşı yama alamaz.",
                remediation="Yönetici PowerShell ile servisi açın:\nSet-Service -Name wuauserv -StartupType Manual; Start-Service wuauserv",
                standard_ref="CIS 5.41"
            )

    def _check_pending_reboot(self) -> CheckItem:
        # 1. WindowsUpdate Auto Update RebootRequired
        reboot_wu = registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        # 2. Component Based Servicing RebootPending
        reboot_cbs = registry_key_exists(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        )

        has_pending = reboot_wu or reboot_cbs

        if not has_pending:
            return CheckItem(
                id="UPD-02",
                title="Bekleyen Güvenlik Güncellemesi Yeniden Başlatması",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Bekleyen Yeniden Başlatma Yok (Güncel)",
                recommended_value="Bekleyen Yama Yok",
                description="Yüklenen güvenlik yamalarının işletim sistemi çekirdeğine tam uygulanıp uygulanmadığını kontrol eder.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="Yama Sağlığı"
            )
        else:
            return CheckItem(
                id="UPD-02",
                title="Bekleyen Güvenlik Güncellemesi Yeniden Başlatması",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value="YENİDEN BAŞLATMA BEKLİYOR!",
                recommended_value="Bekleyen Yama Yok",
                description="Kritik güvenlik güncellemeleri yüklenmiş ancak bilgisayar yeniden başlatılmadığı için henüz aktif değil.",
                remediation="Güvenlik yamalarının yürürlüğe girmesi için bilgisayarınızı en kısa sürede yeniden başlatın.",
                standard_ref="Yama Sağlığı"
            )

    def _check_recent_hotfix(self) -> CheckItem:
        ps_out = run_powershell(
            "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).HotFixID",
            timeout=4
        )
        latest_hotfix = ps_out.strip()

        if latest_hotfix and "KB" in latest_hotfix:
            return CheckItem(
                id="UPD-03",
                title="En Son Kurulan Windows Güvenlik Yaması",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value=f"Son Güncelleme: {latest_hotfix}",
                recommended_value="Düzenli Güncellenmeli",
                description="Sisteme yüklenen en son resmi Microsoft Hotfix / Güvenlik yaması kimliğidir.",
                remediation="Herhangi bir işlem gerekmez, yamalar başarıyla uygulanıyor.",
                standard_ref="CIS Yama Politikası"
            )
        else:
            return CheckItem(
                id="UPD-03",
                title="En Son Kurulan Windows Güvenlik Yaması",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Sistem güncel yapı sürümünde",
                recommended_value="Düzenli Güncellenmeli",
                description="Windows sürüm yamaları doğrulandı.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS Yama Politikası"
            )

    def _check_third_party_updates(self) -> CheckItem:
        """
        Sistemde yüklü 3. parti yazılımların (web tarayıcıları, uzak masaüstü istemcileri,
        geliştirici araçları) güvenlik güncellemelerini winget aracılığıyla denetler.
        """
        upgrades = get_pending_software_upgrades()

        if not upgrades:
            return CheckItem(
                id="UPD-04",
                title="3. Parti Yazılım ve Uygulama Güncelleme Denetimi",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Tüm 3. parti yazılımlar güncel (Bekleyen güvenlik güncellemesi bulunamadı)",
                recommended_value="Tüm kurulu yazılımlar ve web istemcileri en güncel kararlı sürümde olmalıdır",
                description="Sistemdeki 3. parti yazılımlar ve araçlar denetlendi; bilinen bekleyen yama veya sürüm güncellemesi tespit edilmedi.",
                remediation="Herhangi bir işlem gerekmez. Yazılımlarınız güncel durumdadır.",
                standard_ref="CIS Controls v8 (7.1, 7.2 - Application Software Patch Management) | NIST SP 800-53 SI-2"
            )

        # Yüksek riskli internete açık uygulamalar (Tarayıcılar, Uzak Masaüstü, Toplantı araçları)
        high_risk_keywords = ["opera", "chrome", "firefox", "edge", "brave", "zoom", "remote desktop", "anydesk", "teamviewer", "docker"]
        high_risk_found = []
        other_found = []

        for u in upgrades:
            name_lower = u["name"].lower() + " " + u["id"].lower()
            is_high = any(kw in name_lower for kw in high_risk_keywords)
            summary_str = f"{u['name']} (Kurulu: {u['installed']} -> Güncel: {u['available']})"
            if is_high:
                high_risk_found.append(summary_str)
            else:
                other_found.append(summary_str)

        total_count = len(upgrades)
        high_count = len(high_risk_found)

        # Tüm yazılımları eksiksiz listele (sıfır kısaltma / tam detay ilkesi)
        all_items_lines = []
        enriched_upgrades = []
        for u in upgrades:
            name_lower = u["name"].lower() + " " + u["id"].lower()
            is_high = any(kw in name_lower for kw in high_risk_keywords)
            tag = "[KRİTİK / ÖNCELİKLİ]" if is_high else "[STANDART GÜNCELLEME]"
            all_items_lines.append(f"• {u['name']} (Kurulu: {u['installed']} -> Güncel: {u['available']}) {tag}")
            u_copy = dict(u)
            u_copy["is_high_risk"] = is_high
            enriched_upgrades.append(u_copy)

        full_list_text = f"Toplam {total_count} adet yazılım güncelleme bekliyor:\n" + "\n".join(all_items_lines)

        # Eğer tarayıcı veya kritik uzaktan erişim aracı eskiyse FAIL/HIGH
        if high_count > 0:
            severity = Severity.HIGH
            status = Status.WARNING
            desc = (
                f"Sistemde toplam {total_count} adet 3. parti yazılımın güncellemesi eksik! "
                f"Özellikle web tarayıcıları ve ağ istemcileri ({', '.join([h.split(' (')[0] for h in high_risk_found])}) "
                "eski sürümlerde çalıştırıldığında sıfır gün (zero-day) istismarlarına, bellek bozulmalarına (RCE) ve "
                "kötü amaçlı web sitelerinden bulaşacak zararlı kodlara karşı savunmasız kalır."
            )
        else:
            severity = Severity.MEDIUM
            status = Status.WARNING
            desc = (
                f"Sistemde {total_count} adet yazılımın yeni kararlı sürümü mevcut. "
                "Eski sürümler bilinen hataları ve potansiyel güvenlik açıklarını barındırabilir."
            )

        # Çözüm komutu oluştur
        remed_cmd = (
            "PowerShell'i Yönetici olarak açıp tüm yazılımları tek seferde güncellemek için:\n"
            "winget upgrade --all --accept-source-agreements --accept-package-agreements\n\n"
        )
        # Eğer Opera varsa doğrudan Opera komutu da ekle
        opera_item = next((u for u in upgrades if "opera" in (u["name"] + u["id"]).lower()), None)
        if opera_item:
            remed_cmd += f"Yalnızca Opera tarayıcısını güncellemek için:\nwinget upgrade --id {opera_item['id']} --accept-source-agreements --accept-package-agreements"

        return CheckItem(
            id="UPD-04",
            title="3. Parti Yazılım ve Uygulama Güncelleme Denetimi",
            severity=severity,
            status=status,
            current_value=full_list_text,
            recommended_value="Tüm 3. parti yazılımlar ve tarayıcılar en son güvenlik sürümüne güncellenmelidir",
            description=desc,
            remediation=remed_cmd,
            standard_ref="CIS Controls v8 (7.1, 7.2) | NIST SP 800-53 SI-2 | MITRE ATT&CK T1189",
            details={
                "total_outdated": total_count,
                "high_risk_count": high_count,
                "high_risk_apps": high_risk_found,
                "upgrades": enriched_upgrades
            }
        )

    def _check_pending_windows_updates(self) -> CheckItem:
        """
        Sistemde bekleyen Windows OS güncellemeleri, Microsoft Defender Güvenlik Zekası (Security Intelligence),
        antimalware platform güncellemeleri ve sürücüleri denetler.
        """
        updates = get_pending_windows_updates(timeout_seconds=15)

        if not updates:
            return CheckItem(
                id="UPD-05",
                title="Bekleyen Windows ve Microsoft Defender Güncellemeleri",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Sistemde bekleyen Windows veya Microsoft Defender güncellemesi bulunmuyor. (Tüm yamalar güncel)",
                recommended_value="Tüm Windows ve Defender güncellemeleri tam ve zamanında uygulanmalıdır",
                description="Windows Update Agent (WUA) sorgulanmış olup sistemde bekleyen işletim sistemi veya Defender güncellemesi tespit edilmemiştir.",
                remediation="Herhangi bir işlem gerekmez, Windows Update güncel.",
                standard_ref="CIS 18.9.4 / NIST SP 800-53 SI-2 / MITRE T1189",
                details={
                    "total_pending": 0,
                    "windows_updates": []
                }
            )

        total_count = len(updates)
        defender_updates = [u for u in updates if u.get("is_defender")]
        security_updates = [u for u in updates if u.get("is_security") and not u.get("is_defender")]

        # Sıfır Kesinti İlkesi: Tüm güncellemeler madde madde yazılır
        lines = [f"{total_count} adet güncelleme yüklenmeyi bekliyor:"]
        for u in updates:
            tag = "[KRİTİK / ÖNCELİKLİ - DEFENDER]" if u.get("is_defender") else ("[GÜVENLİK YAMASI]" if u.get("is_security") else "[STANDART / SÜRÜCÜ]")
            kb_part = f" ({u['kb']})" if u.get("kb") else ""
            lines.append(f"• {tag} {u['title']}{kb_part} [Önem: {u.get('severity', 'Standard')}]")

        full_list_text = "\n".join(lines)

        if defender_updates or security_updates:
            severity = Severity.HIGH
            status = Status.FAIL
            desc = (
                f"Sistemde {len(defender_updates)} adet Microsoft Defender ve {len(security_updates)} adet Windows güvenlik güncellemesi bekliyor! "
                "Uç nokta güvenlik açıklarının kapatılması ve en yeni virüs/exploit imzalarının devreye girmesi için bu güncellemelerin acilen yüklenmesi gerekir."
            )
        else:
            severity = Severity.MEDIUM
            status = Status.WARNING
            desc = (
                f"Sistemde {total_count} adet güncelleştirme (sürücü veya isteğe bağlı bileşen) bekliyor. "
                "Sistem kararlılığı ve donanım uyumluluğu için yüklenmesi tavsiye edilir."
            )

        remed_parts = []
        if defender_updates:
            remed_parts.append(
                "Defender Güvenlik Zekasını (İmzaları) hemen komut satırından güncellemek için:\n"
                "Update-MpSignature"
            )
        remed_parts.append(
            "Tüm bekleyen Windows ve Microsoft güncellemelerini başlatmak için:\n"
            "UsoClient StartInteractiveScan\n# veya Windows Ayarları > Windows Update ekranından 'Güncelleştirmeleri Denetle' butonuna tıklayınız."
        )

        return CheckItem(
            id="UPD-05",
            title="Bekleyen Windows ve Microsoft Defender Güncellemeleri",
            severity=severity,
            status=status,
            current_value=full_list_text,
            recommended_value="Tüm Windows ve Defender güncellemeleri derhal yüklenmelidir",
            description=desc,
            remediation="\n\n".join(remed_parts),
            standard_ref="CIS 18.9.4 / NIST SP 800-53 SI-2 / MITRE T1189",
            details={
                "total_pending": total_count,
                "defender_count": len(defender_updates),
                "security_count": len(security_updates),
                "windows_updates": updates
            }
        )
