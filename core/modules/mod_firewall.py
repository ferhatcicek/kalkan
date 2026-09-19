import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value


class FirewallModule(BaseModule):
    id: str = "firewall"
    name: str = "Güvenlik Duvarı (Windows Firewall)"
    description: str = "Domain, Private ve Public ağ profillerinin durumu ve varsayılan gelen bağlantı filtreleme kuralları."
    category: str = "Ağ & Çevre Güvenliği"
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_profile("DomainProfile", "FW-01", "Domain Ağ Profili", Severity.HIGH, "CIS 9.1.1"))
        checks.append(self._check_profile("StandardProfile", "FW-02", "Özel (Private) Ağ Profili", Severity.HIGH, "CIS 9.2.1"))
        checks.append(self._check_profile("PublicProfile", "FW-03", "Ortak (Public) Ağ Profili", Severity.CRITICAL, "CIS 9.3.1"))
        checks.append(self._check_default_inbound_action())
        return checks

    def _check_profile(self, profile_key: str, check_id: str, title: str, severity: Severity, ref: str) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile_key}",
            "EnableFirewall"
        )
        is_enabled = (val == 1 or val is None) # Varsayılan 1'dir

        if is_enabled:
            return CheckItem(
                id=check_id,
                title=f"{title} Güvenlik Duvarı",
                severity=severity,
                status=Status.PASS,
                current_value="Etkin (Açık)",
                recommended_value="Etkin (1)",
                description=f"{title} profili için güvenlik duvarının açık olup olmadığını denetler.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref=ref
            )
        else:
            return CheckItem(
                id=check_id,
                title=f"{title} Güvenlik Duvarı",
                severity=severity,
                status=Status.FAIL,
                current_value="Devre Dışı (KAPALI!)",
                recommended_value="Etkin (1)",
                description=f"{title} güvenlik duvarı kapalı! Bilgisayar ağ üzerinden gelen tüm saldırılara savunmasızdır.",
                remediation=f"Yönetici PowerShell ile etkinleştirin:\nSet-NetFirewallProfile -Profile {profile_key.replace('StandardProfile', 'Private').replace('Profile', '')} -Enabled True",
                standard_ref=ref
            )

    def _check_default_inbound_action(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            "DefaultInboundAction"
        )
        # 1 = Block (Default in secure config)
        is_blocked = (val == 1 or val is None)

        if is_blocked:
            return CheckItem(
                id="FW-04",
                title="Varsayılan Gelen Bağlantı Kuralı (Inbound)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Engelle (Block)",
                recommended_value="Engelle (Block / 1)",
                description="Açıkça izin verilmemiş tüm gelen harici ağ bağlantılarını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 9.1.2"
            )
        else:
            return CheckItem(
                id="FW-04",
                title="Varsayılan Gelen Bağlantı Kuralı (Inbound)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value="İzin Ver (Allow - Güvensiz!)",
                recommended_value="Engelle (Block / 1)",
                description="Varsayılan gelen bağlantılara izin verilmiş. Saldırganlar yerel portlara kontrolsüz erişebilir.",
                remediation="Yönetici PowerShell ile varsayılanı engellemeye ayarlayın:\nSet-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block",
                standard_ref="CIS 9.1.2"
            )
