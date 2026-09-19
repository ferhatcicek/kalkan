import winreg
from typing import List
from core.base import BaseModule, CheckItem, Severity, Status
from core.utils import read_registry_value, run_command, run_powershell


class StorageAndUsbModule(BaseModule):
    id: str = "storage_usb"
    name: str = "Çevre Birimleri & Taşınabilir Medya Savunması"
    description: str = "USB depolama erişim ilkesi, BitLocker To Go şifreleme zorunluluğu ve Çekirdek DMA port koruması."
    category: str = "Çevre Birimleri & Veri Sızıntısı Savunması"
    weight: int = 8
    enabled: bool = True
    author: str = "CyberAudit Core Team"
    version: str = "1.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        checks.append(self._check_usb_storage_policy())
        checks.append(self._check_bitlocker_to_go())
        checks.append(self._check_kernel_dma_protection())
        return checks

    def _check_usb_storage_policy(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\USBSTOR",
            "Start"
        )
        # 4 = Disabled (USB storage blocked), 3 = Manual/Demand (Standard allowed)
        is_blocked = (val == 4)

        if is_blocked:
            return CheckItem(
                id="USB-01",
                title="USB Yığın Depolama Kısıtlama İlkesi (USBSTOR)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Devre Dışı (USB Bellek Kullanımı Engelli - En Güvenli)",
                recommended_value="Kurumsal Ortamlarda Devre Dışı",
                description="Yetkisiz USB bellek takılmasını engelleyerek veri sızıntısını (DLP) ve harici zararlı bulaşmasını önler.",
                remediation="Herhangi bir işlem gerekmez, USB engelleme devrede.",
                standard_ref="CIS 18.8.2 / MITRE T1091 / DLP"
            )
        else:
            return CheckItem(
                id="USB-01",
                title="USB Yığın Depolama Kısıtlama İlkesi (USBSTOR)",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Etkin (USB Bellek Bağlantısına İzin Veriliyor)",
                recommended_value="İhtiyaç Halinde Devre Dışı",
                description="Standart bilgisayar yapılandırması. Kurumsal veri koruma politikası gerektiriyorsa USB engellenebilir.",
                remediation="USB bellekleri engellemek isterseniz:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4 -Type DWord",
                standard_ref="CIS 18.8.2 / MITRE T1091 / DLP"
            )

    def _check_bitlocker_to_go(self) -> CheckItem:
        val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\FVE",
            "FDVDenyWriteAccess"
        )
        is_enforced = (val == 1)

        if is_enforced:
            return CheckItem(
                id="USB-02",
                title="BitLocker To Go (Şifresiz USB Diske Yazma Yasağı)",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="Zorunlu (Şifresiz Taşınabilir Disklere Yazılamaz)",
                recommended_value="Zorunlu (1)",
                description="Harici USB belleklere veri kopyalanabilmesi için diskin BitLocker ile şifrelenmiş olmasını şart koşar.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.1.2.2 / Veri Sızıntısı Koruması"
            )
        else:
            return CheckItem(
                id="USB-02",
                title="BitLocker To Go (Şifresiz USB Diske Yazma Yasağı)",
                severity=Severity.LOW,
                status=Status.PASS,
                current_value="Tanımsız (Şifresiz USB Disklere Veri Yazılabilir)",
                recommended_value="Kurumsal Politikalarda Zorunlu",
                description="Şirket verilerinin şifresiz kaybolabilir USB disklere kopyalanmasını önlemek için etkinleştirilmesi önerilir.",
                remediation="Yönetici PowerShell ile etkinleştirin:\nNew-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' -Force; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' -Name 'FDVDenyWriteAccess' -Value 1 -Type DWord",
                standard_ref="CIS 18.1.2.2 / Veri Sızıntısı Koruması"
            )

    def _check_kernel_dma_protection(self) -> CheckItem:
        ps_out = run_powershell(
            "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard).SecurityServicesConfigured",
            timeout=3
        )
        # DMA Protection kontrolü
        dma_val = read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDmaProtection",
            "Enabled"
        )
        is_dma_active = (dma_val == 1 or "Kernel DMA" in ps_out)

        if is_dma_active:
            return CheckItem(
                id="USB-03",
                title="Çekirdek DMA Koruması (Kernel DMA Protection)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Etkin (Aktif)",
                recommended_value="Etkin (1)",
                description="PCIe ve Thunderbolt portları üzerinden bilgisayar belleğine doğrudan erişen (Direct Memory Access) donanım saldırılarını engeller.",
                remediation="Herhangi bir işlem gerekmez.",
                standard_ref="CIS 18.1.5 / MITRE T1200"
            )
        else:
            return CheckItem(
                id="USB-03",
                title="Çekirdek DMA Koruması (Kernel DMA Protection)",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value="Desteklenmiyor veya Devre Dışı",
                recommended_value="Etkin (Donanım Destekliyorsa)",
                description="Kernel DMA koruması aktif değil. Harici Thunderbolt veya PCIe çevre birimlerinden bellek manipülasyonu riski mevcuttur.",
                remediation="Donanımınız destekliyorsa BIOS/UEFI menüsünden 'Kernel DMA Protection' özelliğini etkinleştirin.",
                standard_ref="CIS 18.1.5 / MITRE T1200"
            )
