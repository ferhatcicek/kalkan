from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ScanTemplate(BaseModel):
    id: str
    title: str
    category: str
    badge: str
    description: str
    icon_svg: str
    target_modules: List[str]
    estimated_time: str
    compliance_framework: str


NESSUS_TEMPLATES: List[ScanTemplate] = [
    ScanTemplate(
        id="basic_scan",
        title="Temel Güvenlik Taraması (Basic Vulnerability Scan)",
        category="Genel Tarama",
        badge="Hızlı",
        description="İşletim sistemi, güvenlik duvarı, açık ağ portları ve antivirüs durumunu hızlıca tarar.",
        icon_svg="radar",
        target_modules=["antivirus", "firewall", "network", "updates"],
        estimated_time="~1-2 sn",
        compliance_framework="CIS Controls & Baseline"
    ),
    ScanTemplate(
        id="advanced_audit",
        title="Kapsamlı Kimlik Doğrulamalı Denetim (Advanced Host Audit)",
        category="Tam Kapsam",
        badge="Önerilen",
        description="Tüm 15 güvenlik modülü ve 75+ derin kontrol ile tam kimlik doğrulamalı (credentialed) sistem denetimi.",
        icon_svg="shield-check",
        target_modules=[
            "antivirus", "hardware", "firewall", "network", "identity",
            "asr", "logging", "updates", "persistence", "credguard",
            "appcontrol", "storage_usb", "secret_scan", "software_inventory", "browser_security"
        ],
        estimated_time="~3-5 sn",
        compliance_framework="Full Comprehensive Audit"
    ),
    ScanTemplate(
        id="ransomware_defense",
        title="Fidye Yazılımı & Savunma Sertleştirme (Ransomware Defense)",
        category="Tehdit Odaklı",
        badge="Kritik",
        description="ASR kuralları, Credential Guard, AppControl, BitLocker ve Antivirüs derinlikli fidye yazılımı koruması.",
        icon_svg="lock",
        target_modules=["asr", "credguard", "appcontrol", "antivirus", "hardware", "storage_usb"],
        estimated_time="~2 sn",
        compliance_framework="MITRE ATT&CK / CISA Ransomware Guide"
    ),
    ScanTemplate(
        id="secret_exposure",
        title="Hassas Veri & Gizli Bilgi Sızıntısı (Secrets & Credentials)",
        category="Veri Güvenliği",
        badge="Gitleaks",
        description="SSH anahtarları, bulut kimlikleri (.aws, .kube), geliştirici .env sırları ve terminal geçmişi sızıntıları.",
        icon_svg="key",
        target_modules=["secret_scan", "identity", "persistence"],
        estimated_time="~2 sn",
        compliance_framework="OWASP Secrets Management / Gitleaks"
    ),
    ScanTemplate(
        id="cis_compliance",
        title="CIS Benchmark Uyumluluk Sertifikasyonu (CIS Windows Benchmark)",
        category="Uyum & Regülasyon",
        badge="CIS v8",
        description="CIS Microsoft Windows 10/11 Benchmark Level 1 ve Level 2 kurallarına resmi uyumluluk karnesi.",
        icon_svg="award",
        target_modules=[
            "antivirus", "hardware", "firewall", "network", "identity",
            "asr", "logging", "updates", "credguard", "appcontrol", "browser_security"
        ],
        estimated_time="~3 sn",
        compliance_framework="CIS Controls v8 (Level 1 & Level 2)"
    ),
    ScanTemplate(
        id="sca_cve_audit",
        title="Yazılım Bileşen Analizi & CVE Taraması (Software Inventory & SCA)",
        category="Yazılım Güvenliği",
        badge="SBOM",
        description="Yüklü 3. parti yazılımların envanteri, bilinen kritik CVE zafiyetleri ve CycloneDX v1.5 SBOM üretimi.",
        icon_svg="package",
        target_modules=["software_inventory", "updates", "browser_security"],
        estimated_time="~2 sn",
        compliance_framework="OWASP SCVS / CycloneDX v1.5"
    )
]


def get_all_templates() -> List[ScanTemplate]:
    """Tüm Nessus tarama şablonlarını döner."""
    return NESSUS_TEMPLATES


def get_template(template_id: str) -> Optional[ScanTemplate]:
    """Belirtilen ID'ye sahip şablonu döner."""
    for t in NESSUS_TEMPLATES:
        if t.id == template_id:
            return t
    return None
