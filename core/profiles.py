from typing import Dict, List, Any
from pydantic import BaseModel


class AuditProfile(BaseModel):
    id: str
    name: str
    description: str
    target_environment: str
    enabled_modules: List[str]
    icon: str


PROFILES: Dict[str, AuditProfile] = {
    "cis-l1": AuditProfile(
        id="cis-l1",
        name="CIS Seviye 1 (Kurumsal Standart)",
        description="Temel kurumsal güvenlik sıkılaştırması; iş sürekliliğini aksatmadan maksimum güvenlik sağlar.",
        target_environment="Şirket / Ofis Bilgisayarları",
        enabled_modules=["antivirus", "hardware", "firewall", "network", "identity", "asr", "logging", "updates", "persistence", "credguard", "appcontrol", "storage_usb"],
        icon="🏢"
    ),
    "cis-l2": AuditProfile(
        id="cis-l2",
        name="CIS Seviye 2 (Yüksek Güvenlik / Kritik)",
        description="Savunma sanayii, finans ve kritik altyapılar için en katı güvenlik sıkılaştırma kuralları.",
        target_environment="Kritik Altyapı & Finans",
        enabled_modules=["antivirus", "hardware", "firewall", "network", "identity", "asr", "logging", "updates", "persistence", "credguard", "appcontrol", "storage_usb"],
        icon="🔒"
    ),
    "developer": AuditProfile(
        id="developer",
        name="Geliştirici & Mühendislik Profili",
        description="Yazılım geliştiriciler için yerel web servislerine (Docker, WSL, Node/Python) izin veren dengeli profil.",
        target_environment="Yazılım & DevOps",
        enabled_modules=["antivirus", "hardware", "firewall", "identity", "updates", "persistence", "credguard"],
        icon="💻"
    ),
    "home-user": AuditProfile(
        id="home-user",
        name="Kişisel & Ev Kullanıcısı Profili",
        description="Yazıcı ve ev ağı paylaşımını engellemeden temel fidye yazılımı ve antivirüs koruması sağlar.",
        target_environment="Kişisel / Ev Bilgisayarı",
        enabled_modules=["antivirus", "firewall", "updates", "identity", "credguard"],
        icon="🏠"
    )
}

PROFILES_EN: Dict[str, AuditProfile] = {
    "cis-l1": AuditProfile(
        id="cis-l1",
        name="CIS Level 1 (Corporate Baseline)",
        description="Essential corporate security hardening; provides maximum security without disrupting business continuity.",
        target_environment="Corporate / Office Workstations",
        enabled_modules=["antivirus", "hardware", "firewall", "network", "identity", "asr", "logging", "updates", "persistence", "credguard", "appcontrol", "storage_usb"],
        icon="🏢"
    ),
    "cis-l2": AuditProfile(
        id="cis-l2",
        name="CIS Level 2 (High Security / Critical)",
        description="Strictest security hardening baseline tailored for defense industry, finance, and critical infrastructure.",
        target_environment="Critical Infrastructure & Finance",
        enabled_modules=["antivirus", "hardware", "firewall", "network", "identity", "asr", "logging", "updates", "persistence", "credguard", "appcontrol", "storage_usb"],
        icon="🔒"
    ),
    "developer": AuditProfile(
        id="developer",
        name="Developer & Engineering Profile",
        description="Balanced profile permitting local development services (Docker, WSL, Node/Python) while maintaining core security.",
        target_environment="Software & DevOps",
        enabled_modules=["antivirus", "hardware", "firewall", "identity", "updates", "persistence", "credguard"],
        icon="💻"
    ),
    "home-user": AuditProfile(
        id="home-user",
        name="Personal & Home User Profile",
        description="Provides core anti-malware and ransomware protection without blocking home network sharing and printers.",
        target_environment="Personal / Home Computer",
        enabled_modules=["antivirus", "firewall", "updates", "identity", "credguard"],
        icon="🏠"
    )
}


def get_all_profiles(lang: str = "tr") -> List[AuditProfile]:
    store = PROFILES_EN if (lang or "").lower().startswith("en") else PROFILES
    return list(store.values())


def get_profile(profile_id: str, lang: str = "tr") -> AuditProfile:
    store = PROFILES_EN if (lang or "").lower().startswith("en") else PROFILES
    return store.get(profile_id, store.get("cis-l1"))
