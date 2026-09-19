from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from abc import ABC, abstractmethod


class Severity(str, Enum):
    CRITICAL = "CRITICAL"  # -25 Puan
    HIGH = "HIGH"          # -15 Puan
    MEDIUM = "MEDIUM"      # -8 Puan
    LOW = "LOW"            # -3 Puan
    INFO = "INFO"          # 0 Puan


class Status(str, Enum):
    PASS = "PASS"          # Başarılı / Güvenli
    FAIL = "FAIL"          # Başarısız / Zafiyet Tespit Edildi
    WARNING = "WARNING"    # Uyarı / Kısmi Uyum
    ERROR = "ERROR"        # Hata / Sorgulanamadı


class CheckItem(BaseModel):
    id: str = Field(..., description="Benzersiz kontrol kimliği (örn: AV-01, HW-02)")
    title: str = Field(..., description="Kontrol başlığı")
    severity: Severity = Field(..., description="Tehdit/Önem derecesi")
    status: Status = Field(..., description="Denetim sonucu")
    current_value: str = Field(..., description="Sistemde okunan mevcut değer")
    recommended_value: str = Field(..., description="Önerilen güvenli değer")
    description: str = Field(..., description="Kontrolün amacı ve zafiyet riski açıklaması")
    remediation: str = Field(..., description="Adım adım düzeltme komutu veya rehberi")
    standard_ref: Optional[str] = Field(None, description="CIS Benchmark, MITRE ATT&CK veya CVE referansı")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Ek teknik detaylar")


class ModuleInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Team"
    version: str = "1.0.0"


class CategoryResult(BaseModel):
    module_id: str
    module_name: str
    category: str
    checks: List[CheckItem]
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_checks: int = 0
    score: int = 100  # Kategori içi başarı yüzdesi (0 - 100)


class ScanReport(BaseModel):
    scan_id: str
    timestamp: str
    hostname: str
    os_info: str
    is_admin: bool
    total_score: int  # 0 - 100 Genel Güvenlik İndeksi
    duration_seconds: float
    total_checks: int
    passed_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    categories: List[CategoryResult]


class BaseModule(ABC):
    """
    Tüm CyberAudit güvenlik denetim modülleri bu sınıftan türetilmelidir.
    """
    id: str = "base_module"
    name: str = "Temel Modül"
    description: str = "Temel denetim modülü"
    category: str = "Genel"
    weight: int = 10
    enabled: bool = True
    author: str = "CyberAudit Team"
    version: str = "1.0.0"

    def get_info(self) -> ModuleInfo:
        return ModuleInfo(
            id=self.id,
            name=self.name,
            description=self.description,
            category=self.category,
            weight=self.weight,
            enabled=self.enabled,
            author=self.author,
            version=self.version,
        )

    @abstractmethod
    def run_checks(self) -> List[CheckItem]:
        """
        Modülün tüm güvenlik kontrollerini yürütür ve sonuç listesini döner.
        """
        pass
