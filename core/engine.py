import concurrent.futures
import datetime
import os
import platform
import socket
import time
import uuid
from typing import Callable, List, Optional

from core.base import CategoryResult, CheckItem, ScanReport, Severity, Status
from core.registry import ModuleRegistry
from core.history import HistoryManager
from core.utils import is_admin_user
from core.i18n import translate_report


class AuditEngine:
    """
    Güvenlik denetimlerini koordine eden, modülleri paralel çalıştıran
    ve nihai güvenlik skorunu hesaplayan çekirdek motor.
    """
    def __init__(self):
        self.registry = ModuleRegistry()
        self.latest_report: Optional[ScanReport] = None

    def run_scan(
        self,
        selected_module_ids: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, str, str], None]] = None,
        lang: str = "tr"
    ) -> ScanReport:
        """
        Güvenlik taramasını yürütür.
        progress_callback: fn(percent, module_name, status_message)
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]

        all_modules = self.registry.get_all_modules()
        if selected_module_ids:
            modules_to_run = [m for m in all_modules if m.id in selected_module_ids and m.enabled]
        else:
            modules_to_run = [m for m in all_modules if m.enabled]

        total_modules = len(modules_to_run)
        if total_modules == 0:
            modules_to_run = [m for m in all_modules if m.enabled]
            total_modules = len(modules_to_run)

        categories_results: List[CategoryResult] = []
        completed_count = 0

        if progress_callback:
            progress_callback(5, "Başlatılıyor", "Sistem bilgileri ve modüller yükleniyor...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, total_modules))) as executor:
            future_to_module = {executor.submit(self._execute_module_safe, mod): mod for mod in modules_to_run}

            for future in concurrent.futures.as_completed(future_to_module):
                mod = future_to_module[future]
                completed_count += 1
                try:
                    category_res = future.result()
                    categories_results.append(category_res)
                except Exception as e:
                    categories_results.append(CategoryResult(
                        module_id=mod.id,
                        module_name=mod.name,
                        category=mod.category,
                        checks=[CheckItem(
                            id=f"{mod.id.upper()}-ERR",
                            title="Modül Yürütme Hatası",
                            severity=Severity.HIGH,
                            status=Status.ERROR,
                            current_value="Hata",
                            recommended_value="Başarılı",
                            description=f"Modül çalıştırılırken beklenmeyen hata: {str(e)}",
                            remediation="Hata loglarını kontrol edin."
                        )],
                        total_checks=1,
                        failed_checks=1,
                        score=0
                    ))

                pct = 10 + int((completed_count / max(1, total_modules)) * 85)
                if progress_callback:
                    progress_callback(pct, mod.name, f"{mod.name} denetimi tamamlandı.")

        mod_order = {m.id: idx for idx, m in enumerate(modules_to_run)}
        categories_results.sort(key=lambda c: mod_order.get(c.module_id, 999))

        # İstatistikler ve Ağırlıklı Güvenlik İndeksi (Hardening Index) Hesabı
        total_checks = sum(c.total_checks for c in categories_results)
        passed_count = sum(c.passed_checks for c in categories_results)

        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0

        # Ağırlık matrisi
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }

        total_possible_weight = 0
        earned_weight = 0.0

        for cat in categories_results:
            for check in cat.checks:
                w = weights.get(check.severity, 2)
                if w > 0:
                    total_possible_weight += w
                    if check.status == Status.PASS:
                        earned_weight += w
                    elif check.status == Status.WARNING:
                        earned_weight += (w * 0.5)  # Kısmi başarı
                    elif check.status == Status.FAIL:
                        pass  # 0 puan

                if check.status == Status.FAIL:
                    if check.severity == Severity.CRITICAL:
                        crit_count += 1
                    elif check.severity == Severity.HIGH:
                        high_count += 1
                    elif check.severity == Severity.MEDIUM:
                        med_count += 1
                    elif check.severity == Severity.LOW:
                        low_count += 1
                elif check.status == Status.WARNING:
                    if check.severity == Severity.CRITICAL:
                        crit_count += 1
                    elif check.severity == Severity.HIGH:
                        high_count += 1
                    elif check.severity == Severity.MEDIUM:
                        med_count += 1
                    elif check.severity == Severity.LOW:
                        low_count += 1

        if total_possible_weight > 0:
            final_score = int(round((earned_weight / total_possible_weight) * 100))
        else:
            final_score = 100

        duration = round(time.time() - start_time, 2)

        report = ScanReport(
            scan_id=scan_id,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            hostname=socket.gethostname(),
            os_info=f"{platform.system()} {platform.release()} ({platform.version()})",
            is_admin=is_admin_user(),
            total_score=final_score,
            duration_seconds=duration,
            total_checks=total_checks,
            passed_count=passed_count,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            categories=categories_results
        )

        self.latest_report = report
        
        # Geçmişe kaydet
        try:
            HistoryManager().save_scan(report.model_dump())
        except Exception:
            pass

        if progress_callback:
            progress_callback(100, "Tamamlandı", f"Tarama {duration} saniyede tamamlandı. Skor: {final_score}")

        report = translate_report(report, lang)
        return report

    def _execute_module_safe(self, module) -> CategoryResult:
        """Modülü çalıştırır ve CategoryResult nesnesi üretir."""
        checks = module.run_checks()
        total = len(checks)
        passed = sum(1 for c in checks if c.status == Status.PASS)
        failed = sum(1 for c in checks if c.status == Status.FAIL)
        warning = sum(1 for c in checks if c.status == Status.WARNING)

        # Kategori içi başarı skoru
        if total == 0:
            cat_score = 100
        else:
            cat_score = int((passed / total) * 100)

        return CategoryResult(
            module_id=module.id,
            module_name=module.name,
            category=module.category,
            checks=checks,
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            warning_checks=warning,
            score=cat_score
        )
