import asyncio
import json
import os
import platform
import socket
import time
from typing import List, Optional

import psutil
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from core.base import ScanReport, Status, Severity
from core.engine import AuditEngine
from core.exporter import generate_html_report, generate_sarif_report, generate_cyclonedx_sbom
from core.remediation import generate_powershell_fix_script, calculate_top_remediations
from core.templates import get_all_templates, get_template
from core.nessus_exporter import generate_nessus_v2_xml, generate_nessus_executive_html
from core.plugin_model import enrich_check_to_plugin, PLUGIN_METADATA_MAP
from core.history import HistoryManager
from core.profiles import get_all_profiles, get_profile
from core.registry import ModuleRegistry
from core.utils import is_admin_user

router = APIRouter()
engine = AuditEngine()
registry = ModuleRegistry()
history_mgr = HistoryManager()


class ScanRequest(BaseModel):
    selected_modules: Optional[List[str]] = None


class ToggleModuleRequest(BaseModel):
    enabled: bool


@router.get("/api/system-info")
def get_system_info():
    """Uç noktanın sistem kimliğini ve donanım özetini döner."""
    try:
        ram = psutil.virtual_memory()
        total_ram_gb = round(ram.total / (1024 ** 3), 1)
    except Exception:
        total_ram_gb = 0

    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} (Build {platform.version()})",
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count() or 4,
        "ram_total_gb": total_ram_gb,
        "is_admin": is_admin_user(),
        "scan_ready": True
    }


@router.get("/api/modules")
def list_modules():
    """Sistemde kayıtlı tüm denetim modüllerini döner."""
    return registry.get_modules_info()


@router.post("/api/modules/{module_id}/toggle")
def toggle_module(module_id: str, req: ToggleModuleRequest):
    """Modülün aktiflik durumunu günceller."""
    success = registry.toggle_module(module_id, req.enabled)
    if not success:
        raise HTTPException(status_code=404, detail=f"Modül bulunamadı: {module_id}")
    return {"status": "success", "module_id": module_id, "enabled": req.enabled}


@router.get("/api/modules/{module_id}")
def get_module_detail(module_id: str):
    """Belirtilen modülün detaylı bilgilerini ve denetimlerini döner."""
    mod = registry.get_module(module_id)
    if not mod:
        raise HTTPException(status_code=404, detail=f"Modül bulunamadı: {module_id}")
    info = mod.get_info().model_dump()
    cat_result = engine._execute_module_safe(mod)
    info["checks"] = [c.model_dump() for c in cat_result.checks]
    info["checks_count"] = len(cat_result.checks)
    return info


@router.post("/api/modules/{module_id}/scan")
def scan_single_module(module_id: str):
    """Belirtilen modülü diğer modüllerden tamamen bağımsız ve izole olarak tarar (<1s)."""
    mod = registry.get_module(module_id)
    if not mod:
        raise HTTPException(status_code=404, detail=f"Modül bulunamadı: {module_id}")

    start_t = time.time()
    result = engine._execute_module_safe(mod)
    duration = round(time.time() - start_t, 2)

    return {
        "result": result,
        "duration_seconds": duration,
        "module_info": mod.get_info()
    }


@router.get("/api/modules/{module_id}/fix-script")
def export_module_fix_script(module_id: str):
    """Yalnızca bu modüldeki zafiyetler için özel PowerShell düzeltme betiği üretir."""
    mod = registry.get_module(module_id)
    if not mod:
        raise HTTPException(status_code=404, detail=f"Modül bulunamadı: {module_id}")

    cat_result = engine._execute_module_safe(mod)

    import datetime
    mini_report = ScanReport(
        scan_id=f"mod-{module_id[:4]}",
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        hostname=socket.gethostname(),
        os_info=f"{platform.system()} {platform.release()}",
        is_admin=is_admin_user(),
        total_score=cat_result.score,
        duration_seconds=0.5,
        total_checks=cat_result.total_checks,
        passed_count=cat_result.passed_checks,
        critical_count=sum(1 for c in cat_result.checks if c.status == Status.FAIL and c.severity == Severity.CRITICAL),
        high_count=sum(1 for c in cat_result.checks if c.status == Status.FAIL and c.severity == Severity.HIGH),
        medium_count=sum(1 for c in cat_result.checks if c.status == Status.FAIL and c.severity == Severity.MEDIUM),
        low_count=sum(1 for c in cat_result.checks if c.status == Status.FAIL and c.severity == Severity.LOW),
        categories=[cat_result]
    )

    script_content = generate_powershell_fix_script(mini_report)
    headers = {
        "Content-Disposition": f"attachment; filename=Fix_{module_id}_{socket.gethostname()}.ps1"
    }
    return Response(content=script_content, media_type="text/plain; charset=utf-8", headers=headers)


@router.post("/api/scan")
def run_scan(req: Optional[ScanRequest] = None, lang: str = "tr"):
    """Güvenlik taramasını başlatır ve raporu döner."""
    selected = req.selected_modules if req else None
    report = engine.run_scan(selected_module_ids=selected, lang=lang)
    return report


@router.get("/api/report/latest")
def get_latest_report(lang: str = "tr"):
    """En son yapılan taramanın sonucunu döner."""
    if not engine.latest_report:
        # Eğer henüz tarama yapılmadıysa otomatik bir tarama başlat
        return engine.run_scan(lang=lang)
    from core.i18n import translate_report
    return translate_report(engine.latest_report, lang)


@router.get("/api/export/html")
def export_html():
    """Raporu yazdırılabilir HTML dosyası olarak indirir."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan()
    html_content = generate_html_report(report)
    headers = {
        "Content-Disposition": f"attachment; filename=CyberAudit_Report_{report.hostname}_{report.scan_id}.html"
    }
    return HTMLResponse(content=html_content, headers=headers)


@router.get("/api/export/json")
def export_json():
    """Raporu ham JSON formatında dosya olarak indirir."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan()
    headers = {
        "Content-Disposition": f"attachment; filename=CyberAudit_Report_{report.hostname}_{report.scan_id}.json"
    }
    return JSONResponse(content=report.model_dump(), headers=headers)


@router.get("/api/export/sarif")
def export_sarif():
    """OASIS SARIF v2.1.0 standardında GitHub Code Scanning ve DefectDojo uyumlu rapor indirir."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan()
    sarif_data = generate_sarif_report(report)
    headers = {
        "Content-Disposition": f"attachment; filename=CyberAudit_{report.hostname}_{report.scan_id}.sarif"
    }
    return JSONResponse(content=sarif_data, headers=headers)


@router.get("/api/export/sbom")
def export_sbom():
    """OWASP Dependency-Track uyumlu CycloneDX v1.5 JSON Yazılım Malzeme Listesi (SBOM) indirir."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan()
    sbom_data = generate_cyclonedx_sbom(report)
    headers = {
        "Content-Disposition": f"attachment; filename=CyberAudit_SBOM_{report.hostname}.cdx.json"
    }
    return JSONResponse(content=sbom_data, headers=headers)


@router.post("/api/checks/{module_id}/{check_id}/verify")
def verify_single_check(module_id: str, check_id: str):
    """
    Belirli bir güvenlik kontrolünü anında yeniden çalıştırır (Düzeltme Doğrulama).
    Tüm sistemi taramadan, kullanıcının uyguladığı düzeltmenin başarılı olup olmadığını doğrular.
    """
    mod = registry.get_module(module_id)
    if not mod:
        raise HTTPException(status_code=404, detail=f"Modül bulunamadı: {module_id}")

    # Modülü çalıştır ve ilgili kontrolü filtrele
    cat_result = engine._execute_module_safe(mod)
    matched_check = next((c for c in cat_result.checks if c.id == check_id), None)
    if not matched_check:
        raise HTTPException(status_code=404, detail=f"Kontrol bulunamadı: {check_id}")

    return {
        "status": "success",
        "module_id": module_id,
        "check": matched_check.model_dump()
    }


@router.get("/api/history")
def get_scan_history():
    """Önceki tarama geçmişini ve trend analizini döner."""
    return history_mgr.get_history_summary()


@router.get("/api/profiles")
def list_profiles(lang: str = "tr"):
    """Tüm denetim profillerini (CIS L1, L2, vb.) döner."""
    return [p.model_dump() for p in get_all_profiles(lang=lang)]


@router.get("/api/export/fix-script")
def export_fix_script():
    """Tespit edilen zafiyetler için interaktif PowerShell sıkılaştırma betiği (.ps1) indirir."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan()
    ps1_content = generate_powershell_fix_script(report)
    headers = {
        "Content-Disposition": f"attachment; filename=CyberAudit_Remediation_{report.hostname}.ps1"
    }
    return Response(content=ps1_content, media_type="text/plain; charset=utf-8", headers=headers)


@router.get("/api/templates")
def list_templates():
    """Tüm hazır tarama şablonlarını döner."""
    return [t.model_dump() for t in get_all_templates()]


@router.post("/api/scan/template/{template_id}")
def scan_with_template(template_id: str, lang: str = "tr"):
    """Seçilen Nessus tarama şablonunun hedef modüllerini kullanarak tarama yürütür."""
    template = get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Şablon bulunamadı: {template_id}")

    report = engine.run_scan(selected_module_ids=template.target_modules, lang=lang)
    return {
        "template": template.model_dump(),
        "report": report.model_dump()
    }


@router.get("/api/remediations/top")
def get_top_remediations(lang: str = "tr"):
    """Tenable Nessus standardında en yüksek risk düşüşü sağlayan ilk 5 düzeltmeyi döner."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan(lang=lang)
    else:
        from core.i18n import translate_report
        report = translate_report(report, lang)
    return calculate_top_remediations(report)


@router.get("/api/export/nessus")
def export_nessus_xml():
    """Tenable Nessus / SecurityCenter ile uyumlu .nessus v2 XML dosyası indirir."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan()
    xml_content = generate_nessus_v2_xml(report)
    headers = {
        "Content-Disposition": f"attachment; filename=CyberAudit_Scan_{report.hostname}_{report.scan_id}.nessus"
    }
    return Response(content=xml_content, media_type="application/xml; charset=utf-8", headers=headers)


@router.get("/api/export/nessus-html")
def export_nessus_executive_html():
    """Tenable Nessus tarzı Yönetici Özeti (Executive Summary) HTML raporu indirir."""
    report = engine.latest_report
    if not report:
        report = engine.run_scan()
    html_content = generate_nessus_executive_html(report)
    headers = {
        "Content-Disposition": f"attachment; filename=CyberAudit_Executive_{report.hostname}_{report.scan_id}.html"
    }
    return HTMLResponse(content=html_content, headers=headers)


@router.get("/api/plugins")
def list_plugins():
    """Tüm Nessus eklentileri (Plugins), CVSS v3.1 skorları ve ailelerini döner."""
    plugins = []
    for check_id, meta in PLUGIN_METADATA_MAP.items():
        plugins.append({
            "check_id": check_id,
            "plugin_id": meta["plugin_id"],
            "family": meta["family"],
            "cvss_v3_score": meta["cvss"],
            "cvss_v3_vector": meta["vector"],
            "vpr_score": meta["vpr"],
            "synopsis": meta["synopsis"],
            "exploit_available": meta.get("exploit", False)
        })
    return plugins


@router.get("/api/plugins/{check_id}")
def get_plugin_by_check_id(check_id: str):
    """Belirli bir kontrolün Nessus Plugin ve CVSS v3.1 detaylarını döner."""
    check_id_upper = check_id.upper()
    meta = PLUGIN_METADATA_MAP.get(check_id_upper)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Plugin bulunamadı: {check_id}")
    return {
        "check_id": check_id_upper,
        "plugin_id": meta["plugin_id"],
        "family": meta["family"],
        "cvss_v3_score": meta["cvss"],
        "cvss_v3_vector": meta["vector"],
        "vpr_score": meta["vpr"],
        "synopsis": meta["synopsis"],
        "exploit_available": meta.get("exploit", False),
        "cpe": meta.get("cpe")
    }




@router.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    """Canlı tarama adımlarını ve yüzdesini istemciye aktaran WebSocket."""
    await websocket.accept()
    loop = asyncio.get_running_loop()

    try:
        while True:
            data_text = await websocket.receive_text()
            data = json.loads(data_text)
            action = data.get("action")

            if action == "start_scan":
                selected = data.get("selected_modules", [])
                lang = data.get("lang", "tr")

                def sync_progress(pct: int, module_name: str, msg: str):
                    payload = json.dumps({
                        "event": "progress",
                        "percent": pct,
                        "current_module": module_name,
                        "message": msg
                    })
                    asyncio.run_coroutine_threadsafe(websocket.send_text(payload), loop)

                # Arka planda taramayı çalıştır
                report = await loop.run_in_executor(
                    None,
                    lambda: engine.run_scan(
                        selected_module_ids=selected if selected else None,
                        progress_callback=sync_progress,
                        lang=lang
                    )
                )

                # Tamamlanma mesajı gönder
                completed_payload = json.dumps({
                    "event": "scan_completed",
                    "report": report.model_dump()
                })
                await websocket.send_text(completed_payload)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"event": "error", "message": str(e)}))
        except Exception:
            pass
