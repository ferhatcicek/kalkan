import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient
from run import app
from core.registry import ModuleRegistry
from core.engine import AuditEngine
from core.exporter import generate_html_report

client = TestClient(app)

def test_module_discovery():
    reg = ModuleRegistry()
    modules = reg.get_all_modules()
    assert len(modules) >= 15, f"En az 15 modül olmalı, bulunan: {len(modules)}"
    ids = [m.id for m in modules]
    assert "antivirus" in ids
    assert "hardware" in ids
    assert "firewall" in ids
    assert "network" in ids
    assert "identity" in ids
    assert "asr" in ids
    assert "logging" in ids
    assert "updates" in ids
    assert "persistence" in ids
    assert "credguard" in ids
    assert "appcontrol" in ids
    assert "storage_usb" in ids
    assert "secret_scan" in ids
    assert "software_inventory" in ids
    assert "browser_security" in ids

def test_engine_scan():
    engine = AuditEngine()
    report = engine.run_scan()
    assert report.total_checks >= 65
    assert 0 <= report.total_score <= 100
    assert report.duration_seconds > 0
    assert len(report.categories) >= 15

def test_api_system_info():
    res = client.get("/api/system-info")
    assert res.status_code == 200
    data = res.json()
    assert "hostname" in data
    assert "os" in data
    assert "is_admin" in data
    assert data["scan_ready"] is True

def test_api_modules():
    res = client.get("/api/modules")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 9
    assert any(m["id"] == "antivirus" for m in data)

def test_api_scan():
    res = client.post("/api/scan", json={"selected_modules": ["firewall", "identity"]})
    assert res.status_code == 200
    data = res.json()
    assert data["total_checks"] > 0
    assert len(data["categories"]) == 2

def test_api_export():
    res_html = client.get("/api/export/html")
    assert res_html.status_code == 200
    assert "<!DOCTYPE html>" in res_html.text
    assert "CyberAudit PC" in res_html.text

    res_json = client.get("/api/export/json")
    assert res_json.status_code == 200
    json_data = res_json.json()
    assert "scan_id" in json_data
    assert "total_score" in json_data

    # OASIS SARIF v2.1.0 Testi
    res_sarif = client.get("/api/export/sarif")
    assert res_sarif.status_code == 200
    sarif_data = res_sarif.json()
    assert sarif_data["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif_data["$schema"]
    assert len(sarif_data["runs"]) > 0
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "CyberAudit PC"
    assert "rules" in sarif_data["runs"][0]["tool"]["driver"]

    # CycloneDX v1.5 SBOM Testi
    res_sbom = client.get("/api/export/sbom")
    assert res_sbom.status_code == 200
    sbom_data = res_sbom.json()
    assert sbom_data["bomFormat"] == "CycloneDX"
    assert sbom_data["specVersion"] == "1.5"
    assert "components" in sbom_data
    assert len(sbom_data["components"]) > 0

def test_api_verify_check():
    # Tekil kontrol doğrulaması testi
    res = client.post("/api/checks/browser_security/BRW-01/verify")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["module_id"] == "browser_security"
    assert data["check"]["id"] == "BRW-01"
    assert "status" in data["check"]

    # Var olmayan kontrol için 404
    res_404 = client.post("/api/checks/browser_security/INVALID-99/verify")
    assert res_404.status_code == 404

def test_toggle_module():
    res = client.post("/api/modules/updates/toggle", json={"enabled": False})
    assert res.status_code == 200
    assert res.json()["enabled"] is False

    # Tekrar aç
    res2 = client.post("/api/modules/updates/toggle", json={"enabled": True})
    assert res2.status_code == 200
    assert res2.json()["enabled"] is True

def test_api_history():
    res = client.get("/api/history")
    assert res.status_code == 200
    data = res.json()
    assert "history" in data
    assert "trend" in data
    assert isinstance(data["history"], list)

def test_api_profiles():
    res = client.get("/api/profiles")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 3
    assert any(p["id"] == "cis-l1" for p in data)

def test_api_fix_script():
    res = client.get("/api/export/fix-script")
    assert res.status_code == 200
    assert "CyberAudit PC" in res.text
    assert "Apply-Fix" in res.text

def test_single_module_endpoints():
    # 1. Modül Detayı
    res_detail = client.get("/api/modules/credguard")
    assert res_detail.status_code == 200
    mod_info = res_detail.json()
    assert mod_info["id"] == "credguard"
    assert len(mod_info["checks"]) >= 5

    # 2. İzole Tek Modül Taraması
    res_scan = client.post("/api/modules/credguard/scan")
    assert res_scan.status_code == 200
    scan_data = res_scan.json()
    assert "result" in scan_data
    assert scan_data["result"]["module_id"] == "credguard"
    assert 0 <= scan_data["result"]["score"] <= 100
    assert scan_data["duration_seconds"] < 5.0

    # 3. Tek Modül Fix Scripti
    res_fix = client.get("/api/modules/credguard/fix-script")
    assert res_fix.status_code == 200
    assert "CyberAudit PC" in res_fix.text
    assert "Content-Disposition" in res_fix.headers

def test_new_owasp_modules():
    # 1. Secret Scan Modülü Testi
    res_sec = client.post("/api/modules/secret_scan/scan")
    assert res_sec.status_code == 200
    sec_data = res_sec.json()
    assert sec_data["result"]["module_id"] == "secret_scan"
    assert len(sec_data["result"]["checks"]) == 5

    # 2. Software Inventory & SBOM Modülü Testi
    res_sca = client.post("/api/modules/software_inventory/scan")
    assert res_sca.status_code == 200
    sca_data = res_sca.json()
    assert sca_data["result"]["module_id"] == "software_inventory"
    assert len(sca_data["result"]["checks"]) == 4

    # 3. Browser Security Modülü Testi
    res_brw = client.post("/api/modules/browser_security/scan")
    assert res_brw.status_code == 200
    brw_data = res_brw.json()
    assert brw_data["result"]["module_id"] == "browser_security"
    assert len(brw_data["result"]["checks"]) == 6
    check_ids = [c["id"] for c in brw_data["result"]["checks"]]
    assert "BRW-06" in check_ids

    # 4. Updates Modülü (UPD-04 3. Parti & UPD-05 Windows/Defender Güncellemeleri) Testi
    res_upd = client.post("/api/modules/updates/scan")
    assert res_upd.status_code == 200
    upd_data = res_upd.json()
    assert upd_data["result"]["module_id"] == "updates"
    assert len(upd_data["result"]["checks"]) == 5
    upd_ids = [c["id"] for c in upd_data["result"]["checks"]]
    assert "UPD-04" in upd_ids
    assert "UPD-05" in upd_ids

    # 5. Antivirus Modülü (AV-06 Defender Güvenlik Zekası) Testi
    res_av = client.post("/api/modules/antivirus/scan")
    assert res_av.status_code == 200
    av_data = res_av.json()
    av_ids = [c["id"] for c in av_data["result"]["checks"]]
    assert "AV-06" in av_ids
    av06 = next(c for c in av_data["result"]["checks"] if c["id"] == "AV-06")
    assert "Tanım" in av06["current_value"] or "Aktif" in av06["current_value"]

if __name__ == "__main__":
    print("Testler çalıştırılıyor...")
    test_module_discovery()
    print("[PASS] Modül keşfi başarılı.")
    test_api_system_info()
    print("[PASS] System info API başarılı.")
    test_api_modules()
    print("[PASS] Modules API başarılı.")
    test_single_module_endpoints()
    print("[PASS] Single module scan & fix-script API başarılı.")
    test_api_scan()
    print("[PASS] Scan API başarılı.")
    test_api_export()
    print("[PASS] Export API (HTML & JSON) başarılı.")
    test_api_fix_script()
    print("[PASS] Export Fix Script (.ps1) başarılı.")
    test_api_history()
    print("[PASS] History & Trend API başarılı.")
    test_api_profiles()
    print("[PASS] Profiles API başarılı.")
    test_toggle_module()
    print("[PASS] Module toggle API başarılı.")
    test_engine_scan()
    print("[PASS] Engine scan başarılı.")
    print("\n--- TÜM ENTEGRASYON TESTLERİ BAŞARIYLA GEÇTİ! ---")
