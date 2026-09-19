import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient
from run import app
from core.templates import get_all_templates, get_template
from core.plugin_model import PLUGIN_METADATA_MAP, enrich_check_to_plugin
from core.engine import AuditEngine
from core.remediation import calculate_top_remediations
from core.nessus_exporter import generate_nessus_v2_xml, generate_nessus_executive_html

client = TestClient(app)


def test_templates_catalog():
    templates = get_all_templates()
    assert len(templates) >= 6
    ids = [t.id for t in templates]
    assert "basic_scan" in ids
    assert "advanced_audit" in ids
    assert "ransomware_defense" in ids
    assert "secret_exposure" in ids
    assert "cis_compliance" in ids
    assert "sca_cve_audit" in ids

    basic = get_template("basic_scan")
    assert basic is not None
    assert "antivirus" in basic.target_modules


def test_plugin_metadata_coverage():
    # En az 30 kural doğrudan Nessus Plugin ID'sine sahip olmalıdır
    assert len(PLUGIN_METADATA_MAP) >= 30
    for cid, meta in PLUGIN_METADATA_MAP.items():
        assert meta["plugin_id"] >= 10000
        assert "CVSS:3.1" in meta["vector"]
        assert 0.0 <= meta["cvss"] <= 10.0
        assert 0.0 <= meta["vpr"] <= 10.0
        assert "Windows :" in meta["family"]


def test_top_remediations_engine():
    engine = AuditEngine()
    report = engine.run_scan(selected_module_ids=["firewall", "identity"])
    rems = calculate_top_remediations(report)
    assert isinstance(rems, list)
    if rems:
        assert len(rems) <= 5
        top = rems[0]
        assert "risk_reduction_pct" in top
        assert top["risk_reduction_pct"] > 0
        assert "action_title" in top
        assert "vuln_count" in top
        assert top["rank"] == 1


def test_nessus_xml_generation():
    engine = AuditEngine()
    report = engine.run_scan(selected_module_ids=["firewall"])
    xml = generate_nessus_v2_xml(report)
    assert '<?xml version="1.0"' in xml
    assert "<NessusClientData_v2>" in xml
    assert "<Report " in xml
    assert "<ReportHost " in xml
    assert "<ReportItem " in xml
    assert 'pluginFamily="Windows : Firewall"' in xml


def test_nessus_api_endpoints():
    # 1. Templates API
    res_tmpl = client.get("/api/templates")
    assert res_tmpl.status_code == 200
    assert len(res_tmpl.json()) >= 6

    # 2. Template Scan API
    res_scan = client.post("/api/scan/template/basic_scan")
    assert res_scan.status_code == 200
    scan_json = res_scan.json()
    assert "template" in scan_json
    assert "report" in scan_json
    assert scan_json["template"]["id"] == "basic_scan"

    # 3. Top Remediations API
    res_rem = client.get("/api/remediations/top")
    assert res_rem.status_code == 200
    assert isinstance(res_rem.json(), list)

    # 4. Nessus XML Export API
    res_xml = client.get("/api/export/nessus")
    assert res_xml.status_code == 200
    assert "NessusClientData_v2" in res_xml.text
    assert "application/xml" in res_xml.headers["content-type"]

    # 5. Nessus Executive HTML Export API
    res_html = client.get("/api/export/nessus-html")
    assert res_html.status_code == 200
    assert "Executive Summary" in res_html.text

    # 6. Plugins Catalog API
    res_plug = client.get("/api/plugins")
    assert res_plug.status_code == 200
    plugins = res_plug.json()
    assert len(plugins) >= 30
    assert plugins[0]["plugin_id"] >= 10000

    # 7. Single Plugin API
    res_single = client.get("/api/plugins/AV-01")
    assert res_single.status_code == 200
    assert res_single.json()["plugin_id"] == 10101
    assert res_single.json()["cvss_v3_score"] == 9.8


if __name__ == "__main__":
    pytest.main(["-v", __file__])
