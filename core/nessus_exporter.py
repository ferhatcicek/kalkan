import xml.etree.ElementTree as ET
import datetime
from typing import List, Dict, Any
from core.base import ScanReport, Severity, Status
from core.plugin_model import enrich_check_to_plugin, PLUGIN_METADATA_MAP


def generate_nessus_v2_xml(report: ScanReport) -> str:
    """
    Tenable Nessus Professional / SecurityCenter ile %100 uyumlu
    .nessus v2 XML formatında denetim raporu üretir.
    """
    root = ET.Element("NessusClientData_v2")

    # Policy Etiketi
    policy = ET.SubElement(root, "Policy")
    ET.SubElement(policy, "policyName").text = "CyberAudit Enterprise Security Audit Policy"
    preferences = ET.SubElement(policy, "Preferences")
    pref_cred = ET.SubElement(preferences, "ServerPreferences")
    ET.SubElement(pref_cred, "name").text = "credentialed_scan"
    ET.SubElement(pref_cred, "value").text = "yes"

    # Report Etiketi
    rep = ET.SubElement(root, "Report", attrib={"name": f"CyberAudit_Scan_{report.scan_id}"})
    rep_host = ET.SubElement(rep, "ReportHost", attrib={"name": report.hostname})

    # Host Özellikleri (HostProperties)
    host_props = ET.SubElement(rep_host, "HostProperties")

    tags = {
        "HOST_START": report.timestamp,
        "HOST_END": report.timestamp,
        "operating-system": report.os_info,
        "host-ip": "127.0.0.1",
        "netbios-name": report.hostname,
        "credentialed_scan": "true" if report.is_admin else "false",
        "system-type": "general-purpose",
        "scan-engine": "CyberAudit Engine v2.0"
    }
    for tag_name, tag_val in tags.items():
        tag_el = ET.SubElement(host_props, "tag", attrib={"name": tag_name})
        tag_el.text = tag_val

    # Severity Dönüşüm Haritası (Nessus Standard: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)
    severity_int_map = {
        Severity.CRITICAL: "4",
        Severity.HIGH: "3",
        Severity.MEDIUM: "2",
        Severity.LOW: "1",
        Severity.INFO: "0"
    }

    # Her kontrolü Nessus ReportItem olarak ekle
    for cat in report.categories:
        for check in cat.checks:
            plugin = enrich_check_to_plugin(check, cat.module_name, cat.category)

            # Sadece bulgular (veya bilgi amaçlı olanlar)
            sev_int = severity_int_map.get(check.severity, "1")
            if check.status == Status.PASS:
                # Başarılı kontrolleri Compliance PASS veya Info olarak işaretle
                sev_int = "0"

            item_attribs = {
                "port": "0",
                "svc_name": "general",
                "protocol": "tcp",
                "severity": sev_int,
                "pluginID": str(plugin.plugin_id),
                "pluginName": f"[{check.id}] {plugin.name}",
                "pluginFamily": plugin.family
            }

            rep_item = ET.SubElement(rep_host, "ReportItem", attrib=item_attribs)

            ET.SubElement(rep_item, "synopsis").text = plugin.synopsis
            ET.SubElement(rep_item, "description").text = plugin.description
            ET.SubElement(rep_item, "solution").text = plugin.solution
            ET.SubElement(rep_item, "risk_factor").text = check.severity.value
            ET.SubElement(rep_item, "cvss3_base_score").text = str(plugin.cvss_v3_score)
            ET.SubElement(rep_item, "cvss3_vector").text = plugin.cvss_v3_vector
            ET.SubElement(rep_item, "vpr_score").text = str(plugin.vpr_score)
            ET.SubElement(rep_item, "plugin_output").text = (
                f"Check ID: {check.id}\n"
                f"Status: {check.status.value}\n"
                f"Current System Value: {check.current_value}\n"
                f"Required Hardening Value: {check.recommended_value}\n"
                f"Remediation Guidance:\n{check.remediation}"
            )
            ET.SubElement(rep_item, "fname").text = f"cyberaudit_{check.id.lower().replace('-', '_')}.nasl"
            ET.SubElement(rep_item, "plugin_type").text = "local"

            for sa in plugin.see_also:
                ET.SubElement(rep_item, "see_also").text = sa

    # XML String üret
    xml_declaration = '<?xml version="1.0" encoding="UTF-8" ?>\n'
    rough_string = ET.tostring(root, encoding="utf-8").decode("utf-8")
    return xml_declaration + rough_string


def generate_nessus_executive_html(report: ScanReport) -> str:
    """Tenable Nessus tarzı şık bir Yönetici Özeti (Executive Summary) HTML raporu üretir."""
    crit_count = report.critical_count
    high_count = report.high_count
    med_count = report.medium_count
    low_count = report.low_count

    total_vulns = crit_count + high_count + med_count + low_count

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>CyberAudit PC Executive Security Report - {report.hostname}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .brand {{ font-size: 24px; font-weight: 900; color: #38bdf8; display: flex; align-items: center; gap: 10px; }}
        .meta-box {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 16px; margin: 24px 0; display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
        .sev-bar {{ display: flex; height: 16px; border-radius: 8px; overflow: hidden; margin: 24px 0; background: #334155; }}
        .sev-crit {{ background: #ef4444; width: {(crit_count/max(1, total_vulns))*100}%; }}
        .sev-high {{ background: #f97316; width: {(high_count/max(1, total_vulns))*100}%; }}
        .sev-med {{ background: #eab308; width: {(med_count/max(1, total_vulns))*100}%; }}
        .sev-low {{ background: #06b6d4; width: {(low_count/max(1, total_vulns))*100}%; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e293b; border-radius: 10px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        .pill {{ padding: 3px 8px; border-radius: 6px; font-weight: 800; font-size: 11px; }}
        .pill-crit {{ background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .pill-high {{ background: rgba(249,115,22,0.2); color: #f97316; border: 1px solid #f97316; }}
        .pill-med {{ background: rgba(234,179,8,0.2); color: #eab308; border: 1px solid #eab308; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">🛡️ CyberAudit PC - Kurumsal Güvenlik Denetimi</div>
        <div>Üst Düzey Yönetici Özeti (Executive Summary)</div>
    </div>
    <div class="meta-box">
        <div><strong>Hedef Cihaz:</strong> {report.hostname}</div>
        <div><strong>İşletim Sistemi:</strong> {report.os_info}</div>
        <div><strong>Genel Güvenlik İndeksi:</strong> {report.total_score} / 100</div>
        <div><strong>Kimlik Doğrulamalı Tarama:</strong> {'Evet' if report.is_admin else 'Hayır'}</div>
    </div>
    <h3>Zafiyet Şiddet Dağılımı</h3>
    <div class="sev-bar">
        <div class="sev-crit"></div>
        <div class="sev-high"></div>
        <div class="sev-med"></div>
        <div class="sev-low"></div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Şiddet</th>
                <th>Plugin ID</th>
                <th>Zafiyet Adı</th>
                <th>Aile (Family)</th>
                <th>Durum</th>
            </tr>
        </thead>
        <tbody>
"""
    for cat in report.categories:
        for c in cat.checks:
            if c.status in [Status.FAIL, Status.WARNING]:
                pill_cls = "pill-crit" if c.severity == Severity.CRITICAL else ("pill-high" if c.severity == Severity.HIGH else "pill-med")
                meta = PLUGIN_METADATA_MAP.get(c.id, {})
                pid = meta.get("plugin_id", 10000)
                fam = meta.get("family", cat.category)
                html += f"""
                <tr>
                    <td><span class="pill {pill_cls}">{c.severity.value}</span></td>
                    <td><code>{pid}</code></td>
                    <td><strong>[{c.id}]</strong> {c.title}</td>
                    <td>{fam}</td>
                    <td><code>{c.current_value[:30]}</code></td>
                </tr>
                """

    html += """
        </tbody>
    </table>
</body>
</html>
"""
    return html
