import json
from core.base import ScanReport, Status, Severity


def generate_html_report(report: ScanReport) -> str:
    """
    Kullanıcının çevrimdışı açabileceği veya PDF olarak yazdırabileceği
    modern ve şık bağımsız HTML denetim raporu üretir.
    """
    # Skor renk sınıfı
    if report.total_score >= 85:
        score_color = "#10b981"
        score_badge = "MÜKEMMEL (GÜVENLİ)"
    elif report.total_score >= 70:
        score_color = "#00f0ff"
        score_badge = "İYİ (KISMİ RİSK)"
    elif report.total_score >= 50:
        score_color = "#eab308"
        score_badge = "ORTA (ZAFİYETLER MEVCUT)"
    else:
        score_color = "#ef4444"
        score_badge = "KRİTİK (YÜKSEK RİSK)"

    categories_html = ""
    for cat in report.categories:
        checks_html = ""
        for c in cat.checks:
            if c.status == Status.PASS:
                status_badge = '<span class="badge pass">BAŞARILI</span>'
                status_class = "border-pass"
            elif c.status == Status.FAIL:
                status_badge = f'<span class="badge fail">{c.severity.value} ZAFİYET</span>'
                status_class = "border-fail"
            elif c.status == Status.WARNING:
                status_badge = f'<span class="badge warning">{c.severity.value} UYARI</span>'
                status_class = "border-warning"
            else:
                status_badge = '<span class="badge error">HATA</span>'
                status_class = "border-error"

            remediation_html = ""
            if c.status != Status.PASS and c.remediation:
                remediation_html = f"""
                <div class="remediation-box">
                    <strong>🔧 Nasıl Düzeltilir?</strong>
                    <pre><code>{c.remediation}</code></pre>
                </div>
                """

            checks_html += f"""
            <div class="check-card {status_class}">
                <div class="check-header">
                    <span class="check-title"><strong>[{c.id}]</strong> {c.title}</span>
                    {status_badge}
                </div>
                <div class="check-desc">{c.description}</div>
                <div class="check-meta">
                    <div><strong>Mevcut Değer:</strong> <code>{c.current_value}</code></div>
                    <div><strong>Önerilen:</strong> <code>{c.recommended_value}</code></div>
                    {f"<div><strong>Referans:</strong> {c.standard_ref}</div>" if c.standard_ref else ""}
                </div>
                {remediation_html}
            </div>
            """

        categories_html += f"""
        <div class="category-section">
            <div class="cat-header">
                <h2>{cat.module_name}</h2>
                <div class="cat-score">Kategori Başarısı: %{cat.score} ({cat.passed_checks}/{cat.total_checks})</div>
            </div>
            <div class="checks-list">
                {checks_html}
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberAudit PC Güvenlik Raporu - {report.hostname}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-card: #1f2937;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --cyan: #00f0ff;
            --pass: #10b981;
            --fail: #ef4444;
            --warn: #eab308;
            --border: #374151;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 26px;
            color: var(--cyan);
        }}
        .header p {{
            margin: 4px 0;
            color: var(--text-muted);
            font-size: 14px;
        }}
        .score-box {{
            text-align: center;
            background: var(--surface-card);
            padding: 16px 28px;
            border-radius: 12px;
            border: 2px solid {score_color};
        }}
        .score-val {{
            font-size: 48px;
            font-weight: 800;
            color: {score_color};
            line-height: 1;
        }}
        .score-lbl {{
            font-size: 12px;
            font-weight: 700;
            margin-top: 6px;
            color: {score_color};
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 24px;
            font-weight: 700;
        }}
        .category-section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .cat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 16px;
        }}
        .cat-header h2 {{
            margin: 0;
            font-size: 18px;
            color: var(--cyan);
        }}
        .cat-score {{
            font-weight: 600;
            font-size: 14px;
            color: var(--text-muted);
        }}
        .check-card {{
            background: var(--surface-card);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 14px;
            border-left: 5px solid var(--border);
        }}
        .border-pass {{ border-left-color: var(--pass); }}
        .border-fail {{ border-left-color: var(--fail); }}
        .border-warning {{ border-left-color: var(--warn); }}
        .border-error {{ border-left-color: #9333ea; }}
        .check-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .check-title {{
            font-size: 16px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .badge.pass {{ background: rgba(16, 185, 129, 0.2); color: var(--pass); }}
        .badge.fail {{ background: rgba(239, 68, 68, 0.2); color: var(--fail); }}
        .badge.warning {{ background: rgba(234, 179, 8, 0.2); color: var(--warn); }}
        .badge.error {{ background: rgba(147, 51, 234, 0.2); color: #c084fc; }}
        .check-desc {{
            color: var(--text-muted);
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .check-meta {{
            font-size: 13px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            background: rgba(0,0,0,0.25);
            padding: 8px 12px;
            border-radius: 6px;
        }}
        .check-meta code {{
            color: var(--cyan);
        }}
        .remediation-box {{
            margin-top: 12px;
            background: #111827;
            border: 1px dashed #4b5563;
            border-radius: 6px;
            padding: 10px 14px;
        }}
        .remediation-box strong {{
            color: #fbbf24;
            font-size: 13px;
        }}
        .remediation-box pre {{
            margin: 6px 0 0 0;
            white-space: pre-wrap;
            word-break: break-all;
            color: #38bdf8;
            font-family: Consolas, monospace;
            font-size: 12px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .header, .category-section, .check-card {{ background: #fff; border-color: #ccc; }}
            .score-box {{ border-color: #000; }}
            .score-val, .score-lbl {{ color: #000; }}
            .check-desc, .header p {{ color: #444; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ CyberAudit PC - Güvenlik Denetim Raporu</h1>
                <p><strong>Cihaz / Bilgisayar:</strong> {report.hostname} | <strong>İşletim Sistemi:</strong> {report.os_info}</p>
                <p><strong>Rapor ID:</strong> #{report.scan_id} | <strong>Tarih:</strong> {report.timestamp} | <strong>Yönetici:</strong> {'Evet' if report.is_admin else 'Hayır'}</p>
            </div>
            <div class="score-box">
                <div class="score-val">{report.total_score}</div>
                <div class="score-lbl">{score_badge}</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-num" style="color: var(--cyan);">{report.total_checks}</div>
                <div style="font-size: 13px; color: var(--text-muted);">Toplam Denetim</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--pass);">{report.passed_count}</div>
                <div style="font-size: 13px; color: var(--text-muted);">Başarılı (Geçti)</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--fail);">{report.critical_count + report.high_count}</div>
                <div style="font-size: 13px; color: var(--text-muted);">Kritik & Yüksek Zafiyet</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--warn);">{report.medium_count + report.low_count}</div>
                <div style="font-size: 13px; color: var(--text-muted);">Orta & Düşük Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: #a78bfa;">{report.duration_seconds}s</div>
                <div style="font-size: 13px; color: var(--text-muted);">Tarama Süresi</div>
            </div>
        </div>

        {categories_html}
    </div>
</body>
</html>
"""
    return html


def generate_sarif_report(report: ScanReport) -> dict:
    """
    OASIS SARIF (Static Analysis Results Interchange Format) v2.1.0 standardına
    tam uyumlu JSON güvenlik raporu üretir. GitHub Code Scanning, GitLab Security
    ve DefectDojo ile doğrudan entegre edilebilir.
    """
    rules_dict = {}
    results_list = []

    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    for cat in report.categories:
        for c in cat.checks:
            # Rule tanımı oluştur
            if c.id not in rules_dict:
                rule_level = level_map.get(c.severity, "warning")
                rules_dict[c.id] = {
                    "id": c.id,
                    "name": c.title.replace(" ", ""),
                    "shortDescription": {
                        "text": c.title
                    },
                    "fullDescription": {
                        "text": c.description
                    },
                    "defaultConfiguration": {
                        "level": rule_level
                    },
                    "help": {
                        "text": f"Düzeltme: {c.remediation}\nÖnerilen: {c.recommended_value}",
                        "markdown": f"### Düzeltme / Remediation\n{c.remediation}\n\n**Önerilen Değer:** `{c.recommended_value}`\n\n**Referans:** {c.standard_ref or 'CIS / OWASP'}"
                    },
                    "properties": {
                        "category": cat.category,
                        "module": cat.module_name,
                        "severity": c.severity.value,
                        "standard_ref": c.standard_ref
                    }
                }

            # Sadece FAIL veya WARNING olanları SARIF result olarak ekle
            if c.status in [Status.FAIL, Status.WARNING]:
                result_level = level_map.get(c.severity, "warning")
                results_list.append({
                    "ruleId": c.id,
                    "ruleIndex": list(rules_dict.keys()).index(c.id),
                    "level": result_level,
                    "message": {
                        "text": f"[{c.id}] {c.title}: Mevcut '{c.current_value}', Beklenen '{c.recommended_value}'. {c.description}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f"endpoint://{report.hostname}/{cat.module_id}/{c.id}"
                                },
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 1
                                }
                            }
                        }
                    ],
                    "properties": {
                        "status": c.status.value,
                        "currentValue": c.current_value,
                        "recommendedValue": c.recommended_value,
                        "remediation": c.remediation
                    }
                })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CyberAudit PC",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/cyberaudit/cyberaudit-pc",
                        "rules": list(rules_dict.values())
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.timestamp,
                        "properties": {
                            "hostname": report.hostname,
                            "os": report.os_info,
                            "totalScore": report.total_score,
                            "isAdmin": report.is_admin
                        }
                    }
                ],
                "results": results_list
            }
        ]
    }
    return sarif_doc


def generate_cyclonedx_sbom(report: ScanReport) -> dict:
    """
    OWASP Dependency-Track ve CISA SBOM gereksinimlerine uygun
    CycloneDX v1.5 JSON Yazılım Malzeme Listesi (SBOM) üretir.
    """
    import uuid
    import datetime

    components = []

    # Eğer software_inventory modülü çalıştırıldıysa yazılım listesini al
    from core.modules.mod_software_inventory import SoftwareInventoryModule
    try:
        software_list = SoftwareInventoryModule()._get_installed_software()
    except Exception:
        software_list = []

    for app in software_list:
        app_name = app.get("name", "Unknown")
        app_ver = app.get("version", "0.0.0")
        publisher = app.get("publisher", "Unknown")

        # Güvenli purl (package url) oluştur
        clean_name = "".join(c for c in app_name.lower().replace(" ", "-") if c.isalnum() or c in "-._")
        purl = f"pkg:generic/{clean_name}@{app_ver}"

        component_entry = {
            "type": "application",
            "name": app_name,
            "version": app_ver,
            "purl": purl,
            "properties": []
        }
        if publisher and publisher != "Bilinmiyor":
            component_entry["supplier"] = {"name": publisher}
        if app.get("install_date"):
            component_entry["properties"].append({
                "name": "installDate",
                "value": app.get("install_date")
            })

        components.append(component_entry)

    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "CyberAudit PC Team",
                    "name": "CyberAudit PC",
                    "version": "2.0.0"
                }
            ],
            "component": {
                "type": "operating-system",
                "name": "Microsoft Windows",
                "version": report.os_info,
                "properties": [
                    {"name": "hostname", "value": report.hostname}
                ]
            }
        },
        "components": components
    }
    return sbom_doc

