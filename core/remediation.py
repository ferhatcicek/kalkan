from typing import List
from core.base import ScanReport, Status, Severity


def generate_powershell_fix_script(report: ScanReport) -> str:
    """
    Kullanıcının yönetici PowerShell terminalinde çalıştırarak
    tespit edilen güvenlik açıklarını interaktif veya otomatik düzeltebileceği
    güvenli bir PowerShell betiği (.ps1) üretir.
    """
    failed_items = []
    for cat in report.categories:
        for c in cat.checks:
            if c.status in (Status.FAIL, Status.WARNING) and c.remediation and "Herhangi bir işlem gerekmez" not in c.remediation:
                failed_items.append(c)

    script_lines = [
        "<#",
        "==========================================================================",
        "  CyberAudit PC - Otomatik Güvenlik Sıkılaştırma & Düzeltme Betiği",
        f"  Hedef Bilgisayar : {report.hostname}",
        f"  Tarama ID        : #{report.scan_id}",
        f"  Tarih            : {report.timestamp}",
        f"  Toplam Düzeltme  : {len(failed_items)} Adet Güvenlik Kuralı",
        "==========================================================================",
        "  DİKKAT: Bu betik yönetici yetkisi ile çalıştırılmalıdır.",
        "  Her düzeltme öncesinde kullanıcı onayı istenir (-Force ile atlanabilir).",
        "==========================================================================",
        "#>",
        "",
        "param(",
        "    [switch]$Force = $false",
        ")",
        "",
        "# 1. Yönetici Yetki Kontrolü",
        "$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        "if (-not $isAdmin) {",
        '    Write-Host "[!] HATA: Bu betik Yönetici (Administrator) olarak çalıştırılmalıdır!" -ForegroundColor Red',
        '    Write-Host "[!] Lütfen PowerShell penceresini ''Yönetici Olarak Çalıştır'' seçeneğiyle açıp tekrar deneyin." -ForegroundColor Yellow',
        "    Exit 1",
        "}",
        "",
        'Write-Host "==========================================================================" -ForegroundColor Cyan',
        f'Write-Host "  CyberAudit PC Güvenlik Sıkılaştırma Sihirbazı - {report.hostname}" -ForegroundColor Cyan',
        'Write-Host "==========================================================================" -ForegroundColor Cyan',
        f'Write-Host "Toplam {len(failed_items)} adet tespit edilen güvenlik kuralı incelenecek.`n"',
        "",
        "function Apply-Fix {",
        "    param(",
        "        [string]$Id,",
        "        [string]$Title,",
        "        [string]$Severity,",
        "        [string]$Description,",
        "        [scriptblock]$CommandBlock",
        "    )",
        '    Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray',
        '    Write-Host "[$Id] $Title" -ForegroundColor Yellow',
        '    Write-Host "Önem Derecesi : $Severity" -ForegroundColor ($Severity -eq "CRITICAL" ? "Red" : "DarkYellow")',
        '    Write-Host "Açıklama      : $Description" -ForegroundColor Gray',
        "",
        "    $apply = $false",
        "    if ($Force) {",
        "        $apply = $true",
        "    } else {",
        '        $choice = Read-Host "Bu düzeltmeyi uygulamak istiyor musunuz? (E/H) [Varsayılan: E]"',
        '        if ($choice -eq "" -or $choice -match "^[eEyY]") {',
        "            $apply = $true",
        "        }",
        "    }",
        "",
        "    if ($apply) {",
        '        Write-Host "[-] Düzeltme uygulanıyor..." -ForegroundColor DarkCyan',
        "        try {",
        "            & $CommandBlock",
        '            Write-Host "[+] BAŞARILI: $Title kuralı başarıyla sıkılaştırıldı.`n" -ForegroundColor Green',
        "        } catch {",
        '            Write-Host "[!] HATA: Düzeltme uygulanırken hata oluştu: $($_.Exception.Message)`n" -ForegroundColor Red',
        "        }",
        "    } else {",
        '        Write-Host "[*] Atlandı.`n" -ForegroundColor DarkGray',
        "    }",
        "}",
        ""
    ]

    for item in failed_items:
        clean_desc = item.description.replace('"', '`"').replace('$', '`$')
        clean_title = item.title.replace('"', '`"')
        rem_code = item.remediation.strip()

        code_lines = []
        for line in rem_code.splitlines():
            l_str = line.strip()
            if not l_str:
                continue
            l_lower = l_str.lower()
            is_cmd = any(l_lower.startswith(prefix) for prefix in ("winget", "set-", "new-", "enable-", "disable-", "reg", "netsh", "auditpol", "sc.exe", "sc ", "takeown", "icacls", "secedit", "&", "$", "get-", "remove-", "start-", "stop-", "restart-"))
            if is_cmd:
                code_lines.append(l_str)
            else:
                code_lines.append(f"# {l_str}")

        if not code_lines:
            continue

        cmd_block = "\n        ".join(code_lines)

        script_lines.append(f'Apply-Fix -Id "{item.id}" -Title "{clean_title}" -Severity "{item.severity.value}" -Description "{clean_desc}" -CommandBlock {{')
        script_lines.append(f"        {cmd_block}")
        script_lines.append("    }")
        script_lines.append("")

    script_lines.extend([
        'Write-Host "==========================================================================" -ForegroundColor Green',
        'Write-Host "  Tüm seçilen güvenlik düzeltmeleri tamamlandı!" -ForegroundColor Green',
        'Write-Host "  Değişiklikleri görmek için CyberAudit PC arayüzünden tekrar tarama yapın." -ForegroundColor Cyan',
        'Write-Host "==========================================================================" -ForegroundColor Green'
    ])

    return "\n".join(script_lines)


def calculate_top_remediations(report: ScanReport) -> List[dict]:
    """
    Tenable Nessus 'Top Remediations' algoritmasını uygulayarak,
    sistem risk puanını en yüksek oranda düşürecek ilk 5 kritik düzeltmeyi hesaplar.
    """
    from core.plugin_model import PLUGIN_METADATA_MAP

    # 1. Başarısız kontrolleri modül/aksiyon bazında grupla
    module_actions: dict = {}
    total_system_risk_score = 0.0

    for cat in report.categories:
        for c in cat.checks:
            if c.status in [Status.FAIL, Status.WARNING]:
                meta = PLUGIN_METADATA_MAP.get(c.id, {})
                cvss = meta.get("cvss", 7.0 if c.severity == Severity.CRITICAL else (5.0 if c.severity == Severity.HIGH else 3.0))
                vpr = meta.get("vpr", cvss * 0.95)
                risk_weight = cvss * 1.5 if meta.get("exploit") else cvss
                total_system_risk_score += risk_weight

                if cat.module_id not in module_actions:
                    module_actions[cat.module_id] = {
                        "module_id": cat.module_id,
                        "module_name": cat.module_name,
                        "category": cat.category,
                        "vulns": [],
                        "total_cvss": 0.0,
                        "total_risk": 0.0,
                        "remediations": []
                    }

                module_actions[cat.module_id]["vulns"].append({
                    "id": c.id,
                    "title": c.title,
                    "severity": c.severity.value,
                    "cvss": cvss,
                    "vpr": round(vpr, 1),
                    "remediation": c.remediation
                })
                module_actions[cat.module_id]["total_cvss"] += cvss
                module_actions[cat.module_id]["total_risk"] += risk_weight
                if c.remediation and c.remediation not in module_actions[cat.module_id]["remediations"]:
                    module_actions[cat.module_id]["remediations"].append(c.remediation)

    if total_system_risk_score == 0:
        return []

    # 2. Aksiyonları sağladıkları risk azaltma yüzdesine göre sırala
    ranked_actions = []
    for m_id, data in module_actions.items():
        reduction_pct = round((data["total_risk"] / total_system_risk_score) * 100, 1)
        ranked_actions.append({
            "module_id": m_id,
            "action_title": f"{data['module_name']} Sıkılaştırması ({data['category']})",
            "vuln_count": len(data["vulns"]),
            "vulns": data["vulns"],
            "cvss_saved": round(data["total_cvss"], 1),
            "risk_reduction_pct": reduction_pct,
            "solution_summary": f"Bu modüldeki {len(data['vulns'])} güvenlik açığı giderildiğinde genel risk %{reduction_pct} oranında azalacaktır.",
            "remediations": data["remediations"]
        })

    ranked_actions.sort(key=lambda x: x["risk_reduction_pct"], reverse=True)

    # İlk 5 aksiyona sıra numarası ekle
    top_5 = ranked_actions[:5]
    for idx, act in enumerate(top_5, 1):
        act["rank"] = idx

    return top_5

