import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routes import router as api_router
from core.engine import AuditEngine
from core.base import Status, Severity

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Windows Terminal UTF-8 Uyumluluğu
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = FastAPI(
    title="KALKAN",
    description="Gelişmiş Windows Uç Nokta Güvenlik Denetim ve Sıkılaştırma Platformu",
    version="3.0.0"
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web")), name="static")
app.include_router(api_router)


@app.get("/")
def serve_index(response: Response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return FileResponse(str(BASE_DIR / "web" / "index.html"), headers=response.headers)


def open_browser_delayed(url: str, delay: float = 1.2):
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def run_cli_audit(
    output_format: str = "console",
    output_file: Optional[str] = None,
    fail_on_critical: bool = True,
    fail_on_high: bool = False
):
    """Terminal üzerinden komut satırı taraması gerçekleştirir, SARIF/SBOM/JSON/HTML çıktısı üretir."""
    import json
    from core.exporter import generate_html_report, generate_sarif_report, generate_cyclonedx_sbom

    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        has_rich = True
    except ImportError:
        has_rich = False

    engine = AuditEngine()
    if output_format == "console":
        print("\n[+] CyberAudit PC Güvenlik Taraması Başlatılıyor...")

    start_time = time.time()
    report = engine.run_scan()
    duration = round(time.time() - start_time, 2)

    # İstenen formata göre içerik hazırla
    content_to_save = ""
    if output_format == "json":
        content_to_save = json.dumps(report.model_dump(), indent=2, ensure_ascii=False)
        if not output_file:
            print(content_to_save)
    elif output_format == "sarif":
        sarif_doc = generate_sarif_report(report)
        content_to_save = json.dumps(sarif_doc, indent=2, ensure_ascii=False)
        if not output_file:
            print(content_to_save)
    elif output_format == "sbom":
        sbom_doc = generate_cyclonedx_sbom(report)
        content_to_save = json.dumps(sbom_doc, indent=2, ensure_ascii=False)
        if not output_file:
            print(content_to_save)
    elif output_format == "html":
        content_to_save = generate_html_report(report)
        if not output_file:
            print(f"[+] HTML rapor oluşturuldu ({len(content_to_save)} bayt). --output ile dosyaya kaydedin.")
    else:  # console
        if has_rich:
            console = Console(highlight=False)

            # Skor Paneli
            score_color = "green" if report.total_score >= 85 else ("cyan" if report.total_score >= 70 else ("yellow" if report.total_score >= 50 else "red"))
            score_panel = Panel(
                f"[bold {score_color}]GÜVENLİK İNDEKSİ: {report.total_score} / 100[/bold {score_color}]\n"
                f"Toplam Kontrol: {report.total_checks} | Başarılı: {report.passed_count} | Kritik: [red]{report.critical_count}[/red] | Yüksek: [orange3]{report.high_count}[/orange3] | Orta: [yellow]{report.medium_count}[/yellow]\n"
                f"Cihaz: {report.hostname} | OS: {report.os_info} | Süre: {duration}s",
                title="[bold][CYBERAUDIT PC] Güvenlik Denetim ve Zafiyet Özeti (OWASP Standart)[/bold]",
                border_style=score_color
            )
            console.print(score_panel)

            # Bulgular Tablosu
            table = Table(title="\nTespit Edilen Riskler, Zafiyetler ve Uyumsuzluklar", border_style="dim")
            table.add_column("ID", style="cyan", width=8)
            table.add_column("Kural Başlığı", style="bold", width=34)
            table.add_column("Seviye", width=12)
            table.add_column("Mevcut Durum", width=28)
            table.add_column("Önerilen Güvenli Değer", style="dim", width=24)

            risk_count = 0
            for cat in report.categories:
                for c in cat.checks:
                    if c.status != Status.PASS:
                        risk_count += 1
                        sev_style = "red bold" if c.severity == Severity.CRITICAL else ("orange3 bold" if c.severity == Severity.HIGH else "yellow")
                        table.add_row(
                            c.id,
                            c.title,
                            f"[{sev_style}]{c.severity.value}[/{sev_style}]",
                            c.current_value[:35] + "..." if len(c.current_value) > 35 else c.current_value,
                            c.recommended_value[:30] + "..." if len(c.recommended_value) > 30 else c.recommended_value
                        )

            if risk_count > 0:
                console.print(table)
                console.print(f"\n[yellow]Toplam {risk_count} adet sıkılaştırma gerektiren kural tespit edildi.[/yellow]")
            else:
                console.print("\n[green]Tebrikler! Sistemde herhangi bir güvenlik zafiyeti tespit edilmedi.[/green]\n")

        else:
            print("\n" + "=" * 60)
            print(f"  GÜVENLİK SKORU : {report.total_score} / 100")
            print(f"  Toplam Denetim : {report.total_checks} (Geçen: {report.passed_count}, Kritik: {report.critical_count}, Yüksek: {report.high_count})")
            print("=" * 60)

    # Dosyaya kaydetme istenmişse
    if output_file and content_to_save:
        out_path = Path(output_file)
        out_path.write_text(content_to_save, encoding="utf-8")
        print(f"[✓] Rapor başarıyla kaydedildi: {out_path.resolve()}")

    # Çıkış kodu (CI/CD Exit Code) değerlendirmesi
    should_fail = False
    if fail_on_high and (report.critical_count > 0 or report.high_count > 0):
        should_fail = True
    elif fail_on_critical and report.critical_count > 0:
        should_fail = True

    if should_fail:
        if output_format == "console":
            print(f"[!] CI/CD Kural İhlali: Sistemde {report.critical_count} kritik, {report.high_count} yüksek zafiyet bulundu. Çıkış kodu: 1")
        sys.exit(1)
    else:
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="CyberAudit PC - Gelişmiş Güvenlik Denetim ve Sıkılaştırma Platformu")
    parser.add_argument("--cli", action="store_true", help="Web arayüzü yerine terminalde hızlı CLI/CI-CD taraması yap")
    parser.add_argument("--format", choices=["console", "json", "sarif", "html", "sbom"], default="console", help="Çıktı formatı (varsayılan: console)")
    parser.add_argument("--output", "-o", help="Raporun kaydedileceği dosya yolu (örn: results.sarif)")
    parser.add_argument("--fail-on-critical", action="store_true", default=True, help="Kritik zafiyet varsa exit 1 ile çık (CI/CD)")
    parser.add_argument("--fail-on-high", action="store_true", help="Yüksek veya kritik zafiyet varsa exit 1 ile çık (CI/CD)")
    parser.add_argument("--export-sbom", help="Doğrudan CycloneDX SBOM dosyası üretir ve çıkar (örn: --export-sbom sbom.json)")
    parser.add_argument("--host", default="127.0.0.1", help="Bağlanılacak host (varsayılan: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port numarası (varsayılan: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Tarayıcıyı otomatik açma")

    args = parser.parse_args()

    if args.export_sbom:
        run_cli_audit(output_format="sbom", output_file=args.export_sbom, fail_on_critical=False)
        return

    if args.cli:
        run_cli_audit(
            output_format=args.format,
            output_file=args.output,
            fail_on_critical=args.fail_on_critical,
            fail_on_high=args.fail_on_high
        )
        return

    print("\n" + "=" * 68)
    print("      🛡️  CyberAudit PC v2.0 - OWASP Uyumlu PC Güvenlik Platformu")
    print("=" * 68)
    print("  [+] Mimari       : Eklenti Tabanlı (Pluggable BaseModule)")
    print("  [+] Kapsam       : 15 Güvenlik Kategorisi, 73+ Derin Kontrol")
    print("  [+] Standartlar  : OASIS SARIF v2.1.0, CycloneDX v1.5 SBOM, CWE, CIS v8")
    print("  [+] Modül Hub    : Bağımsız Modül Taraması & Özel Düzeltme Betikleri")
    print("  [+] Doğrulama    : Tekil Kontrol Canlı Düzeltme Doğrulama (Verify Fix)")
    print(f"  [+] Web Adresi   : http://{args.host}:{args.port}")
    print("=" * 68)
    print("  Sunucu çalışıyor... Tarayıcınız otomatik açılacaktır.")
    print("  Durdurmak için terminalde CTRL+C tuşlarına basabilirsiniz.\n")

    if not args.no_browser:
        t = threading.Thread(target=open_browser_delayed, args=(f"http://{args.host}:{args.port}",))
        t.daemon = True
        t.start()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="warning"
    )


if __name__ == "__main__":
    main()

