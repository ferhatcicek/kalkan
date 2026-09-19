import winreg
import re
from typing import List, Dict, Any, Optional
from core.base import BaseModule, CheckItem, Severity, Status


class SoftwareInventoryModule(BaseModule):
    """
    Yüklü yazılımları, bileşenleri, bilinen zafiyetli ve EOL (ömrü bitmiş)
    sürümleri denetleyen ve CycloneDX SBOM standardı için veri üreten modül
    (OWASP Dependency-Check / BomLens standardı).
    """
    id: str = "software_inventory"
    name: str = "Yazılım Bileşen Analizi (SCA) & SBOM"
    description: str = "Yüklü 3. parti yazılımların envanterini çıkarır, bilinen kritik CVE zafiyetli/eski sürümleri ve EOL yazılımları tespit eder."
    category: str = "Yazılım Güvenliği"
    weight: int = 15
    enabled: bool = True
    author: str = "CyberAudit Team"
    version: str = "2.0.0"

    def run_checks(self) -> List[CheckItem]:
        installed_apps = self._get_installed_software()

        checks = []
        # 1. Yazılım Envanteri (SCA-01)
        checks.append(self._check_software_count(installed_apps))

        # 2. Bilinen Kritik Zafiyetli Yazılım Sürümleri (SCA-02)
        checks.append(self._check_vulnerable_software(installed_apps))

        # 3. Destek Ömrü Biten (End-of-Life - EOL) Yazılımlar (SCA-03)
        checks.append(self._check_eol_software(installed_apps))

        # 4. SBOM ve Bileşen Bütünlüğü (SCA-04)
        checks.append(self._check_sbom_readiness(installed_apps))

        return checks

    def _get_installed_software(self) -> List[Dict[str, str]]:
        """Windows Registry üzerinden 32-bit ve 64-bit yüklü tüm programları listeler."""
        software_list: List[Dict[str, str]] = []
        registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
        ]

        seen_names = set()

        for hkey, subkey, access_flag in registry_keys:
            try:
                access = winreg.KEY_READ | access_flag if access_flag else winreg.KEY_READ
                with winreg.OpenKey(hkey, subkey, 0, access) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as app_key:
                                def get_val(val_name):
                                    try:
                                        val, _ = winreg.QueryValueEx(app_key, val_name)
                                        return str(val).strip()
                                    except Exception:
                                        return ""

                                display_name = get_val("DisplayName")
                                display_version = get_val("DisplayVersion")
                                publisher = get_val("Publisher")
                                install_date = get_val("InstallDate")

                                # Sistem güncellemelerini ve boş girdileri filtrele
                                if not display_name or display_name.startswith("KB") or "Security Update" in display_name:
                                    continue

                                # SystemComponent = 1 olan gizli bileşenleri atla
                                if get_val("SystemComponent") == "1":
                                    continue

                                unique_key = f"{display_name.lower()}_{display_version}"
                                if unique_key not in seen_names:
                                    seen_names.add(unique_key)
                                    software_list.append({
                                        "name": display_name,
                                        "version": display_version or "Bilinmiyor",
                                        "publisher": publisher or "Bilinmiyor",
                                        "install_date": install_date or "Bilinmiyor"
                                    })
                        except Exception:
                            continue
            except Exception:
                continue

        software_list.sort(key=lambda x: x["name"].lower())
        return software_list

    def _parse_version(self, version_str: str) -> List[int]:
        """Sürüm dizesini sayı listesine dönüştürür (örn: '22.01' -> [22, 1])."""
        numbers = re.findall(r'\d+', version_str)
        return [int(n) for n in numbers[:4]] if numbers else [0]

    def _check_software_count(self, apps: List[Dict[str, str]]) -> CheckItem:
        """Yüklü yazılım sayısını ve envanterini doğrular."""
        total = len(apps)

        return CheckItem(
            id="SCA-01",
            title="Yüklü 3. Parti Yazılım Envanteri (Software Inventory)",
            severity=Severity.INFO,
            status=Status.PASS,
            current_value=f"Sistemde toplam {total} adet 3. parti yazılım tespit edildi ve eksiksiz SBOM envanterine işlendi.",
            recommended_value="Tüm kurulu yazılımlar onaylı kurumsal yazılım envanterinde kayıtlı olmalıdır",
            description=f"Sistem kayıt defterinde (Registry) toplam {total} adet 3. parti yazılım tespit edildi. SCA ve SBOM analizi için eksiksiz envanter sağlandı.",
            remediation="Düzenli olarak kullanılmayan yazılımları kaldırarak saldırı yüzeyini daraltın.",
            standard_ref="CIS Controls v8 (2.1 - Establish and Maintain a Software Inventory)",
            details={"software_count": total, "applications": apps}
        )

    def _check_vulnerable_software(self, apps: List[Dict[str, str]]) -> CheckItem:
        """Sık kullanılan ve bilinen kritik CVE zafiyetine sahip eski sürümleri denetler."""
        # Bilinen kritik açık içeren sürümler veritabanı
        # format: (uygulama_adı_deseni, güvenli_minimum_sürüm, cve_id, açıklama)
        vuln_definitions = [
            ("opera", [136, 0], "CVE-2024-43093 / Chromium V8 RCE", "Opera 136 öncesi sürümlerde Chromium tabanlı bellek bozulması ve uzaktan kod çalıştırma açıkları bulunmaktadır."),
            ("google chrome", [130, 0], "CVE-2024-0519 / CVE-2023-4863", "Eski Chrome sürümlerinde WebP bellek taşması ve V8 uzaktan kod çalıştırma zafiyetleri vardır."),
            ("firefox", [130, 0], "CVE-2024-9680", "Eski Firefox sürümlerinde Animation timeline bellek yönetimi kritik zero-day açığı vardır."),
            ("7-zip", [23, 1], "CVE-2023-31102 / CVE-2022-29072", "7-Zip 23.01 öncesi sürümlerde ayrıcalık yükseltme ve bellek taşması açıkları bulunmaktadır."),
            ("winrar", [6, 23], "CVE-2023-38831", "WinRAR 6.23 öncesi sürümlerde tıklandığında uzaktan kod çalıştıran kritik zero-day açığı vardır."),
            ("notepad++", [8, 5, 7], "CVE-2023-40031", "Notepad++ 8.5.7 öncesi sürümlerde bellek bozulması ve yetkisiz kod yürütme açığı vardır."),
            ("vlc media player", [3, 0, 19], "CVE-2023-47359", "VLC 3.0.19 öncesi sürümlerde kötü amaçlı medya dosyalarıyla kod çalıştırma riski vardır."),
            ("git", [2, 40, 1], "CVE-2023-25652", "Git 2.40.1 öncesi sürümlerde özel hazırlanmış depo klonlama ile komut çalıştırma açığı vardır.")
        ]

        vulnerable_found = []

        for app in apps:
            name_lower = app["name"].lower()
            version_str = app["version"]
            parsed_ver = self._parse_version(version_str)

            for target_name, min_ver, cve, desc in vuln_definitions:
                if re.search(r'\b' + re.escape(target_name) + r'\b', name_lower) and parsed_ver != [0]:
                    # Karşılaştır
                    is_older = False
                    for i in range(max(len(parsed_ver), len(min_ver))):
                        v_cur = parsed_ver[i] if i < len(parsed_ver) else 0
                        v_min = min_ver[i] if i < len(min_ver) else 0
                        if v_cur < v_min:
                            is_older = True
                            break
                        elif v_cur > v_min:
                            break

                    if is_older:
                        vulnerable_found.append(f"{app['name']} (Sürüm: {version_str} < Asgari: {'.'.join(map(str, min_ver))}) [{cve}]")

        if vulnerable_found:
            vuln_lines = "\n".join([f"• {v}" for v in vulnerable_found])
            return CheckItem(
                id="SCA-02",
                title="Bilinen Kritik Zafiyetli Yazılım Sürümleri (Known Exploited CVEs)",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                current_value=f"{len(vulnerable_found)} adet kritik CVE zafiyetli yazılım tespit edildi:\n{vuln_lines}",
                recommended_value="Tüm 3. parti yazılımlar güncel ve zafiyetsiz sürümlere yükseltilmelidir",
                description="Sistemde genel olarak bilinen, istismar edilmiş (CISA KEV / NVD) kritik CVE güvenlik açıklarına sahip eski yazılım sürümleri tespit edildi.",
                remediation="Tespit edilen yazılımları en son stabil sürüme derhal güncelleyin veya kaldırın.",
                standard_ref="CWE-1035: Vulnerable Third Party Component | OWASP Top 10 (A06:2021-Vulnerable and Outdated Components)",
                details={"vulnerabilities": vulnerable_found}
            )
        else:
            return CheckItem(
                id="SCA-02",
                title="Bilinen Kritik Zafiyetli Yazılım Sürümleri (Known Exploited CVEs)",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                current_value="Bilinen yüksek riskli/eski popüler yazılım sürümü tespit edilmedi",
                recommended_value="Yazılımlar daima güncel tutulmalıdır",
                description="Popüler uygulamalarda bilinen kritik zero-day/CVE zafiyetli eski sürüm tespit edilmedi.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-1035 | OWASP Top 10 (A06:2021)"
            )

    def _check_eol_software(self, apps: List[Dict[str, str]]) -> CheckItem:
        """Destek ömrü (EOL) dolmuş ve üreticisi tarafından güvenlik yaması almayan yazılımları denetler."""
        eol_signatures = [
            ("python 2.", "Python 2.x (Destek 1 Ocak 2020'de bitti)"),
            ("python 3.6", "Python 3.6 (EOL - Güvenlik desteği bitti)"),
            ("python 3.7", "Python 3.7 (EOL - Güvenlik desteği bitti)"),
            ("adobe flash player", "Adobe Flash Player (Resmi olarak sonlandırıldı)"),
            ("silverlight", "Microsoft Silverlight (Destek Ekim 2021'de bitti)"),
            ("microsoft office 2010", "Office 2010 (EOL - Güvenlik yaması almıyor)"),
            ("microsoft office 2007", "Office 2007 (EOL - Güvenlik yaması almıyor)"),
            ("java(tm) 6", "Java SE 6 (Destek ömrü bitti)"),
            ("java(tm) 7", "Java SE 7 (Destek ömrü bitti)"),
            ("internet explorer 10", "Internet Explorer 10 (Sonlandırıldı)")
        ]

        eol_detected = []
        for app in apps:
            full_str = f"{app['name']} {app['version']}".lower()
            for sig, desc in eol_signatures:
                if sig in full_str:
                    eol_detected.append(f"{app['name']} ({desc})")

        if eol_detected:
            return CheckItem(
                id="SCA-03",
                title="Destek Ömrü Biten (End-of-Life) Yazılımlar",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value=f"{len(eol_detected)} adet EOL yazılım tespit edildi: {', '.join(eol_detected)}",
                recommended_value="Destek ömrü biten hiçbir yazılım kullanılmamalı ve kaldırılmalıdır",
                description="Sistemde üreticisi tarafından artık güvenlik güncellemesi almayan (End-of-Life) yazılımlar bulundu. Bu yazılımlarda çıkacak yeni açıklara yama gelmeyeceği için kalıcı güvenlik riski oluştururlar.",
                remediation="EOL olan yazılımları sistemden kaldırın ve desteklenen güncel sürümlerine geçiş yapın.",
                standard_ref="CWE-1104: Use of Unmaintained Third Party Components | CIS Controls v8 (2.2)"
            )
        else:
            return CheckItem(
                id="SCA-03",
                title="Destek Ömrü Biten (End-of-Life) Yazılımlar",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Destek ömrü dolmuş (EOL) kritik yazılım tespit edilmedi",
                recommended_value="Destek ömrü biten yazılımlar sistemden arındırılmalıdır",
                description="Sistemde desteği bitmiş kritik yazılım tespit edilmedi.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-1104 | CIS Controls v8 (2.2)"
            )

    def _check_sbom_readiness(self, apps: List[Dict[str, str]]) -> CheckItem:
        """Sistem yazılımlarının CycloneDX standardı ile SBOM üretilebilirliğini denetler."""
        valid_apps = [a for a in apps if a.get("name") and a.get("version") != "Bilinmiyor"]
        ratio = round((len(valid_apps) / max(1, len(apps))) * 100, 1)

        return CheckItem(
            id="SCA-04",
            title="Yazılım Malzeme Listesi (SBOM - CycloneDX v1.5) Uyumluluğu",
            severity=Severity.LOW,
            status=Status.PASS if ratio >= 70 else Status.WARNING,
            current_value=f"Yazılımların %{ratio}'si doğrulanabilir sürüm etiketine sahip ({len(valid_apps)}/{len(apps)})",
            recommended_value="Tüm sistem bileşenleri standart SBOM formatında belgelenebilir olmalıdır",
            description="OWASP standardında Yazılım Malzeme Listesi (SBOM) oluşturabilmek için yüklü bileşenlerin ad, sürüm ve yayıncı verilerinin eksiksiz olması gereklidir.",
            remediation="Sürüm bilgisi eksik olan gayriresmi veya taşınabilir yazılımları resmi paket yöneticileri (winget, choco) ile yönetin.",
            standard_ref="OWASP Software Component Verification Standard (SCVS) | Executive Order 14028",
            details={"sbom_ready_ratio": ratio, "total_apps": len(apps)}
        )
