import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.base import BaseModule, CheckItem, Severity, Status


class SecretScanModule(BaseModule):
    """
    Yerel sistemde, kullanıcı ev dizininde, geliştirici çalışma alanlarında
    ve komut geçmişinde açıkta kalan kimlik bilgilerini, özel anahtarları
    ve API token'larını denetleyen modül (Gitleaks / TruffleHog standardı).
    """
    id: str = "secret_scan"
    name: str = "Kimlik Bilgisi ve Gizli Anahtar Taraması"
    description: str = "Açıkta kalan SSH anahtarları, bulut kimlikleri (.aws, .kube), .env sırları ve terminal geçmişi sızıntılarını denetler."
    category: str = "Veri Güvenliği"
    weight: int = 15
    enabled: bool = True
    author: str = "CyberAudit Team"
    version: str = "2.0.0"

    def run_checks(self) -> List[CheckItem]:
        checks = []
        user_home = Path(os.environ.get("USERPROFILE", os.path.expanduser("~")))

        # 1. SSH Özel Anahtarları Kontrolü (SEC-01)
        checks.append(self._check_ssh_keys(user_home))

        # 2. Bulut ve Konteyner Yapılandırma Dosyaları (SEC-02)
        checks.append(self._check_cloud_credentials(user_home))

        # 3. Geliştirici Çalışma Alanlarında .env ve API Sırları (SEC-03)
        checks.append(self._check_env_secrets(user_home))

        # 4. PowerShell Komut Satırı Geçmişinde Düz Metin Parolalar (SEC-04)
        checks.append(self._check_powershell_history())

        # 5. Git Yapılandırmasında Açık Token / Kimlik Bilgileri (SEC-05)
        checks.append(self._check_git_credentials(user_home))

        return checks

    def _check_ssh_keys(self, user_home: Path) -> CheckItem:
        """Kullanıcının .ssh dizinindeki özel anahtarları inceler."""
        ssh_dir = user_home / ".ssh"
        unencrypted_keys = []
        found_keys = []

        key_names = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]

        if ssh_dir.exists() and ssh_dir.is_dir():
            try:
                for file_path in ssh_dir.iterdir():
                    if file_path.is_file() and not file_path.name.endswith(".pub") and not file_path.name.endswith(".ppk"):
                        # Dosyanın ilk satırını oku
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read(1024)
                                if "PRIVATE KEY-----" in content:
                                    found_keys.append(file_path.name)
                                    # Parola ile şifrelenmiş mi? (ENCRYPTED veya Proc-Type: 4,ENCRYPTED)
                                    if "ENCRYPTED" not in content and "aes256-cbc" not in content and "bcrypt" not in content:
                                        unencrypted_keys.append(file_path.name)
                        except Exception:
                            pass
            except Exception:
                pass

        if unencrypted_keys:
            return CheckItem(
                id="SEC-01",
                title="Şifrelenmemiş SSH Özel Anahtarları (SSH Private Keys)",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value=f"{len(unencrypted_keys)} adet şifrelenmemiş özel anahtar: {', '.join(unencrypted_keys)}",
                recommended_value="Tüm SSH özel anahtarları güçlü bir parola (passphrase) ile korunmalıdır",
                description="Kullanıcı ev dizininde (.ssh) parolasız şifrelenmemiş özel anahtar bulundu. Bilgisayara erişen veya kötü amaçlı yazılım bu anahtarları doğrudan çalarak uzak sunuculara yetkisiz erişim sağlayabilir.",
                remediation="Özel anahtarlarınızı şifrelemek için: ssh-keygen -p -f ~/.ssh/<anahtar_adı>",
                standard_ref="CWE-312: Cleartext Storage of Sensitive Information | CIS Controls v8 (3.11)"
            )
        elif found_keys:
            return CheckItem(
                id="SEC-01",
                title="Şifrelenmemiş SSH Özel Anahtarları (SSH Private Keys)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value=f"{len(found_keys)} adet SSH anahtarı bulundu (Parola ile şifreli/korumalı)",
                recommended_value="Tüm SSH özel anahtarları güçlü bir parola ile korunmalıdır",
                description="Tespit edilen SSH özel anahtarları parola korumalı görünüyor.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-312 | CIS Controls v8 (3.11)"
            )
        else:
            return CheckItem(
                id="SEC-01",
                title="Şifrelenmemiş SSH Özel Anahtarları (SSH Private Keys)",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Yerel .ssh dizininde özel anahtar bulunamadı",
                recommended_value="Özel anahtarlar parola ile korunmalıdır",
                description="Sistemde açıkta kalan SSH özel anahtarı bulunamadı.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-312 | CIS Controls v8 (3.11)"
            )

    def _check_cloud_credentials(self, user_home: Path) -> CheckItem:
        """AWS, Azure, Kubernetes ve Docker kimlik dosyalarını kontrol eder."""
        cloud_files = {
            "AWS Kimlik Bilgileri": user_home / ".aws" / "credentials",
            "Kubernetes Config": user_home / ".kube" / "config",
            "Azure Oturum Dosyası": user_home / ".azure" / "azureProfile.json",
            "Docker Kimlikleri": user_home / ".docker" / "config.json"
        }

        exposed = []
        for name, path in cloud_files.items():
            if path.exists() and path.is_file():
                try:
                    size = path.stat().st_size
                    if size > 10:
                        exposed.append(f"{name} ({path.name})")
                except Exception:
                    pass

        if exposed:
            return CheckItem(
                id="SEC-02",
                title="Açıkta Kalan Bulut & Konteyner Kimlik Dosyaları",
                severity=Severity.HIGH,
                status=Status.WARNING,
                current_value=f"Tespit edilen dosyalar: {', '.join(exposed)}",
                recommended_value="Bulut kimlikleri ortam değişkenleri (SSO/IAM roles) ile geçici olarak sağlanmalıdır",
                description="Kullanıcı ev dizininde düz metin AWS, Kubernetes veya Docker kimlik dosyaları bulundu. Bu dosyalar uç nokta ele geçirildiğinde bulut altyapısına doğrudan sızma (cloud pivoting) riski taşır.",
                remediation="Kalıcı Access Key yerine AWS IAM Identity Center (SSO) veya geçici oturum jetonları (STS) kullanın.",
                standard_ref="CWE-522: Insufficiently Protected Credentials | MITRE ATT&CK T1552.001"
            )
        else:
            return CheckItem(
                id="SEC-02",
                title="Açıkta Kalan Bulut & Konteyner Kimlik Dosyaları",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Yerel ev dizininde açıkta kalan bulut/k8s/docker kimlik dosyası bulunamadı",
                recommended_value="Bulut kimlikleri geçici yetkilendirme (SSO) ile yönetilmelidir",
                description="Sistemde düz metin bulut kimlik yapılandırma dosyası tespit edilmedi.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-522 | MITRE ATT&CK T1552.001"
            )

    def _check_env_secrets(self, user_home: Path) -> CheckItem:
        """
        Kullanıcı çalışma alanlarında (.env) dosyalarında açık API anahtarı arar.
        Hız için sadece yaygın geliştirici klasörlerini (max depth 2) tarar.
        """
        search_dirs = [
            user_home / "Desktop",
            user_home / "Documents",
            user_home / "Downloads",
            user_home / "source" / "repos",
            user_home / "Projects",
            user_home / "workspace",
            user_home / "code"
        ]

        secret_patterns = [
            (re.compile(r'(?i)(?:aws_secret_access_key|aws_access_key_id)\s*=\s*["\']?([A-Za-z0-9/+=]{16,40})["\']?'), "AWS Access Key"),
            (re.compile(r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})'), "GitHub Personal Access Token"),
            (re.compile(r'sk-[a-zA-Z0-9]{32,64}'), "OpenAI / LLM API Key"),
            (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), "Slack Token"),
            (re.compile(r'(?i)(?:password|secret|apikey|api_key)\s*=\s*["\']?([^"\'\s]{8,64})["\']?'), "Düz Metin API Anahtarı/Parola")
        ]

        found_secrets: List[str] = []
        scanned_files_count = 0

        for base_dir in search_dirs:
            if not base_dir.exists() or not base_dir.is_dir():
                continue

            try:
                for root, dirs, files in os.walk(base_dir):
                    # node_modules, .git, venv atla
                    dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build')]
                    # Derinlik sınırla (en fazla 2 seviye)
                    rel_depth = len(Path(root).relative_to(base_dir).parts)
                    if rel_depth > 2:
                        continue

                    for file in files:
                        if file == ".env" or file.endswith(".env.local") or file.endswith(".env.production"):
                            scanned_files_count += 1
                            file_path = Path(root) / file
                            try:
                                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                    lines = f.readlines()
                                    for line_idx, line in enumerate(lines[:100], 1):
                                        for pattern, label in secret_patterns:
                                            match = pattern.search(line)
                                            if match:
                                                # Örnek maskeli tespit
                                                val = match.group(1) if match.groups() else match.group(0)
                                                masked = val[:4] + "..." + val[-3:] if len(val) > 7 else "***"
                                                found_secrets.append(f"{file_path.name} (Satır {line_idx}: {label} [{masked}])")
                                                break
                            except Exception:
                                pass
            except Exception:
                pass

        if found_secrets:
            return CheckItem(
                id="SEC-03",
                title="Geliştirici Çalışma Alanlarında .env ve Gizli Anahtar Sızıntısı",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value=f"{len(found_secrets)} adet sızıntı tespit edildi: {', '.join(found_secrets[:4])}",
                recommended_value="API anahtarları ve sırlar yerel dosyalarda düz metin saklanmamalıdır",
                description="Geliştirici klasörlerinde (.env) dosyalarında açık API anahtarları veya parolalar bulundu (Gitleaks standardı). Bu dosyalar kazara Git'e gönderilebilir veya yerel yazılımlarca çalınabilir.",
                remediation="Hassas anahtarları .env.vault, HashiCorp Vault veya Windows Credential Manager ile şifreleyin ve .gitignore dosyanıza .env ekleyin.",
                standard_ref="CWE-798: Use of Hard-coded Credentials | OWASP Top 10 (A07:2021-Identification and Authentication Failures)"
            )
        else:
            return CheckItem(
                id="SEC-03",
                title="Geliştirici Çalışma Alanlarında .env ve Gizli Anahtar Sızıntısı",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value=f"Taranan dizinlerde açıkta kalan .env sırrı bulunamadı ({scanned_files_count} .env dosyası incelendi)",
                recommended_value="Gizli anahtarlar şifreli kasalarda saklanmalıdır",
                description="Geliştirici alanlarında şifrelenmemiş kritik API anahtarı veya sızıntı tespit edilmedi.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-798 | OWASP Top 10 (A07:2021)"
            )

    def _check_powershell_history(self) -> CheckItem:
        """PowerShell PSReadLine komut geçmişini tarar."""
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            return CheckItem(
                id="SEC-04",
                title="PowerShell Komut Satırı Geçmişi Sızıntı Denetimi",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="APPDATA dizini okunamadı",
                recommended_value="Komut satırında düz metin parola girilmemelidir",
                description="PowerShell geçmiş dosyası konumu doğrulanamadı.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-532: Insertion of Sensitive Information into Log File"
            )

        hist_path = Path(appdata) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        if not hist_path.exists():
            return CheckItem(
                id="SEC-04",
                title="PowerShell Komut Satırı Geçmişi Sızıntı Denetimi",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="PowerShell geçmiş dosyası boş veya mevcut değil",
                recommended_value="Komut satırında düz metin parola girilmemelidir",
                description="Sistemde kaydedilmiş PowerShell komut geçmişi dosyası bulunamadı.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-532"
            )

        sensitive_keywords = ["password", "-pass ", "net use ", "convertto-securestring", "token", "apikey", "api_key", "secret"]
        leaks_found = []

        try:
            with open(hist_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                for idx, line in enumerate(lines[-200:], 1):  # Son 200 komut
                    lower = line.lower()
                    for kw in sensitive_keywords:
                        if kw in lower and len(line.strip()) > 10:
                            leaks_found.append(f"Komut #{idx}: '{line.strip()[:40]}...'")
                            break
        except Exception:
            pass

        if leaks_found:
            return CheckItem(
                id="SEC-04",
                title="PowerShell Komut Satırı Geçmişinde Hassas Veri Sızıntısı",
                severity=Severity.MEDIUM,
                status=Status.WARNING,
                current_value=f"{len(leaks_found)} şüpheli komut tespit edildi (ör: {leaks_found[0]})",
                recommended_value="Komut satırında parola/token parametre olarak geçilmemelidir",
                description="PowerShell PSReadLine komut geçmişinde (ConsoleHost_history.txt) düz metin parola, token veya ağ bağlantı kimlik bilgisi tespit edildi.",
                remediation="Geçmişi temizlemek için PowerShell'de: Clear-History; Remove-Item (Get-PSReadLineOption).HistorySavePath",
                standard_ref="CWE-532: Insertion of Sensitive Information into Log File | MITRE ATT&CK T1552.003"
            )
        else:
            return CheckItem(
                id="SEC-04",
                title="PowerShell Komut Satırı Geçmişinde Hassas Veri Sızıntısı",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                current_value="PowerShell geçmişinde açıkta kalan parola veya jeton tespit edilmedi",
                recommended_value="Komut geçmişinde hassas veri bulunmamalıdır",
                description="PowerShell komut geçmişinde düz metin kimlik bilgisi bulunamadı.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-532 | MITRE ATT&CK T1552.003"
            )

    def _check_git_credentials(self, user_home: Path) -> CheckItem:
        """Kullanıcının .gitconfig ve .git-credentials dosyalarını denetler."""
        git_creds = user_home / ".git-credentials"
        git_config = user_home / ".gitconfig"
        issues = []

        if git_creds.exists():
            try:
                with open(git_creds, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if "http" in content and ":" in content and "@" in content:
                        issues.append(".git-credentials dosyasında düz metin URL ve parola saklanıyor")
            except Exception:
                pass

        if git_config.exists():
            try:
                with open(git_config, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if "helper = store" in content:
                        issues.append("Git credential.helper = store yapılandırılmış (Düz metin saklama modu)")
            except Exception:
                pass

        if issues:
            return CheckItem(
                id="SEC-05",
                title="Git Kimlik Bilgilerinin Düz Metin Saklanması",
                severity=Severity.HIGH,
                status=Status.FAIL,
                current_value=f"Tespit edilen risk: {'; '.join(issues)}",
                recommended_value="Git kimlik bilgileri Windows Kimlik Yöneticisi (Git Credential Manager) ile şifrelenmelidir",
                description="Git istemcisi parolaları veya kişisel erişim jetonlarını düz metin olarak diskte saklıyor. Git Credential Manager Core kullanılarak Windows Credential Manager'a taşınmalıdır.",
                remediation="PowerShell'de: git config --global credential.helper manager",
                standard_ref="CWE-312: Cleartext Storage of Sensitive Information | CIS Controls v8 (3.11)"
            )
        else:
            return CheckItem(
                id="SEC-05",
                title="Git Kimlik Bilgilerinin Düz Metin Saklanması",
                severity=Severity.HIGH,
                status=Status.PASS,
                current_value="Düz metin Git kimlik saklama tespit edilmedi",
                recommended_value="Git kimlik bilgileri Git Credential Manager ile korunmalıdır",
                description="Git kimlik bilgileri güvenli yapılandırılmış görünüyor.",
                remediation="Ek işlem gerekmez.",
                standard_ref="CWE-312 | CIS Controls v8 (3.11)"
            )
