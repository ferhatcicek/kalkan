import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from core.base import CheckItem, Severity, Status


class NessusPlugin(BaseModel):
    plugin_id: int
    check_id: str
    name: str
    family: str
    severity: Severity
    cvss_v3_score: float
    cvss_v3_vector: str
    vpr_score: float
    synopsis: str
    description: str
    solution: str
    plugin_output: str = ""
    see_also: List[str] = Field(default_factory=list)
    cpe: Optional[str] = None
    exploit_available: bool = False


# Kapsamlı Nessus Plugin ve CVSS v3.1 Veritabanı Haritası
PLUGIN_METADATA_MAP: Dict[str, Dict[str, Any]] = {
    # 1. Antivirüs & EDR
    "AV-01": {
        "plugin_id": 10101,
        "family": "Windows : Antivirus & EDR",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.2,
        "synopsis": "The remote Windows host is missing real-time antivirus protection.",
        "exploit": True,
        "cpe": "cpe:/a:microsoft:windows_defender"
    },
    "AV-02": {
        "plugin_id": 10102,
        "family": "Windows : Antivirus & EDR",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "vpr": 7.1,
        "synopsis": "Microsoft Defender Cloud-Delivered Protection is disabled.",
        "exploit": False
    },
    "AV-03": {
        "plugin_id": 10103,
        "family": "Windows : Antivirus & EDR",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 8.5,
        "synopsis": "Tamper Protection is disabled, allowing malware to modify antivirus settings.",
        "exploit": True
    },
    "AV-04": {
        "plugin_id": 10104,
        "family": "Windows : Antivirus & EDR",
        "cvss": 7.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "vpr": 6.8,
        "synopsis": "Potentially Unwanted Application (PUA/PUP) blocking is disabled.",
        "exploit": False
    },
    "AV-05": {
        "plugin_id": 10105,
        "family": "Windows : Antivirus & EDR",
        "cvss": 7.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vpr": 7.4,
        "synopsis": "Antivirus signature definitions are out of date.",
        "exploit": True
    },

    # 2. Saldırı Yüzeyi Azaltma (ASR)
    "ASR-01": {
        "plugin_id": 10201,
        "family": "Windows : Attack Surface Reduction",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vpr": 8.7,
        "synopsis": "Office applications are permitted to create child processes (Macro Execution).",
        "exploit": True
    },
    "ASR-02": {
        "plugin_id": 10202,
        "family": "Windows : Attack Surface Reduction",
        "cvss": 9.1,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.0,
        "synopsis": "Credential stealing from LSASS memory is not blocked by ASR.",
        "exploit": True
    },
    "ASR-03": {
        "plugin_id": 10203,
        "family": "Windows : Attack Surface Reduction",
        "cvss": 8.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "vpr": 8.3,
        "synopsis": "Ransomware advanced protection rule is not enforced.",
        "exploit": True
    },
    "ASR-04": {
        "plugin_id": 10204,
        "family": "Windows : Attack Surface Reduction",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "vpr": 7.9,
        "synopsis": "Obfuscated script execution is permitted.",
        "exploit": True
    },
    "ASR-05": {
        "plugin_id": 10205,
        "family": "Windows : Attack Surface Reduction",
        "cvss": 8.2,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "vpr": 8.0,
        "synopsis": "Office applications are allowed to inject code into other processes.",
        "exploit": True
    },

    # 3. Kimlik Bilgisi Koruması & LSASS
    "CG-01": {
        "plugin_id": 10301,
        "family": "Windows : Credentials & Auth",
        "cvss": 9.3,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "vpr": 9.4,
        "synopsis": "Credential Guard (VBS Isolated LSASS) is disabled.",
        "exploit": True
    },
    "CG-02": {
        "plugin_id": 10302,
        "family": "Windows : Credentials & Auth",
        "cvss": 8.6,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 8.8,
        "synopsis": "WDigest plain-text authentication credentials are stored in memory.",
        "exploit": True
    },
    "CG-03": {
        "plugin_id": 10303,
        "family": "Windows : Credentials & Auth",
        "cvss": 8.2,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 8.0,
        "synopsis": "LSASS RunAsPPL protected process light mode is disabled.",
        "exploit": True
    },
    "CG-04": {
        "plugin_id": 10304,
        "family": "Windows : Credentials & Auth",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 7.9,
        "synopsis": "Legacy insecure LM / NTLMv1 authentication protocol is enabled.",
        "exploit": True
    },
    "CG-05": {
        "plugin_id": 10305,
        "family": "Windows : Credentials & Auth",
        "cvss": 6.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 6.2,
        "synopsis": "Domain controller cached logon credentials limit is excessive.",
        "exploit": False
    },

    # 4. Donanım & Çekirdek Güvenliği
    "HW-01": {
        "plugin_id": 10401,
        "family": "Windows : System Hardening",
        "cvss": 8.2,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "vpr": 7.5,
        "synopsis": "TPM (Trusted Platform Module) 2.0 cryptographic chip is missing or disabled.",
        "exploit": False
    },
    "HW-02": {
        "plugin_id": 10402,
        "family": "Windows : System Hardening",
        "cvss": 8.5,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "vpr": 8.0,
        "synopsis": "UEFI Secure Boot is disabled, allowing rootkit/bootkit persistence.",
        "exploit": True
    },
    "HW-03": {
        "plugin_id": 10403,
        "family": "Windows : System Hardening",
        "cvss": 7.8,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 7.2,
        "synopsis": "BitLocker Full Volume Drive Encryption is not enabled.",
        "exploit": True
    },
    "HW-04": {
        "plugin_id": 10404,
        "family": "Windows : System Hardening",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 7.8,
        "synopsis": "Hypervisor-Protected Code Integrity (HVCI) is disabled.",
        "exploit": True
    },
    "HW-05": {
        "plugin_id": 10405,
        "family": "Windows : System Hardening",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 7.0,
        "synopsis": "DMA (Direct Memory Access) bus attack protection is disabled.",
        "exploit": True
    },

    # 5. Güvenlik Duvarı (Firewall)
    "FW-01": {
        "plugin_id": 10501,
        "family": "Windows : Firewall",
        "cvss": 8.6,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 8.4,
        "synopsis": "Windows Domain Firewall Profile is disabled.",
        "exploit": True
    },
    "FW-02": {
        "plugin_id": 10502,
        "family": "Windows : Firewall",
        "cvss": 8.6,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 8.4,
        "synopsis": "Windows Private Network Firewall Profile is disabled.",
        "exploit": True
    },
    "FW-03": {
        "plugin_id": 10503,
        "family": "Windows : Firewall",
        "cvss": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 9.0,
        "synopsis": "Windows Public Network Firewall Profile is disabled.",
        "exploit": True
    },
    "FW-04": {
        "plugin_id": 10504,
        "family": "Windows : Firewall",
        "cvss": 7.2,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "vpr": 6.8,
        "synopsis": "Default inbound firewall connection action is set to allow.",
        "exploit": True
    },

    # 6. Ağ & Paylaşımlar
    "NET-01": {
        "plugin_id": 10601,
        "family": "Windows : Network & Services",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.9,
        "synopsis": "Vulnerable legacy SMBv1 protocol is enabled (EternalBlue / WannaCry risk).",
        "exploit": True
    },
    "NET-02": {
        "plugin_id": 10602,
        "family": "Windows : Network & Services",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 7.4,
        "synopsis": "LLMNR multicast name resolution is enabled (Responder poisoning vulnerability).",
        "exploit": True
    },
    "NET-03": {
        "plugin_id": 10603,
        "family": "Windows : Network & Services",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 7.4,
        "synopsis": "NetBIOS over TCP/IP is enabled on active network adapters.",
        "exploit": True
    },
    "NET-04": {
        "plugin_id": 10604,
        "family": "Windows : Network & Services",
        "cvss": 7.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 7.5,
        "synopsis": "Remote Desktop Protocol (RDP) service is listening without NLA enforcement.",
        "exploit": True
    },
    "NET-05": {
        "plugin_id": 10605,
        "family": "Windows : Network & Services",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 6.0,
        "synopsis": "Default administrative hidden shares (C$, ADMIN$) are active.",
        "exploit": False
    },

    # 7. Kimlik & Erişim (Identity)
    "ID-01": {
        "plugin_id": 10701,
        "family": "Windows : User Rights & Privileges",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vpr": 8.6,
        "synopsis": "User Account Control (UAC) is disabled or set to lowest elevation level.",
        "exploit": True
    },
    "ID-02": {
        "plugin_id": 10702,
        "family": "Windows : User Rights & Privileges",
        "cvss": 7.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 7.5,
        "synopsis": "The built-in local Administrator account is enabled.",
        "exploit": True
    },
    "ID-03": {
        "plugin_id": 10703,
        "family": "Windows : User Rights & Privileges",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 7.0,
        "synopsis": "The built-in Guest account is active on the system.",
        "exploit": False
    },
    "ID-04": {
        "plugin_id": 10704,
        "family": "Windows : User Rights & Privileges",
        "cvss": 6.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 6.3,
        "synopsis": "Minimum password length policy is less than 14 characters.",
        "exploit": False
    },
    "ID-05": {
        "plugin_id": 10705,
        "family": "Windows : User Rights & Privileges",
        "cvss": 7.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 7.1,
        "synopsis": "Account lockout threshold policy is not configured (Brute force risk).",
        "exploit": True
    },

    # 8. Uygulama Kontrolü (AppControl)
    "AC-01": {
        "plugin_id": 10801,
        "family": "Windows : Application Whitelisting",
        "cvss": 8.4,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 8.3,
        "synopsis": "Windows Defender Application Control (WDAC) / AppLocker is not enforced.",
        "exploit": True
    },
    "AC-02": {
        "plugin_id": 10802,
        "family": "Windows : Application Whitelisting",
        "cvss": 7.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 7.6,
        "synopsis": "Microsoft Recommended Driver Block Rules policy is disabled (BYOVD risk).",
        "exploit": True
    },
    "AC-03": {
        "plugin_id": 10803,
        "family": "Windows : Application Whitelisting",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N",
        "vpr": 7.8,
        "synopsis": "SmartScreen for Windows Store Apps is disabled.",
        "exploit": False
    },
    "AC-04": {
        "plugin_id": 10804,
        "family": "Windows : Application Whitelisting",
        "cvss": 7.2,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 6.9,
        "synopsis": "PowerShell Constrained Language Mode is disabled (FullLanguage Mode enabled).",
        "exploit": True
    },

    # 9. Günlük Kayıtları (Logging)
    "LOG-01": {
        "plugin_id": 10901,
        "family": "Windows : Audit & Logging",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N",
        "vpr": 5.9,
        "synopsis": "PowerShell Script Block Logging (EID 4104) is disabled.",
        "exploit": False
    },
    "LOG-02": {
        "plugin_id": 10902,
        "family": "Windows : Audit & Logging",
        "cvss": 6.2,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N",
        "vpr": 5.8,
        "synopsis": "Command line process creation auditing (EID 4688) is not enabled.",
        "exploit": False
    },
    "LOG-03": {
        "plugin_id": 10903,
        "family": "Windows : Audit & Logging",
        "cvss": 6.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N",
        "vpr": 5.5,
        "synopsis": "Logon and Logoff advanced security event auditing is not enabled.",
        "exploit": False
    },
    "LOG-04": {
        "plugin_id": 10904,
        "family": "Windows : Audit & Logging",
        "cvss": 5.5,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L",
        "vpr": 4.8,
        "synopsis": "Windows Security Event Log maximum size is set below 1 GB.",
        "exploit": False
    },

    # 10. Güncellemeler (Updates)
    "UPD-01": {
        "plugin_id": 11001,
        "family": "Windows : Microsoft Updates",
        "cvss": 9.6,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.7,
        "synopsis": "Windows Automatic Updates service is disabled or failing.",
        "exploit": True
    },
    "UPD-02": {
        "plugin_id": 11002,
        "family": "Windows : Microsoft Updates",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.1,
        "synopsis": "The system has not installed critical security patches in over 30 days.",
        "exploit": True
    },
    "UPD-03": {
        "plugin_id": 11003,
        "family": "Windows : Microsoft Updates",
        "cvss": 7.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "vpr": 6.5,
        "synopsis": "Microsoft Update for third-party products (Office, SQL) is disabled.",
        "exploit": False
    },
    "UPD-04": {
        "plugin_id": 11004,
        "family": "Windows : Third-Party Updates",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vpr": 8.7,
        "synopsis": "Third-party desktop applications or web clients have critical security updates available.",
        "exploit": True
    },
    "UPD-05": {
        "plugin_id": 11005,
        "family": "Windows : Microsoft Updates",
        "cvss": 9.2,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.0,
        "synopsis": "Windows OS or Microsoft Defender Security Intelligence updates are pending installation.",
        "exploit": True
    },

    # 11. Kalıcılık & Başlangıç (Persistence)
    "PER-01": {
        "plugin_id": 11101,
        "family": "Windows : Malware Persistence",
        "cvss": 7.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 7.9,
        "synopsis": "Unsigned or suspicious executable configured in Windows Registry Run keys.",
        "exploit": True
    },
    "PER-02": {
        "plugin_id": 11102,
        "family": "Windows : Malware Persistence",
        "cvss": 8.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 8.1,
        "synopsis": "Suspicious scheduled task executing PowerShell or Command Prompt discovered.",
        "exploit": True
    },
    "PER-03": {
        "plugin_id": 11103,
        "family": "Windows : Malware Persistence",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 7.4,
        "synopsis": "Non-standard startup folder executable item detected.",
        "exploit": True
    },

    # 12. Depolama & USB
    "USB-01": {
        "plugin_id": 11201,
        "family": "Windows : Removable Storage",
        "cvss": 8.2,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 8.3,
        "synopsis": "AutoRun / AutoPlay for removable storage devices is enabled (Stuxnet/BadUSB risk).",
        "exploit": True
    },
    "USB-02": {
        "plugin_id": 11202,
        "family": "Windows : Removable Storage",
        "cvss": 6.8,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 6.0,
        "synopsis": "Removable USB mass storage devices are unrestricted (Data exfiltration risk).",
        "exploit": False
    },
    "USB-03": {
        "plugin_id": 11203,
        "family": "Windows : Removable Storage",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 5.8,
        "synopsis": "BitLocker To Go encryption is not enforced for removable media.",
        "exploit": False
    },

    # 13. Sırlar & Kimlik Sızıntısı (Secrets Scan)
    "SEC-01": {
        "plugin_id": 11301,
        "family": "Windows : Sensitive Data & Secrets",
        "cvss": 8.9,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "vpr": 9.1,
        "synopsis": "Unencrypted SSH private keys (id_rsa, id_ed25519) stored in user profile.",
        "exploit": True
    },
    "SEC-02": {
        "plugin_id": 11302,
        "family": "Windows : Sensitive Data & Secrets",
        "cvss": 8.6,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "vpr": 8.8,
        "synopsis": "Plaintext Cloud & Container credentials (.aws, .kube, .docker) exposed.",
        "exploit": True
    },
    "SEC-03": {
        "plugin_id": 11303,
        "family": "Windows : Sensitive Data & Secrets",
        "cvss": 8.7,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 9.0,
        "synopsis": "Hardcoded API keys, tokens or secrets discovered in developer .env files.",
        "exploit": True
    },
    "SEC-04": {
        "plugin_id": 11304,
        "family": "Windows : Sensitive Data & Secrets",
        "cvss": 6.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 6.5,
        "synopsis": "Plaintext passwords or tokens exposed in PowerShell ConsoleHost_history.",
        "exploit": True
    },
    "SEC-05": {
        "plugin_id": 11305,
        "family": "Windows : Sensitive Data & Secrets",
        "cvss": 7.9,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 8.1,
        "synopsis": "Git credentials stored in plaintext via helper=store or .git-credentials.",
        "exploit": True
    },

    # 14. Yazılım Envanteri & Zafiyetler (SCA)
    "SCA-01": {
        "plugin_id": 11401,
        "family": "Windows : Third-Party Software & CVEs",
        "cvss": 0.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "vpr": 0.0,
        "synopsis": "Installed 3rd-party software inventory and component census.",
        "exploit": False
    },
    "SCA-02": {
        "plugin_id": 11402,
        "family": "Windows : Third-Party Software & CVEs",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.9,
        "synopsis": "Known exploited vulnerabilities (CVEs) found in installed third-party software.",
        "exploit": True
    },
    "SCA-03": {
        "plugin_id": 11403,
        "family": "Windows : Third-Party Software & CVEs",
        "cvss": 8.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 8.6,
        "synopsis": "End-of-Life (EOL) unsupported software detected on the host.",
        "exploit": True
    },
    "SCA-04": {
        "plugin_id": 11404,
        "family": "Windows : Third-Party Software & CVEs",
        "cvss": 3.5,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "vpr": 3.0,
        "synopsis": "Software Bill of Materials (CycloneDX SBOM) readiness status.",
        "exploit": False
    },

    # 15. Tarayıcı & İstemci Güvenliği (Browser Security)
    "BRW-01": {
        "plugin_id": 11501,
        "family": "Windows : Web Browsers & Clients",
        "cvss": 5.9,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 5.4,
        "synopsis": "DNS-over-HTTPS (DoH) encrypted DNS query enforcement is disabled.",
        "exploit": False
    },
    "BRW-02": {
        "plugin_id": 11502,
        "family": "Windows : Web Browsers & Clients",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vpr": 8.5,
        "synopsis": "Web browser SafeBrowsing / SmartScreen phishing defense is disabled.",
        "exploit": True
    },
    "BRW-03": {
        "plugin_id": 11503,
        "family": "Windows : Web Browsers & Clients",
        "cvss": 4.5,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
        "vpr": 4.0,
        "synopsis": "Browser extension policy allows unrestricted 3rd-party sideloading.",
        "exploit": False
    },
    "BRW-04": {
        "plugin_id": 11504,
        "family": "Windows : Web Browsers & Clients",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.8,
        "synopsis": "Browser running with exposed Remote Debugging Port (--remote-debugging-port).",
        "exploit": True
    },
    "BRW-05": {
        "plugin_id": 11505,
        "family": "Windows : Web Browsers & Clients",
        "cvss": 5.3,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 5.0,
        "synopsis": "Browser password manager stores credentials without master OS challenge.",
        "exploit": False
    },
    "BRW-06": {
        "plugin_id": 11506,
        "family": "Windows : Web Browsers & Clients",
        "cvss": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vpr": 8.5,
        "synopsis": "Installed web browser (e.g. Opera) is outdated and vulnerable to zero-day / RCE exploits.",
        "exploit": True,
        "cpe": "cpe:/a:opera:opera_browser"
    },

    # 16. Yama & Güncelleme Yönetimi (Patch Management)
    "UPD-01": {
        "plugin_id": 10601,
        "family": "Windows : Patch Management",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.2,
        "synopsis": "Windows Update service is disabled, preventing installation of critical OS patches.",
        "exploit": True
    },
    "UPD-02": {
        "plugin_id": 10602,
        "family": "Windows : Patch Management",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "vpr": 7.0,
        "synopsis": "The host has installed critical security patches that require a reboot to be effective.",
        "exploit": False
    },
    "UPD-03": {
        "plugin_id": 10603,
        "family": "Windows : Patch Management",
        "cvss": 5.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "vpr": 4.5,
        "synopsis": "Windows hotfix patch history baseline verification.",
        "exploit": False
    },
    "UPD-04": {
        "plugin_id": 10604,
        "family": "Windows : Patch Management",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "vpr": 8.2,
        "synopsis": "Third-party desktop applications and packages are missing critical security updates.",
        "exploit": True
    },

    # 17. Yazılım Bileşen Analizi (SCA) & SBOM
    "SCA-01": {
        "plugin_id": 11601,
        "family": "Windows : Software Composition Analysis",
        "cvss": 2.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "vpr": 2.0,
        "synopsis": "Installed 3rd-party software inventory baseline.",
        "exploit": False
    },
    "SCA-02": {
        "plugin_id": 11602,
        "family": "Windows : Software Composition Analysis",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vpr": 9.5,
        "synopsis": "One or more installed software applications contain known exploited critical CVE vulnerabilities.",
        "exploit": True
    },
    "SCA-03": {
        "plugin_id": 11603,
        "family": "Windows : Software Composition Analysis",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "vpr": 7.2,
        "synopsis": "End-of-Life (EOL) unsupported software detected on host.",
        "exploit": False
    },
    "SCA-04": {
        "plugin_id": 11604,
        "family": "Windows : Software Composition Analysis",
        "cvss": 2.0,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "vpr": 2.0,
        "synopsis": "Software Bill of Materials (SBOM) CycloneDX readiness check.",
        "exploit": False
    }
}


def enrich_check_to_plugin(check: CheckItem, module_name: str, category_name: str) -> NessusPlugin:
    """CyberAudit CheckItem nesnesini tam donanımlı NessusPlugin nesnesine dönüştürür."""
    meta = PLUGIN_METADATA_MAP.get(check.id)
    if not meta:
        # Standart fallback
        hash_id = abs(hash(check.id)) % 80000 + 10000
        cvss_val = 9.0 if check.severity == Severity.CRITICAL else (7.5 if check.severity == Severity.HIGH else (5.0 if check.severity == Severity.MEDIUM else 2.5))
        meta = {
            "plugin_id": hash_id,
            "family": f"Windows : {category_name}",
            "cvss": cvss_val,
            "vector": f"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "vpr": cvss_val * 0.95,
            "synopsis": check.title,
            "exploit": check.severity in [Severity.CRITICAL, Severity.HIGH],
            "cpe": None
        }

    return NessusPlugin(
        plugin_id=meta["plugin_id"],
        check_id=check.id,
        name=check.title,
        family=meta["family"],
        severity=check.severity,
        cvss_v3_score=meta["cvss"],
        cvss_v3_vector=meta["vector"],
        vpr_score=round(meta["vpr"], 1),
        synopsis=meta["synopsis"],
        description=check.description,
        solution=check.remediation,
        plugin_output=f"Checked Condition: {check.title}\nCurrent State: {check.current_value}\nRequired State: {check.recommended_value}\nStandard Reference: {check.standard_ref or 'CIS Microsoft Windows Benchmark'}",
        see_also=[
            f"https://www.tenable.com/plugins/nessus/{meta['plugin_id']}",
            f"https://cve.mitre.org/",
            "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
        ],
        cpe=meta.get("cpe"),
        exploit_available=meta.get("exploit", False)
    )
