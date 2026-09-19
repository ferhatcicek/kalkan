const translations = {
    tr: {
        // Navbar & Platform
        "nav_dashboard": "Taramalar & Bulgular",
        "nav_wizard": "Tarama Sihirbazı",
        "nav_remediations": "Öncelikli İyileştirme",
        "nav_modules": "Güvenlik Modülleri",
        "badge_edition": "ENTERPRISE",
        "theme_dark": "Koyu Tema (Dark)",
        "theme_light": "Açık Tema (Light)",
        "theme_hacker": "Hacker Teması",
        "btn_run_audit": "GÜVENLİK TARAMASINI BAŞLAT",
        "btn_running": "DENETLENİYOR...",
        "btn_rescan": "GÜVENLİK TARAMASINI YENİLE",
        "engine_active": "Denetim Motoru: 75 Kural Aktif",
        "export_title": "Dışa Aktar",
        "history_title": "Geçmiş Trendi",
        
        // Telemetri
        "telemetry_host": "Hedef Uç Nokta Cihazı",
        "telemetry_os": "İşletim Sistemi",
        "telemetry_priv": "Ayrıcalık Düzeyi",
        "role_admin": "Yönetici",
        "role_user": "Standart Kullanıcı",

        // Dashboard & KPI
        "dash_title": "Sistem Güvenlik Skoru",
        "dash_last_scan": "Son tarama",
        "dash_not_scanned": "Henüz yapılmadı",
        "dash_kpi_total": "Toplam Denetim",
        "dash_kpi_pass": "Başarılı (Geçti)",
        "dash_kpi_crit": "Kritik Risk",
        "dash_kpi_high": "Yüksek Risk",
        "dash_kpi_warn": "Orta & Düşük",
        "tab_findings": "Tüm Güvenlik Bulguları",
        "tab_ports": "Ağ & Dinlenen Portlar Haritası",
        "filter_all": "Tümü",
        "filter_fails": "Tüm Zafiyetler",
        "filter_pass": "Başarılı",
        "filter_crit": "Kritik",
        "filter_high": "Yüksek",
        "filter_med": "Orta",
        "search_placeholder": "Kontrol veya anahtar kelime ara (örn: SMB, UAC, BitLocker)...",
        
        // Skor Gauge & Profil
        "gauge_label": "GÜVENLİK İNDEKSİ",
        "profile_label": "🎯 Denetim Profili",
        "profile_cis_l1": "🏢 CIS Seviye 1 (Kurumsal Standart)",
        "profile_cis_l2": "🔒 CIS Seviye 2 (Yüksek Güvenlik / Kritik)",
        "profile_dev": "💻 Geliştirici & Mühendislik",
        "profile_home": "🏠 Kişisel / Ev Kullanıcısı",
        "breakdown_title": "Kategori Bazlı Güvenlik Başarısı",
        "breakdown_sub": "CIS Benchmark ve MITRE ATT&CK Uyum Oranları",
        
        // Modüller Sayfası
        "cat_title": "Güvenlik Modülleri",
        "cat_desc": "Sistemde yüklü 15 derin güvenlik modülünü yönetin.",
        "catalog_hero_h2": "Güvenlik Modülleri Kontrol ve Yönetim Merkezi",
        "catalog_hero_p": "Sistemde yüklü 15 derin güvenlik modülünü yönetin, aktif/pasif durumlarını değiştirin, tek tıkla bağımsız (< 1 sn) tarayın veya detaylı modül sayfasına girerek tüm kuralları inceleyin.",
        "btn_enable_all": "Tümünü Aç",
        "btn_disable_all": "Tümünü Kapat",
        "search_mod_placeholder": "Modül adı veya anahtar kelime ara (örn: Antivirüs)...",
        "filter_cat_all": "Tümü",
        "btn_quick_scan": "Hızlı Tara",
        "btn_examine": "Modülü İncele & Yönet",
        "mod_status_label": "Modül Durumu",
        "mod_active": "Aktif",
        "mod_passive": "Pasif",
        "btn_back_to_catalog": "Tüm Modüllere Dön",
        "btn_scan_single_mod": "BU MODÜLÜ BAĞIMSIZ TARA",
        "btn_download_fix_script": "Düzeltme Betiği (.ps1)",
        "mod_kpi_score": "MODÜL SKORU",
        "mod_kpi_score_sub": "Kategori İçi Başarı",
        "mod_kpi_total": "TOPLAM KONTROL",
        "mod_kpi_total_sub": "Derin Denetim Kuralı",
        "mod_kpi_pass": "BAŞARILI (PASS)",
        "mod_kpi_pass_sub": "Güvenli Parametreler",
        "mod_kpi_fail": "RİSK / ZAFİYET",
        "mod_kpi_fail_sub": "İyileştirme Gerekli",
        "mod_kpi_duration": "SON TARAMA SÜRESİ",
        "mod_kpi_not_scanned": "Henüz Taranmadı",
        "mod_checks_title": "Modül Güvenlik Kontrolleri ve Kuralları",
        "search_rule_placeholder": "Kural veya kod ara...",

        // Sihirbaz
        "wizard_title": "Hedefe Yönelik Güvenlik Taramaları",
        "wizard_sub": "İhtiyacınıza uygun hazır denetim şablonunu seçerek hızlı analiz başlatın.",
        "wizard_btn_start": "Taramayı Başlat",

        // İyileştirme
        "rem_title": "En Yüksek Risk Azaltıcı İlk 5 Eylem (Top Remediations)",
        "rem_sub": "Güvenlik sektörünün kanıtlanmış yaklaşımı: Yüzlerce bulgu yerine, genel riski en hızlı düşürecek ilk 5 kritik eyleme odaklanın.",
        "rem_btn_download_all": "Toplu Sıkılaştırma Betiği İndir (.ps1)",
        "rem_btn_goto": "Modülü İncele & Çöz",
        "rem_btn_copy": "Komutu Kopyala",
        "rem_risk_reduction": "Risk Azaltımı",
        "rem_est_time": "Tahmini Çözüm Süresi",
        "rem_standard": "Standart",

        // Port Haritası
        "ports_title": "Dış Dünyaya Açık Dinlenen Ağ Portları (0.0.0.0 & ::)",
        "ports_sub": "Bilgisayarınızda dışarıdan gelen bağlantıları kabul eden aktif servisler",
        "th_port": "Port",
        "th_service": "Protokol / Servis",
        "th_binding": "Dinleme Adresi",
        "th_process": "Çalışan Süreç (Process)",
        "th_pid": "PID",
        "th_risk": "Risk Durumu",
        "ports_risky": "RİSKLİ / İZLENMELİ",
        "ports_standard": "STANDART",
        "ports_empty": "Dinlenen riskli harici port bulunamadı veya yetki yetersizliği.",

        // Kural Detay & Drawer
        "how_to_fix": "Nasıl Düzeltilir? (Önerilen Komut)",
        "btn_verify": "Doğrula (Verify)",
        "btn_inspect_rule": "Kural Detayı",
        "btn_inspect_drawer": "Kuralı İncele",
        "val_detected": "Sistemde Okunan Değer:",
        "val_recommended": "Önerilen Güvenli Değer:",
        "val_standard_ref": "Standart Referansı:",
        "drawer_loading": "Plugin ve CVSS verileri alınıyor...",
        "drawer_cvss_vector": "CVSS v3.1 Vektör Dizgisi",
        "drawer_synopsis": "Synopsis & Güvenlik Açıklaması",
        "drawer_audit_output": "Denetim Çıktısı & Sistem Kanıtı (Audit Output)",
        "drawer_solution": "Çözüm & Sıkılaştırma (Solution)",
        "drawer_rec_ps": "Önerilen PowerShell Otomasyonu:",
        "drawer_exploit_active": "⚠️ Aktif Exploit Riski (CISA KEV)",
        "drawer_exploit_none": "Exploit Bilinmiyor",
        "history_modal_title": "Güvenlik Skoru Değişim Trendi & Geçmiş",
        "history_last_two": "Son İki Tarama Trendi",
        "history_prev": "Önceki Skor:",
        "history_curr": "Güncel:",
        "history_none": "Kayıtlı geçmiş tarama bulunmuyor.",

        // Durumlar & Bildirimler
        "score_status_analyzing": "Analiz Ediliyor...",
        "score_status_excellent": "Mükemmel & Sıkılaştırılmış",
        "score_status_good": "İyi Seviye (Kısmi İyileştirme Gerekir)",
        "score_status_warn": "Dikkat: Önemli Zafiyetler Mevcut",
        "score_status_crit": "Kritik Risk: Sistem Savunmasız!",
        "theme_changed": "Tema değiştirildi",
        "lang_changed": "Dil değiştirildi: Türkçe",
        "copied": "Kopyalandı!",
        "copy": "Kopyala",
        "close": "Kapat",
        "no_matching_checks": "Seçili filtre veya arama kriterine uygun denetim bulunamadı.",
        "no_matching_modules": "Arama kriterine uygun modül bulunamadı."
    },
    en: {
        // Navbar & Platform
        "nav_dashboard": "Scans & Findings",
        "nav_wizard": "Scan Wizard",
        "nav_remediations": "Top Remediations",
        "nav_modules": "Security Modules",
        "badge_edition": "ENTERPRISE",
        "theme_dark": "Enterprise Dark",
        "theme_light": "Enterprise Light",
        "theme_hacker": "Midnight Cyber",
        "btn_run_audit": "START SECURITY AUDIT",
        "btn_running": "SCANNING...",
        "btn_rescan": "RE-RUN SECURITY AUDIT",
        "engine_active": "Audit Engine: 75 Rules Active",
        "export_title": "Export",
        "history_title": "Score History",
        
        // Telemetri
        "telemetry_host": "Target Endpoint Device",
        "telemetry_os": "Operating System",
        "telemetry_priv": "Privilege Level",
        "role_admin": "Administrator",
        "role_user": "Standard User",

        // Dashboard & KPI
        "dash_title": "System Security Score",
        "dash_last_scan": "Last scan",
        "dash_not_scanned": "Not scanned yet",
        "dash_kpi_total": "Total Checks",
        "dash_kpi_pass": "Passed (Secure)",
        "dash_kpi_crit": "Critical Risk",
        "dash_kpi_high": "High Risk",
        "dash_kpi_warn": "Medium & Low",
        "tab_findings": "All Security Findings",
        "tab_ports": "Network & Listening Ports Map",
        "filter_all": "All",
        "filter_fails": "Vulnerabilities",
        "filter_pass": "Passed",
        "filter_crit": "Critical",
        "filter_high": "High",
        "filter_med": "Medium",
        "search_placeholder": "Search checks or keywords (e.g., SMB, UAC, BitLocker)...",
        
        // Skor Gauge & Profil
        "gauge_label": "SECURITY INDEX",
        "profile_label": "🎯 Audit Profile",
        "profile_cis_l1": "🏢 CIS Level 1 (Corporate Baseline)",
        "profile_cis_l2": "🔒 CIS Level 2 (High Security / Critical)",
        "profile_dev": "💻 Developer & Engineering",
        "profile_home": "🏠 Personal / Home User",
        "breakdown_title": "Security Compliance by Category",
        "breakdown_sub": "CIS Benchmark and MITRE ATT&CK Alignment Rates",
        
        // Modüller Sayfası
        "cat_title": "Security Modules",
        "cat_desc": "Manage the 15 deep security modules installed on the system.",
        "catalog_hero_h2": "Security Modules Control & Management Center",
        "catalog_hero_p": "Manage 15 deep security modules, toggle active/inactive states, perform instant isolated scans (< 1s), or inspect detailed module rules.",
        "btn_enable_all": "Enable All",
        "btn_disable_all": "Disable All",
        "search_mod_placeholder": "Search module name or keyword (e.g., Antivirus)...",
        "filter_cat_all": "All",
        "btn_quick_scan": "Quick Scan",
        "btn_examine": "Manage Module",
        "mod_status_label": "Module Status",
        "mod_active": "Active",
        "mod_passive": "Disabled",
        "btn_back_to_catalog": "Back to All Modules",
        "btn_scan_single_mod": "SCAN THIS MODULE",
        "btn_download_fix_script": "Remediation Script (.ps1)",
        "mod_kpi_score": "MODULE SCORE",
        "mod_kpi_score_sub": "Category Compliance",
        "mod_kpi_total": "TOTAL CHECKS",
        "mod_kpi_total_sub": "Deep Audit Rules",
        "mod_kpi_pass": "PASSED (PASS)",
        "mod_kpi_pass_sub": "Compliant Settings",
        "mod_kpi_fail": "RISK / VULNERABILITY",
        "mod_kpi_fail_sub": "Action Needed",
        "mod_kpi_duration": "LAST SCAN DURATION",
        "mod_kpi_not_scanned": "Not Scanned Yet",
        "mod_checks_title": "Module Security Checks & Rules",
        "search_rule_placeholder": "Search check or code...",

        // Sihirbaz
        "wizard_title": "Targeted Security Scans",
        "wizard_sub": "Choose a tailored audit profile and run focused security analysis.",
        "wizard_btn_start": "Launch Scan",

        // İyileştirme
        "rem_title": "Top 5 High-Impact Security Fixes (Top Remediations)",
        "rem_sub": "Industry proven methodology: Instead of hundreds of findings, focus on the top 5 actions that reduce overall risk fastest.",
        "rem_btn_download_all": "Download Hardening Script (.ps1)",
        "rem_btn_goto": "Review & Remediate",
        "rem_btn_copy": "Copy Command",
        "rem_risk_reduction": "Risk Reduction",
        "rem_est_time": "Estimated Effort",
        "rem_standard": "Standard",

        // Port Haritası
        "ports_title": "Externally Listening Network Ports (0.0.0.0 & ::)",
        "ports_sub": "Active services accepting external inbound connections on this computer",
        "th_port": "Port",
        "th_service": "Protocol / Service",
        "th_binding": "Binding Address",
        "th_process": "Process Name",
        "th_pid": "PID",
        "th_risk": "Risk State",
        "ports_risky": "RISKY / EXPOSED",
        "ports_standard": "STANDARD",
        "ports_empty": "No open listening external ports found or insufficient permissions.",

        // Kural Detay & Drawer
        "how_to_fix": "How to Remediate (Recommended Command)",
        "btn_verify": "Verify",
        "btn_inspect_rule": "Rule Details",
        "btn_inspect_drawer": "Inspect Rule",
        "val_detected": "Detected Value:",
        "val_recommended": "Recommended Value:",
        "val_standard_ref": "Standard Reference:",
        "drawer_loading": "Loading Plugin and CVSS telemetry...",
        "drawer_cvss_vector": "CVSS v3.1 Vector String",
        "drawer_synopsis": "Synopsis & Security Summary",
        "drawer_audit_output": "Audit Output & System Evidence",
        "drawer_solution": "Solution & Hardening Guidance",
        "drawer_rec_ps": "Recommended PowerShell Automation:",
        "drawer_exploit_active": "⚠️ Known Exploited Vulnerability (CISA KEV)",
        "drawer_exploit_none": "No Known Exploit",
        "history_modal_title": "Security Score Trend & Scan History",
        "history_last_two": "Last Two Scans Trend",
        "history_prev": "Previous Score:",
        "history_curr": "Current:",
        "history_none": "No scan history recorded.",

        // Durumlar & Bildirimler
        "score_status_analyzing": "Analyzing...",
        "score_status_excellent": "Hardened & Secure",
        "score_status_good": "Good Level (Minor Improvements Needed)",
        "score_status_warn": "Warning: Significant Risks Present",
        "score_status_crit": "Critical Risk: System Exposed!",
        "theme_changed": "Theme changed",
        "lang_changed": "Language switched to English",
        "copied": "Copied!",
        "copy": "Copy",
        "close": "Close",
        "no_matching_checks": "No findings match the selected filter or search criteria.",
        "no_matching_modules": "No modules match the search criteria."
    }
};

let _currentLanguage = localStorage.getItem("cyberaudit_lang") || "tr";

function currentLang() {
    return _currentLanguage;
}

function getCurrentLang() {
    return _currentLanguage;
}

function t(key) {
    if (translations[_currentLanguage] && translations[_currentLanguage][key]) {
        return translations[_currentLanguage][key];
    }
    if (translations["tr"] && translations["tr"][key]) {
        return translations["tr"][key];
    }
    return key;
}

function setLanguage(lang) {
    if (!translations[lang]) return;
    _currentLanguage = lang;
    try {
        localStorage.setItem("cyberaudit_lang", lang);
    } catch (e) {}
    
    applyTranslations();
    
    // Tüm dinleyicilere dil değişim event'i fırlat
    window.dispatchEvent(new CustomEvent("cyberaudit_lang_change", { detail: { lang } }));
}

function applyTranslations() {
    try {
        const lang = _currentLanguage;
        const langData = translations[lang] || translations["tr"];
        if (!langData) return;
        
        // data-i18n etiketlerini dönüştür
        document.querySelectorAll("[data-i18n]").forEach(el => {
            const key = el.getAttribute("data-i18n");
            if (key && langData[key]) {
                if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") {
                    el.setAttribute("placeholder", langData[key]);
                } else {
                    el.textContent = langData[key];
                }
            }
        });

        // HTML lang özniteliğini güncelle
        document.documentElement.setAttribute("lang", lang);

        // langSelect kutusu varsa senkronize et
        const select = document.getElementById("langSelect");
        if (select && select.value !== lang) {
            select.value = lang;
        }
    } catch (err) {
        console.error("applyTranslations error:", err);
    }
}

// Global olarak dışa aktar
window.t = t;
window.setLanguage = setLanguage;
window.applyTranslations = applyTranslations;
window.currentLang = currentLang;
window.getCurrentLang = getCurrentLang;
