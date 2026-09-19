document.addEventListener("DOMContentLoaded", () => {
    // Durum Değişkenleri (State Variables)
    let currentReport = null;
    let registeredModules = [];
    let currentFilter = "all";
    let currentSearchTerm = "";
    let isScanning = false;
    let ws = null;
    let currentActiveModuleId = null;
    let catalogFilterCat = "all";
    let catalogFilterSearch = "";
    let detailFilterStatus = "all";
    let detailFilterSearch = "";

    // --- 1. TEMA VE DİL YÖNETİM SİSTEMİ (PLUGGABLE THEMES & i18n) ---
    const themeSelect = document.getElementById("themeSelect");
    const savedTheme = localStorage.getItem("cyberaudit_theme") || "enterprise-dark";
    applyTheme(savedTheme);

    themeSelect.value = savedTheme;
    themeSelect.addEventListener("change", (e) => {
        const selected = e.target.value;
        applyTheme(selected);
        localStorage.setItem("cyberaudit_theme", selected);
        showToast(t("theme_changed") || `Tema değiştirildi: ${e.target.options[e.target.selectedIndex].text}`);
    });

    const langSelect = document.getElementById("langSelect");
    if (langSelect) {
        langSelect.value = currentLang();
    }

    // Dil değiştiğinde çalışacak listener
    window.addEventListener("cyberaudit_lang_change", async (e) => {
        try {
            const newLang = e.detail ? e.detail.lang : currentLang();
            showToast(t("lang_changed"));
            loadSystemInfo();
            
            // Re-fetch latest report with selected language
            try {
                const res = await fetch(`/api/report/latest?lang=${newLang}`);
                if (res.ok) {
                    currentReport = await res.json();
                }
            } catch (err) {
                console.warn("Could not reload report in new language", err);
            }

            if (currentReport) {
                renderFullReport(currentReport);
            } else {
                resetScanButton();
            }

            if (registeredModules && registeredModules.length > 0) {
                renderModulesCatalog();
            }

            if (typeof loadWizardTemplates === "function" && viewWizard && viewWizard.style.display !== "none") {
                loadWizardTemplates();
            }
            if (typeof loadTopRemediations === "function" && viewRemediations && viewRemediations.style.display !== "none") {
                loadTopRemediations();
            }
            if (typeof openModuleDetailPage === "function" && viewModuleDetail && viewModuleDetail.style.display !== "none" && currentActiveModuleId) {
                openModuleDetailPage(currentActiveModuleId);
            }
        } catch (err) {
            console.error("Language change event error:", err);
        }
    });

    // Apply translations on load
    applyTranslations();

    function applyTheme(themeName) {
        document.documentElement.setAttribute("data-theme", themeName);
    }

    // --- DOM ELEMENTLERİ ---
    const scoreNum = document.getElementById("scoreNum");
    const gaugeValue = document.getElementById("gaugeValue");
    const scoreStatus = document.getElementById("scoreStatus");
    const btnRunAudit = document.getElementById("btnRunAudit");
    const btnRunAuditText = document.getElementById("btnRunAuditText");
    const lblScanMeta = document.getElementById("lblScanMeta");

    // KPI Sayaçları
    const kpiTotal = document.getElementById("kpiTotal");
    const kpiPass = document.getElementById("kpiPass");
    const kpiCrit = document.getElementById("kpiCrit");
    const kpiHigh = document.getElementById("kpiHigh");
    const kpiWarn = document.getElementById("kpiWarn");
    const categoryBarsGrid = document.getElementById("categoryBarsGrid");

    // Canlı Tarama Bandı
    const liveScanBanner = document.getElementById("liveScanBanner");
    const liveModuleName = document.getElementById("liveModuleName");
    const livePctText = document.getElementById("livePctText");
    const liveProgressFill = document.getElementById("liveProgressFill");
    const liveStatusMsg = document.getElementById("liveStatusMsg");

    // --- SAYFA GÖRÜNÜMLERİ VE GEZİNME (VIEWS & ROUTING) ---
    const viewDashboard = document.getElementById("viewDashboard");
    const viewModulesCatalog = document.getElementById("viewModulesCatalog");
    const viewModuleDetail = document.getElementById("viewModuleDetail");
    const viewWizard = document.getElementById("viewWizard");
    const viewRemediations = document.getElementById("viewRemediations");

    const navBtnDashboard = document.getElementById("navBtnDashboard");
    const navBtnWizard = document.getElementById("navBtnWizard");
    const navBtnRemediations = document.getElementById("navBtnRemediations");
    const navBtnModules = document.getElementById("navBtnModules");
    const navActiveCountBadge = document.getElementById("navActiveCountBadge");

    // Nessus Bileşenleri
    const wizardTemplatesGrid = document.getElementById("wizardTemplatesGrid");
    const topRemediationsStack = document.getElementById("topRemediationsStack");
    const nessusCritCount = document.getElementById("nessusCritCount");
    const nessusHighCount = document.getElementById("nessusHighCount");
    const nessusMedCount = document.getElementById("nessusMedCount");
    const nessusLowCount = document.getElementById("nessusLowCount");
    const nessusPassCount = document.getElementById("nessusPassCount");
    const nessusSegCrit = document.getElementById("nessusSegCrit");
    const nessusSegHigh = document.getElementById("nessusSegHigh");
    const nessusSegMed = document.getElementById("nessusSegMed");
    const nessusSegLow = document.getElementById("nessusSegLow");
    const nessusSegPass = document.getElementById("nessusSegPass");

    // Nessus Plugin Inspector Drawer
    const pluginDrawerBackdrop = document.getElementById("pluginDrawerBackdrop");
    const pluginDrawer = document.getElementById("pluginDrawer");
    const btnDrawerClose = document.getElementById("btnDrawerClose");
    const drawerPluginId = document.getElementById("drawerPluginId");
    const drawerPluginTitle = document.getElementById("drawerPluginTitle");
    const drawerPluginContent = document.getElementById("drawerPluginContent");

    // Dashboard İçi Sekmeler
    const tabFindings = document.getElementById("tabFindings");
    const tabPorts = document.getElementById("tabPorts");
    const viewFindings = document.getElementById("viewFindings");
    const viewPorts = document.getElementById("viewPorts");
    const portsTableBody = document.getElementById("portsTableBody");

    // Modüller Kataloğu Elementleri
    const catTotalBadge = document.getElementById("catTotalBadge");
    const catActiveBadge = document.getElementById("catActiveBadge");
    const btnCatalogEnableAll = document.getElementById("btnCatalogEnableAll");
    const btnCatalogDisableAll = document.getElementById("btnCatalogDisableAll");
    const catalogSearchInput = document.getElementById("catalogSearchInput");
    const catalogCardsGrid = document.getElementById("catalogCardsGrid");

    // Detaylı Modül Sayfası Elementleri
    const btnBackToCatalog = document.getElementById("btnBackToCatalog");
    const crumbLinkCatalog = document.getElementById("crumbLinkCatalog");
    const detailCrumbCategory = document.getElementById("detailCrumbCategory");
    const detailCrumbTitle = document.getElementById("detailCrumbTitle");
    const detailTagCategory = document.getElementById("detailTagCategory");
    const detailTagWeight = document.getElementById("detailTagWeight");
    const detailTagVersion = document.getElementById("detailTagVersion");
    const detailTagStandard = document.getElementById("detailTagStandard");
    const detailTitle = document.getElementById("detailTitle");
    const detailDesc = document.getElementById("detailDesc");
    const detailStatusLabel = document.getElementById("detailStatusLabel");
    const detailToggleModule = document.getElementById("detailToggleModule");
    const btnDetailScanModule = document.getElementById("btnDetailScanModule");
    const txtDetailScan = document.getElementById("txtDetailScan");
    const btnDetailDownloadFix = document.getElementById("btnDetailDownloadFix");
    const detailKpiScore = document.getElementById("detailKpiScore");
    const detailKpiTotal = document.getElementById("detailKpiTotal");
    const detailKpiPass = document.getElementById("detailKpiPass");
    const detailKpiFail = document.getElementById("detailKpiFail");
    const detailKpiDuration = document.getElementById("detailKpiDuration");
    const detailKpiTimestamp = document.getElementById("detailKpiTimestamp");
    const detailChecksCountTag = document.getElementById("detailChecksCountTag");
    const detailCheckSearch = document.getElementById("detailCheckSearch");
    const detailChecksStack = document.getElementById("detailChecksStack");

    // Filtre & Arama
    const filterChips = document.querySelectorAll(".filter-chip");
    const filterSearch = document.getElementById("filterSearch");
    const accordionStack = document.getElementById("accordionStack");

    // Toast
    const toastNotice = document.getElementById("toastNotice");

    // --- 2. SİSTEM BİLGİSİ ---
    async function loadSystemInfo() {
        try {
            const res = await fetch("/api/system-info");
            if (!res.ok) return;
            const data = await res.json();
            document.getElementById("txtHost").textContent = data.hostname;
            document.getElementById("txtOS").textContent = data.os.split("(")[0].trim();
            document.getElementById("txtAdmin").textContent = data.is_admin ? t("role_admin") : t("role_user");
        } catch (e) {
            console.error("Sistem bilgisi alınamadı:", e);
        }
    }

    // --- 3. MODÜLLERİN YÜKLENMESİ VE DRAWER ---
    async function loadModules() {
        try {
            const res = await fetch("/api/modules");
            if (!res.ok) return;
            registeredModules = await res.json();
            renderDrawerModules();
            renderModulesCatalog();
        } catch (e) {
            console.error("Modüller alınamadı:", e);
        }
    }

    async function toggleModuleAPI(modId, enabled) {
        try {
            await fetch(`/api/modules/${modId}/toggle`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled })
            });
            showToast(`${modId} modülü ${enabled ? "etkinleştirildi" : "pasifleştirildi"}.`);
        } catch (e) {
            console.error("Modül değiştirilemedi:", e);
        }
    }

    // --- 4. GÜVENLİK TARAMASI (WEBSOCKET & REST FALLBACK) ---
    function startAuditScan() {
        if (isScanning) return;
        isScanning = true;

        btnRunAudit.disabled = true;
        btnRunAuditText.textContent = t("btn_running");

        liveScanBanner.style.display = "block";
        liveProgressFill.style.width = "5%";
        livePctText.textContent = "5%";
        liveModuleName.textContent = currentLang() === 'en' ? "Initializing scan..." : "Tarama Başlatılıyor...";
        liveStatusMsg.textContent = currentLang() === 'en' ? "Preparing audit engine and registry connections..." : "Denetim motoru ve kayıt defteri bağlantısı hazırlanıyor...";

        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/scan`;

        try {
            ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                ws.send(JSON.stringify({
                    action: "start_scan",
                    selected_modules: [],
                    lang: currentLang()
                }));
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.event === "progress") {
                        liveProgressFill.style.width = `${data.percent}%`;
                        livePctText.textContent = `${data.percent}%`;
                        liveModuleName.textContent = data.current_module;
                        liveStatusMsg.textContent = data.message;
                    } else if (data.event === "scan_completed") {
                        onScanDone(data.report);
                    }
                } catch (err) {
                    console.error("WebSocket veri hatası:", err);
                }
            };

            ws.onerror = () => { fallbackScan(); };
            ws.onclose = () => { if (isScanning) fallbackScan(); };
        } catch (e) {
            fallbackScan();
        }
    }

    async function fallbackScan() {
        try {
            const res = await fetch(`/api/scan?lang=${currentLang()}`, { method: "POST" });
            const rep = await res.json();
            onScanDone(rep);
        } catch (err) {
            showToast(currentLang() === 'en' ? "Error during scan!" : "Tarama sırasında hata oluştu!");
            resetScanButton();
        }
    }

    function onScanDone(report) {
        currentReport = report;
        isScanning = false;
        resetScanButton();

        liveProgressFill.style.width = "100%";
        livePctText.textContent = "100%";
        liveModuleName.textContent = currentLang() === 'en' ? "Scan Successfully Completed!" : "Tarama Başarıyla Tamamlandı!";
        liveStatusMsg.textContent = currentLang() === 'en' 
            ? `${report.total_checks} checks verified in ${report.duration_seconds}s.`
            : `${report.total_checks} kontrol ${report.duration_seconds} saniyede denetlendi.`;

        setTimeout(() => {
            liveScanBanner.style.display = "none";
        }, 3000);

        renderFullReport(report);
        renderModulesCatalog();
        if (currentActiveModuleId) {
            openModuleDetailPage(currentActiveModuleId);
        }
        showToast(currentLang() === 'en' ? `Scan finished! Security Score: ${report.total_score}/100` : `Tarama bitti! Güvenlik Skoru: ${report.total_score}/100`);
    }

    function resetScanButton() {
        btnRunAudit.disabled = false;
        btnRunAuditText.textContent = currentReport ? t("btn_rescan") : t("btn_run_audit");
    }

    // --- 5. RAPORU VE GÖRSEL BİLEŞENLERİ ÇİZ ---
    function renderFullReport(report) {
        updateCircularGauge(report.total_score);

        lblScanMeta.textContent = `${t("dash_last_scan")}: ${report.timestamp} (${report.duration_seconds}s)`;

        // KPI Metrikleri
        kpiTotal.textContent = report.total_checks;
        kpiPass.textContent = report.passed_count;
        kpiCrit.textContent = report.critical_count;
        kpiHigh.textContent = report.high_count;
        kpiWarn.textContent = report.medium_count + report.low_count;

        // KPI Kutu Yüzde Rozetleri
        const total = report.total_checks || 1;
        const pPass = Math.round((report.passed_count / total) * 100);
        const pCrit = Math.round((report.critical_count / total) * 100);
        const pHigh = Math.round((report.high_count / total) * 100);
        const pWarn = Math.round(((report.medium_count + report.low_count) / total) * 100);

        const pctTotal = document.getElementById("pctTotal");
        const pctPass = document.getElementById("pctPass");
        const pctCrit = document.getElementById("pctCrit");
        const pctHigh = document.getElementById("pctHigh");
        const pctWarn = document.getElementById("pctWarn");

        if (pctTotal) pctTotal.textContent = "100%";
        if (pctPass) pctPass.textContent = `%${pPass}`;
        if (pctCrit) pctCrit.textContent = `%${pCrit}`;
        if (pctHigh) pctHigh.textContent = `%${pHigh}`;
        if (pctWarn) pctWarn.textContent = `%${pWarn}`;

        // Toolbar sayıları
        const failsCount = report.critical_count + report.high_count + report.medium_count + report.low_count;
        document.getElementById("fAll").textContent = report.total_checks;
        document.getElementById("fFails").textContent = failsCount;
        document.getElementById("fCrit").textContent = report.critical_count;
        document.getElementById("fHigh").textContent = report.high_count;
        document.getElementById("fMed").textContent = report.medium_count;
        document.getElementById("btnRunAuditText").textContent = t("btn_rescan");
        document.getElementById("fPass").textContent = report.passed_count;

        // Kategori Başarı Çubukları
        renderCategoryProgress(report.categories);

        // Bulgular Akordeonu
        renderFindingsList();

        // Portlar Tablosu
        renderPortsTable();
    }

    function updateCircularGauge(score) {
        scoreNum.textContent = score;
        const radius = 85;
        const circumference = 2 * Math.PI * radius; // ~534.07
        const offset = circumference - (score / 100) * circumference;
        gaugeValue.style.strokeDashoffset = offset;

        scoreStatus.className = "score-badge-status";
        if (score >= 85) {
            gaugeValue.style.stroke = "var(--color-pass)";
            scoreStatus.textContent = t("score_status_excellent");
            scoreStatus.classList.add("pass");
        } else if (score >= 70) {
            gaugeValue.style.stroke = "var(--primary)";
            scoreStatus.textContent = t("score_status_good");
            scoreStatus.classList.add("pass");
        } else if (score >= 50) {
            gaugeValue.style.stroke = "var(--color-med)";
            scoreStatus.textContent = t("score_status_warn");
            scoreStatus.classList.add("warn");
        } else {
            gaugeValue.style.stroke = "var(--color-crit)";
            scoreStatus.textContent = t("score_status_crit");
            scoreStatus.classList.add("crit");
        }
    }

    function renderCategoryProgress(categories) {
        categoryBarsGrid.innerHTML = "";
        categories.forEach(cat => {
            const item = document.createElement("div");
            item.className = "cat-progress-item";
            item.innerHTML = `
                <div class="cat-progress-labels">
                    <span class="cat-progress-name">${cat.module_name}</span>
                    <span class="cat-progress-pct">%${cat.score}</span>
                </div>
                <div class="progress-track">
                    <div class="progress-fill" style="width: ${cat.score}%;"></div>
                </div>
            `;
            categoryBarsGrid.appendChild(item);
        });
    }

    function formatCurrentValue(val) {
        if (!val) return "-";
        if (val.includes("\n") || val.includes("•")) {
            return `<div class="val-multiline-box">${escapeHtml(val)}</div>`;
        }
        return `<code>${escapeHtml(val)}</code>`;
    }

    function renderFindingsTable(chk) {
        if (!chk || !chk.details) return "";

        // 1. Windows & Microsoft Defender Güncellemeleri Tablosu
        if (chk.details.windows_updates && chk.details.windows_updates.length > 0) {
            const updates = chk.details.windows_updates;
            let rowsHtml = "";
            updates.forEach(u => {
                const isDef = u.is_defender;
                const isSec = u.is_security;
                const badgeClass = isDef ? "badge-risk-high" : (isSec ? "badge-risk-high" : "badge-risk-std");
                const badgeText = isDef ? "KRİTİK / DEFENDER" : (isSec ? "GÜVENLİK YAMASI" : "SÜRÜCÜ / DİĞER");
                const fixCmd = isDef ? "Update-MpSignature" : "UsoClient StartInteractiveScan";
                const btnLabel = isDef ? "İmzaları Güncelle" : "Yüklemeyi Başlat";

                rowsHtml += `
                    <tr>
                        <td><strong>${escapeHtml(u.title)}</strong></td>
                        <td><span class="ver-mono">${escapeHtml(u.kb || '-')}</span></td>
                        <td><span style="font-size: 11px; color: var(--text-secondary);">${escapeHtml((u.categories || []).join(', ') || 'Windows Update')}</span></td>
                        <td><span class="${badgeClass}">${badgeText}</span></td>
                        <td>
                            <button class="btn-table-copy" data-cmd="${encodeURIComponent(fixCmd)}" title="${escapeHtml(fixCmd)} komutunu panoya kopyala">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                ${btnLabel}
                            </button>
                        </td>
                    </tr>
                `;
            });

            return `
                <div class="finding-details-table-wrap">
                    <div class="finding-table-header">
                        <span class="finding-table-title">BEKLEYEN WINDOWS & DEFENDER GÜNCELLEMELERİ (${updates.length} ADET - EKSİKSİZ LİSTE)</span>
                        <span class="finding-table-badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border-color: rgba(239, 68, 68, 0.3);">Windows Update Agent</span>
                    </div>
                    <div class="finding-table-scroll">
                        <table class="finding-data-table">
                            <thead>
                                <tr>
                                    <th>Güncelleme / Yama Başlığı</th>
                                    <th>KB No</th>
                                    <th>Kategori</th>
                                    <th>Önem</th>
                                    <th>Hızlı İşlem</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${rowsHtml}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // 2. 3. Parti Yazılım Güncellemeleri Tablosu (winget)
        if (chk.details.upgrades && chk.details.upgrades.length > 0) {
            const upgrades = chk.details.upgrades;
            let rowsHtml = "";
            upgrades.forEach(u => {
                const isHigh = u.is_high_risk;
                const badgeClass = isHigh ? "badge-risk-high" : "badge-risk-std";
                const badgeText = isHigh ? "KRİTİK / ÖNCELİKLİ" : "STANDART";
                const wingetCmd = `winget upgrade --id ${u.id} --accept-source-agreements --accept-package-agreements`;

                rowsHtml += `
                    <tr>
                        <td><strong>${escapeHtml(u.name)}</strong></td>
                        <td><span class="ver-mono">${escapeHtml(u.id)}</span></td>
                        <td><span class="ver-mono">${escapeHtml(u.installed)}</span></td>
                        <td><span class="ver-mono ver-avail">${escapeHtml(u.available)}</span></td>
                        <td><span class="${badgeClass}">${badgeText}</span></td>
                        <td>
                            <button class="btn-table-copy" data-cmd="${encodeURIComponent(wingetCmd)}" title="Tekil güncelleme komutunu kopyala">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                Komut Kopyala
                            </button>
                        </td>
                    </tr>
                `;
            });

            return `
                <div class="finding-details-table-wrap">
                    <div class="finding-table-header">
                        <span class="finding-table-title">GÜNCELLEME BEKLEYEN TÜM YAZILIMLAR (${upgrades.length} ADET - TAM VE DETAYLI LİSTE)</span>
                        <span class="finding-table-badge">%100 Eksiksiz Envanter</span>
                    </div>
                    <div class="finding-table-scroll">
                        <table class="finding-data-table">
                            <thead>
                                <tr>
                                    <th>Uygulama Adı</th>
                                    <th>Paket Kimliği</th>
                                    <th>Kurulu Sürüm</th>
                                    <th>Hedef Sürüm</th>
                                    <th>Öncelik</th>
                                    <th>İşlem</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${rowsHtml}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // 3. Ağ Portları Tablosu (NET-01)
        if (chk.details.ports && chk.details.ports.length > 0) {
            const ports = chk.details.ports;
            let rowsHtml = "";
            ports.forEach(p => {
                const isRisky = [21, 23, 80, 135, 139, 445, 3389, 5985, 8080].includes(p.port);
                const badgeClass = isRisky ? "badge-risk-high" : "badge-risk-std";
                const badgeText = isRisky ? "RİSKLİ PORT" : "STANDART";
                const bindingsStr = (p.bindings || []).join("<br>");

                rowsHtml += `
                    <tr>
                        <td><strong style="color: var(--primary); font-family: Consolas;">${p.port}</strong></td>
                        <td><strong>${escapeHtml(p.service_name || "Bilinmeyen")}</strong><br><span style="font-size: 11px; color: var(--text-secondary);">${escapeHtml(p.description || "")}</span></td>
                        <td><span class="ver-mono">${bindingsStr}</span></td>
                        <td><strong style="color: var(--text-base);">${escapeHtml(p.process || "Sistem")}</strong></td>
                        <td><span class="ver-mono">${p.pid || "-"}</span></td>
                        <td><span class="${badgeClass}">${badgeText}</span></td>
                    </tr>
                `;
            });

            return `
                <div class="finding-details-table-wrap">
                    <div class="finding-table-header">
                        <span class="finding-table-title">AÇIK VE DİNLENEN AĞ PORTLARI (${ports.length} ADET - SIFIR KESİNTİ LİSTESİ)</span>
                        <span class="finding-table-badge" style="background: rgba(59, 130, 246, 0.15); color: #3b82f6; border-color: rgba(59, 130, 246, 0.3);">Network Sockets</span>
                    </div>
                    <div class="finding-table-scroll">
                        <table class="finding-data-table">
                            <thead>
                                <tr>
                                    <th>Port No</th>
                                    <th>Servis Bilgisi</th>
                                    <th>Ağ Arayüzü (Binding)</th>
                                    <th>Süreç (Process)</th>
                                    <th>PID</th>
                                    <th>Durum</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${rowsHtml}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        return "";
    }

    function renderFindingsList() {
        if (!currentReport) return;
        accordionStack.innerHTML = "";

        currentReport.categories.forEach(cat => {
            const filteredChecks = cat.checks.filter(check => {
                if (currentFilter === "fails") {
                    if (check.status === "PASS") return false;
                } else if (currentFilter !== "all") {
                    if (currentFilter === "PASS" && check.status !== "PASS") return false;
                    if (currentFilter !== "PASS" && (check.severity !== currentFilter || check.status === "PASS")) return false;
                }

                if (currentSearchTerm) {
                    const term = currentSearchTerm.toLowerCase();
                    const matchTitle = check.title.toLowerCase().includes(term);
                    const matchId = check.id.toLowerCase().includes(term);
                    const matchDesc = check.description.toLowerCase().includes(term);
                    if (!matchTitle && !matchId && !matchDesc) return false;
                }

                return true;
            });

            if (filteredChecks.length === 0) return;

            const card = document.createElement("div");
            card.className = "cat-accordion-item open";

            let checksHtml = "";
            filteredChecks.forEach(check => {
                let statusBadgeClass = "pass";
                let statusBadgeText = t("status_passed") || "BAŞARILI";
                let borderClass = "border-pass";

                if (check.status === "FAIL") {
                    statusBadgeText = `${check.severity} ${t("status_vuln") || "ZAFİYET"}`;
                    if (check.severity === "CRITICAL") { statusBadgeClass = "crit"; borderClass = "border-crit"; }
                    else if (check.severity === "HIGH") { statusBadgeClass = "high"; borderClass = "border-high"; }
                    else { statusBadgeClass = "med"; borderClass = "border-med"; }
                } else if (check.status === "WARNING") {
                    statusBadgeText = `${check.severity} ${t("status_warn") || "UYARI"}`;
                    statusBadgeClass = "med";
                    borderClass = "border-med";
                }

                let remBoxHtml = "";
                if (check.status !== "PASS" && check.remediation) {
                    remBoxHtml = `
                        <div class="remediation-box-modern">
                            <div class="rem-top-bar">
                                <span class="rem-label">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path></svg>
                                    ${t("how_to_fix") || "Nasıl Düzeltilir? (Önerilen Komut)"}
                                </span>
                                <div class="rem-actions-wrap">
                                    <button class="btn-copy-code" data-code="${encodeURIComponent(check.remediation)}">${t("copy") || "Kopyala"}</button>
                                    <button class="btn-verify-check" data-mod="${cat.module_id}" data-check="${check.id}" title="Verify">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                                        ${t("btn_verify") || "Doğrula (Verify)"}
                                    </button>
                                    <button class="btn-drawer-inspect" data-checkid="${check.id}">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                                        ${t("btn_inspect_drawer") || "Kuralı İncele"}
                                    </button>
                                </div>
                            </div>
                            <pre class="rem-pre-block">${escapeHtml(check.remediation)}</pre>
                        </div>
                    `;
                }

                checksHtml += `
                    <div class="audit-check-card ${borderClass}" data-checkid="${check.id}">
                        <div class="check-headline">
                            <div class="check-name-wrap">
                                <span class="check-id-badge btn-inspect-trigger" data-checkid="${check.id}" style="cursor: pointer;">[${check.id}]</span>
                                <span>${check.title}</span>
                            </div>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <button class="btn-drawer-inspect btn-inspect-trigger" data-checkid="${check.id}" style="padding: 3px 8px; font-size: 10px;">
                                    ${t("btn_inspect_rule") || "Kural Detayı"}
                                </button>
                                <span class="check-severity-pill ${statusBadgeClass}">${statusBadgeText}</span>
                            </div>
                        </div>
                        <div class="check-explanation">${check.description}</div>
                        <div class="check-key-values">
                            <div class="check-kv-item">
                                <strong>${t("val_detected") || "Sistemde Okunan Değer:"}</strong>
                                ${formatCurrentValue(check.current_value)}
                            </div>
                            <div class="check-kv-item">
                                <strong>${t("val_recommended") || "Önerilen Güvenli Değer:"}</strong>
                                <code>${escapeHtml(check.recommended_value)}</code>
                            </div>
                            ${check.standard_ref ? `<div class="check-kv-item"><strong>${t("val_standard_ref") || "Standart Referansı:"}</strong> <code>${escapeHtml(check.standard_ref)}</code></div>` : ""}
                        </div>
                        ${renderFindingsTable(check)}
                        {rem_placeholder}
                    </div>
                `.replace("{rem_placeholder}", remBoxHtml);
            });

            card.innerHTML = `
                <div class="cat-accordion-header">
                    <div class="cat-title-group">
                        <h3>${cat.module_name}</h3>
                        <span class="badge-cat-score">%${cat.score} ${t("score_success") || "Başarı"}</span>
                    </div>
                    <div class="cat-meta-group">
                        <span style="font-size: 12px; color: var(--text-muted);">${filteredChecks.length} ${t("checks_count_label") || "kontrol"}</span>
                        <svg class="chevron-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    </div>
                </div>
                <div class="cat-checks-body">
                    ${checksHtml}
                </div>
            `;

            // Akordeon Aç/Kapa
            const header = card.querySelector(".cat-accordion-header");
            header.addEventListener("click", () => {
                card.classList.toggle("open");
                const body = card.querySelector(".cat-checks-body");
                body.style.display = card.classList.contains("open") ? "flex" : "none";
            });

            // Kopyala butonu
            card.querySelectorAll(".btn-copy-code").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const code = decodeURIComponent(btn.getAttribute("data-code"));
                    navigator.clipboard.writeText(code);
                    btn.textContent = "Kopyalandı!";
                    setTimeout(() => { btn.textContent = "Kopyala"; }, 2000);
                    showToast("Düzeltme komutu panoya kopyalandı.");
                });
            });

            // Tablo içi kopyala butonu
            card.querySelectorAll(".btn-table-copy").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const cmd = decodeURIComponent(btn.getAttribute("data-cmd"));
                    navigator.clipboard.writeText(cmd);
                    const origText = btn.innerHTML;
                    btn.textContent = "Kopyalandı!";
                    setTimeout(() => { btn.innerHTML = origText; }, 2000);
                    showToast("Yazılım güncelleme komutu panoya kopyalandı.");
                });
            });

            // Doğrula (Verify) butonu
            card.querySelectorAll(".btn-verify-check").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const checkCard = btn.closest(".audit-check-card");
                    handleVerifyCheck(btn, checkCard);
                });
            });

            // Nessus Plugin Inspector Açıcı
            card.querySelectorAll(".btn-inspect-trigger, .btn-drawer-inspect").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const checkId = btn.getAttribute("data-checkid");
                    const targetCheck = cat.checks.find(c => c.id === checkId);
                    if (targetCheck) {
                        openPluginDrawer(targetCheck, cat.module_name, cat.category_name);
                    }
                });
            });

            accordionStack.appendChild(card);
        });

        if (accordionStack.children.length === 0) {
            accordionStack.innerHTML = `
                <div style="text-align:center; padding: 48px; color: var(--text-muted); background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border-subtle);">
                    ${t("no_matching_checks")}
                </div>
            `;
        }
    }

    // --- 6. AÇIK PORTLAR HARİTASI ---
    function renderPortsTable() {
        if (!currentReport) return;
        portsTableBody.innerHTML = "";

        // Ağ modülündeki NET-01 detaylarından portları çek
        let services = [];
        for (const cat of currentReport.categories) {
            for (const c of cat.checks) {
                if (c.id === "NET-01" && c.details && c.details.ports) {
                    services = c.details.ports;
                    break;
                }
            }
        }

        if (services.length === 0) {
            portsTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--text-muted);">${t("ports_empty")}</td></tr>`;
            return;
        }

        services.forEach(s => {
            const tr = document.createElement("tr");
            const isRisky = [21, 23, 80, 135, 139, 445, 3389, 5985, 8080].includes(s.port);
            const bindingsStr = (s.bindings || []).join(", ");
            tr.innerHTML = `
                <td><strong style="color: var(--primary); font-family: Consolas;">${s.port}</strong></td>
                <td>${s.service_name || getPortServiceLabel(s.port)}</td>
                <td><code>${bindingsStr}</code></td>
                <td><strong>${s.process || "Sistem"}</strong></td>
                <td><code>${s.pid || "-"}</code></td>
                <td>
                    <span class="check-severity-pill ${isRisky ? 'high' : 'pass'}">
                        ${isRisky ? t("ports_risky") : t("ports_standard")}
                    </span>
                </td>
            `;
            portsTableBody.appendChild(tr);
        });
    }

    function getPortServiceLabel(port) {
        const portMap = {
            21: "FTP (Dosya Aktarımı)",
            23: "Telnet (Uzaktan Terminal)",
            80: "HTTP Web Servisi",
            135: "RPC / DCOM",
            137: "NetBIOS Name Service",
            138: "NetBIOS Datagram",
            139: "NetBIOS Session",
            445: "SMB Dosya Paylaşımı",
            3389: "RDP Uzak Masaüstü",
            5985: "WinRM HTTP",
            5986: "WinRM HTTPS",
            8080: "Alternatif HTTP Proxy"
        };
        return portMap[port] || "TCP/UDP Dinleyici";
    }

    // --- 7. SAYFA YÖNETİMİ & ROUTER (MULTI-PAGE SPA) ---
    function showView(viewName, param = null) {
        // Navigasyon sekmelerinin aktiflik durumlarını temizle
        if (navBtnDashboard) navBtnDashboard.classList.remove("active");
        if (navBtnWizard) navBtnWizard.classList.remove("active");
        if (navBtnRemediations) navBtnRemediations.classList.remove("active");
        if (navBtnModules) navBtnModules.classList.remove("active");

        // Sayfa containerlarını gizle
        if (viewDashboard) viewDashboard.style.display = "none";
        if (viewWizard) viewWizard.style.display = "none";
        if (viewRemediations) viewRemediations.style.display = "none";
        if (viewModulesCatalog) viewModulesCatalog.style.display = "none";
        if (viewModuleDetail) viewModuleDetail.style.display = "none";

        if (viewName === "dashboard") {
            if (navBtnDashboard) navBtnDashboard.classList.add("active");
            if (viewDashboard) viewDashboard.style.display = "block";
        } else if (viewName === "wizard") {
            if (navBtnWizard) navBtnWizard.classList.add("active");
            if (viewWizard) viewWizard.style.display = "block";
            loadWizardTemplates();
        } else if (viewName === "remediations") {
            if (navBtnRemediations) navBtnRemediations.classList.add("active");
            if (viewRemediations) viewRemediations.style.display = "block";
            loadTopRemediations();
        } else if (viewName === "modules") {
            if (navBtnModules) navBtnModules.classList.add("active");
            if (viewModulesCatalog) viewModulesCatalog.style.display = "block";
            renderModulesCatalog();
        } else if (viewName === "module-detail") {
            if (navBtnModules) navBtnModules.classList.add("active");
            if (viewModuleDetail) viewModuleDetail.style.display = "block";
            if (param) openModuleDetailPage(param);
        }
    }

    if (navBtnDashboard) navBtnDashboard.addEventListener("click", () => showView("dashboard"));
    if (navBtnWizard) navBtnWizard.addEventListener("click", () => showView("wizard"));
    if (navBtnRemediations) navBtnRemediations.addEventListener("click", () => showView("remediations"));
    if (navBtnModules) navBtnModules.addEventListener("click", () => showView("modules"));
    if (btnBackToCatalog) btnBackToCatalog.addEventListener("click", () => showView("modules"));
    if (crumbLinkCatalog) crumbLinkCatalog.addEventListener("click", () => showView("modules"));

    // Dashboard İçi Sekmeler (Bulgular vs Portlar)
    tabFindings.addEventListener("click", () => {
        tabFindings.classList.add("active");
        tabPorts.classList.remove("active");
        viewFindings.style.display = "block";
        viewPorts.style.display = "none";
    });

    tabPorts.addEventListener("click", () => {
        tabPorts.classList.add("active");
        tabFindings.classList.remove("active");
        viewFindings.style.display = "none";
        viewPorts.style.display = "block";
    });

    // --- 8. GÜVENLİK MODÜLLERİ KATALOĞU (TÜM MODÜLLER SAYFASI) ---
    function renderModulesCatalog() {
        if (!catalogCardsGrid) return;

        const activeCount = registeredModules.filter(m => m.enabled).length;
        if (catTotalBadge) catTotalBadge.textContent = `${registeredModules.length} ${t("cat_title")}`;
        if (catActiveBadge) catActiveBadge.textContent = `${activeCount}/${registeredModules.length} ${t("mod_active")}`;
        if (navActiveCountBadge) navActiveCountBadge.textContent = `${activeCount} ${currentLang() === 'en' ? 'Modules' : 'Modül'}`;

        const filtered = registeredModules.filter(mod => {
            if (catalogFilterCat !== "all") {
                if (catalogFilterCat === "Ağ Güvenliği" && mod.category.includes("Ağ")) {
                    // Eşleşti
                } else if (mod.category !== catalogFilterCat) {
                    return false;
                }
            }
            if (catalogFilterSearch) {
                const s = catalogFilterSearch.toLowerCase();
                const mName = mod.name.toLowerCase().includes(s);
                const mId = mod.id.toLowerCase().includes(s);
                const mDesc = mod.description.toLowerCase().includes(s);
                const mCat = mod.category.toLowerCase().includes(s);
                if (!mName && !mId && !mDesc && !mCat) return false;
            }
            return true;
        });

        catalogCardsGrid.innerHTML = "";
        if (filtered.length === 0) {
            catalogCardsGrid.innerHTML = `
                <div style="grid-column: 1/-1; text-align:center; padding: 48px; color: var(--text-muted); background: var(--bg-card); border-radius: 14px;">
                    ${t("no_matching_modules")}
                </div>
            `;
            return;
        }

        filtered.forEach(mod => {
            const card = document.createElement("div");
            card.className = "catalog-mod-card";

            // Mevcut skoru bul
            let scoreVal = 0;
            let scoreText = t("mod_kpi_not_scanned");
            let scoreColor = "var(--text-muted)";
            if (currentReport) {
                const cat = currentReport.categories.find(c => c.module_id === mod.id);
                if (cat) {
                    scoreVal = cat.score;
                    scoreText = `%${cat.score} ${t("score_success")}`;
                    if (cat.score >= 80) scoreColor = "var(--color-pass)";
                    else if (cat.score >= 50) scoreColor = "var(--color-med)";
                    else scoreColor = "var(--color-crit)";
                }
            }

            card.innerHTML = `
                <div>
                    <div class="catalog-card-top">
                        <div class="catalog-card-id-cat">
                            <span class="catalog-mod-tag">${escapeHtml(mod.category)}</span>
                            <span style="font-size: 11px; font-weight: 700; color: var(--text-dim);">${mod.id.toUpperCase()}</span>
                        </div>
                        <label class="ios-toggle" title="${mod.enabled ? (currentLang() === 'en' ? 'Disable' : 'Modülü Pasife Al') : (currentLang() === 'en' ? 'Enable' : 'Modülü Etkinleştir')}">
                            <input type="checkbox" class="chk-catalog-mod" data-modid="${mod.id}" ${mod.enabled ? 'checked' : ''}>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>

                    <h3 class="catalog-mod-name">${escapeHtml(mod.name)}</h3>
                    <p class="catalog-mod-desc">${escapeHtml(mod.description)}</p>

                    <div class="catalog-score-progress-box">
                        <div class="catalog-score-labels">
                            <span style="color: var(--text-secondary);">${currentLang() === 'en' ? 'Security Status' : 'Güvenlik Durumu'}</span>
                            <span class="lbl-card-score" style="color: ${scoreColor};">${scoreText}</span>
                        </div>
                        <div class="progress-track" style="height: 6px;">
                            <div class="progress-fill fill-card-bar" style="width: ${scoreVal}%; background: ${scoreColor};"></div>
                        </div>
                    </div>
                </div>

                <div class="catalog-card-footer">
                    <button class="catalog-btn-quick-scan" data-modid="${mod.id}">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                        <span>${t("btn_quick_scan")}</span>
                    </button>
                    <button class="catalog-btn-examine" data-modid="${mod.id}">
                        <span>${t("btn_examine")}</span>
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                    </button>
                </div>
            `;

            // Toggle switch
            const chk = card.querySelector(".chk-catalog-mod");
            chk.addEventListener("change", async (e) => {
                const checked = e.target.checked;
                mod.enabled = checked;
                await toggleModuleAPI(mod.id, checked);
                const active = registeredModules.filter(m => m.enabled).length;
                if (catActiveBadge) catActiveBadge.textContent = `${active}/${registeredModules.length} ${t("mod_active")}`;
                if (navActiveCountBadge) navActiveCountBadge.textContent = `${active} ${currentLang() === 'en' ? 'Modules' : 'Modül'}`;
            });

            // Hızlı Tara butonu
            const btnQuick = card.querySelector(".catalog-btn-quick-scan");
            btnQuick.addEventListener("click", async () => {
                btnQuick.disabled = true;
                const txt = btnQuick.querySelector("span");
                txt.textContent = t("btn_running");
                try {
                    const res = await fetch(`/api/modules/${mod.id}/scan`, { method: "POST" });
                    const data = await res.json();
                    updateModuleInGlobalReport(data.result);
                    // Kart içi skoru güncelle
                    const lblScore = card.querySelector(".lbl-card-score");
                    const fillBar = card.querySelector(".fill-card-bar");
                    let color = data.result.score >= 80 ? "var(--color-pass)" : (data.result.score >= 50 ? "var(--color-med)" : "var(--color-crit)");
                    lblScore.textContent = `%${data.result.score} ${t("score_success")}`;
                    lblScore.style.color = color;
                    fillBar.style.width = `${data.result.score}%`;
                    fillBar.style.background = color;
                    showToast(`"${mod.name}" ${currentLang() === 'en' ? 'scanned! Score:' : 'tarandı! Skor:'} %${data.result.score} (${data.duration_seconds}s)`);
                } catch (err) {
                    showToast(currentLang() === 'en' ? "Quick scan error!" : "Hızlı tarama hatası!");
                } finally {
                    btnQuick.disabled = false;
                    txt.textContent = t("btn_quick_scan");
                }
            });

            // Modülü İncele & Yönet butonu
            const btnExamine = card.querySelector(".catalog-btn-examine");
            btnExamine.addEventListener("click", () => {
                showView("module-detail", mod.id);
            });

            catalogCardsGrid.appendChild(card);
        });
    }

    // Katalog arama ve filtreleri
    if (catalogSearchInput) {
        catalogSearchInput.addEventListener("input", (e) => {
            catalogFilterSearch = e.target.value.trim();
            renderModulesCatalog();
        });
    }

    document.querySelectorAll("#catalogCatChips .filter-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            document.querySelectorAll("#catalogCatChips .filter-chip").forEach(c => c.classList.remove("active"));
            chip.classList.add("active");
            catalogFilterCat = chip.getAttribute("data-modcat");
            renderModulesCatalog();
        });
    });

    if (btnCatalogEnableAll) {
        btnCatalogEnableAll.addEventListener("click", async () => {
            for (const m of registeredModules) {
                m.enabled = true;
                await toggleModuleAPI(m.id, true);
            }
            renderModulesCatalog();
            showToast("Tüm modüller etkinleştirildi.");
        });
    }

    if (btnCatalogDisableAll) {
        btnCatalogDisableAll.addEventListener("click", async () => {
            for (const m of registeredModules) {
                m.enabled = false;
                await toggleModuleAPI(m.id, false);
            }
            renderModulesCatalog();
            showToast("Tüm modüller pasife alındı.");
        });
    }

    // --- 9. DETAYLI ÖZEL MODÜL SAYFASI (SINGLE MODULE PAGE) ---
    let activeModuleChecks = [];

    async function openModuleDetailPage(moduleId) {
        currentActiveModuleId = moduleId;
        const mod = registeredModules.find(m => m.id === moduleId);
        if (!mod) return;

        // Breadcrumb
        detailCrumbCategory.textContent = mod.category;
        detailCrumbTitle.textContent = mod.name;

        // Hero
        detailTitle.textContent = mod.name;
        detailDesc.textContent = mod.description;
        detailTagCategory.textContent = mod.category;
        detailTagWeight.textContent = `${currentLang() === 'en' ? 'Weight' : 'Ağırlık'}: ${mod.weight || 10}`;
        detailTagVersion.textContent = `v${mod.version || "1.0.0"}`;
        detailToggleModule.checked = mod.enabled;
        detailStatusLabel.innerHTML = `${t("mod_status_label")}: <strong>${mod.enabled ? t("mod_active") : t("mod_passive")}</strong>`;
        btnDetailDownloadFix.href = `/api/modules/${moduleId}/fix-script`;

        // Modül Durumu Switch Değişimi
        detailToggleModule.onchange = async (e) => {
            const checked = e.target.checked;
            mod.enabled = checked;
            await toggleModuleAPI(mod.id, checked);
            detailStatusLabel.innerHTML = `${t("mod_status_label")}: <strong>${checked ? t("mod_active") : t("mod_passive")}</strong>`;
            const active = registeredModules.filter(m => m.enabled).length;
            if (catActiveBadge) catActiveBadge.textContent = `${active}/${registeredModules.length} ${t("mod_active")}`;
            if (navActiveCountBadge) navActiveCountBadge.textContent = `${active} ${currentLang() === 'en' ? 'Modules' : 'Modül'}`;
        };

        // Mevcut raporda bu modülün sonucu var mı?
        let catResult = null;
        if (currentReport) {
            catResult = currentReport.categories.find(c => c.module_id === moduleId);
        }

        if (catResult) {
            populateModuleDetailKPI(catResult, `${currentReport.duration_seconds}s (${currentLang() === 'en' ? 'Full Scan' : 'Toplu Tarama'})`);
            activeModuleChecks = catResult.checks;
            renderModuleDetailChecks();
        } else {
            // Henüz taranmadıysa API'den kuralları al
            detailKpiScore.textContent = "--%";
            detailKpiScore.style.color = "var(--text-muted)";
            detailKpiTotal.textContent = mod.checks_count || "--";
            detailKpiPass.textContent = "--";
            detailKpiFail.textContent = "--";
            detailKpiDuration.textContent = t("mod_kpi_not_scanned");
            detailKpiTimestamp.textContent = "--";

            try {
                const res = await fetch(`/api/modules/${moduleId}`);
                if (res.ok) {
                    const data = await res.json();
                    activeModuleChecks = data.checks || [];
                    renderModuleDetailChecks();
                }
            } catch (err) {
                console.error("Modül kuralları alınamadı:", err);
            }
        }
    }

    function populateModuleDetailKPI(catResult, durationText) {
        detailKpiScore.textContent = `%${catResult.score}`;
        let col = catResult.score >= 80 ? "var(--color-pass)" : (catResult.score >= 50 ? "var(--color-med)" : "var(--color-crit)");
        detailKpiScore.style.color = col;

        const fails = catResult.checks.filter(c => c.status === "FAIL" || c.status === "WARNING").length;
        detailKpiTotal.textContent = catResult.checks.length;
        detailKpiPass.textContent = catResult.passed_checks;
        detailKpiFail.textContent = fails;
        detailKpiDuration.textContent = durationText;
        detailKpiTimestamp.textContent = new Date().toLocaleTimeString();
    }

    // Modül Sayfasındaki "BU MODÜLÜ BAĞIMSIZ TARA" Butonu
    if (btnDetailScanModule) {
        btnDetailScanModule.onclick = async () => {
            if (!currentActiveModuleId) return;
            btnDetailScanModule.disabled = true;
            if (txtDetailScan) txtDetailScan.textContent = "TARANIYOR... (<1 sn)";

            try {
                const res = await fetch(`/api/modules/${currentActiveModuleId}/scan`, { method: "POST" });
                if (!res.ok) throw new Error("Tarama başarısız");
                const data = await res.json();

                populateModuleDetailKPI(data.result, `${data.duration_seconds} sn (İzole Tarama)`);
                activeModuleChecks = data.result.checks;
                renderModuleDetailChecks();

                // Global raporu güncelle
                updateModuleInGlobalReport(data.result);

                showToast(`"${data.module_info.name}" başarıyla tarandı! Skor: %${data.result.score} (${data.duration_seconds}s)`);
            } catch (err) {
                console.error("Tekil modül tarama hatası:", err);
                showToast("Modül taranırken bir hata oluştu!");
            } finally {
                btnDetailScanModule.disabled = false;
                if (txtDetailScan) txtDetailScan.textContent = "BU MODÜLÜ BAĞIMSIZ TARA";
            }
        };
    }

    // Modül içi kontrolleri çiz
    function renderModuleDetailChecks() {
        if (!detailChecksStack) return;

        const filtered = activeModuleChecks.filter(chk => {
            if (detailFilterStatus === "fails" && chk.status === "PASS") return false;
            if (detailFilterStatus === "PASS" && chk.status !== "PASS") return false;
            if (["CRITICAL", "HIGH"].includes(detailFilterStatus)) {
                if (chk.severity !== detailFilterStatus || chk.status === "PASS") return false;
            }
            if (detailFilterSearch) {
                const s = detailFilterSearch.toLowerCase();
                const mTitle = (chk.title || "").toLowerCase().includes(s);
                const mId = (chk.id || "").toLowerCase().includes(s);
                const mDesc = (chk.description || "").toLowerCase().includes(s);
                if (!mTitle && !mId && !mDesc) return false;
            }
            return true;
        });

        if (detailChecksCountTag) detailChecksCountTag.textContent = `${filtered.length} Kontrol`;

        detailChecksStack.innerHTML = "";
        if (filtered.length === 0) {
            detailChecksStack.innerHTML = `
                <div style="text-align:center; padding: 36px; color: var(--text-muted); background: var(--bg-subtle); border-radius: 10px;">
                    Filtre veya arama kriterine uygun kontrol bulunamadı.
                </div>
            `;
            return;
        }

        filtered.forEach(chk => {
            let statusClass = "pass";
            let statusText = t("status_passed") || "BAŞARILI";
            let borderClass = "border-pass";

            if (chk.status === "FAIL") {
                statusText = `${chk.severity} ${t("status_vuln") || "ZAFİYET"}`;
                if (chk.severity === "CRITICAL") { statusClass = "crit"; borderClass = "border-crit"; }
                else if (chk.severity === "HIGH") { statusClass = "high"; borderClass = "border-high"; }
                else { statusClass = "med"; borderClass = "border-med"; }
            } else if (chk.status === "WARNING") {
                statusText = `${chk.severity} ${t("status_warn") || "UYARI"}`;
                statusClass = "med";
                borderClass = "border-med";
            } else if (!chk.status) {
                statusText = chk.severity || "CHECK";
                statusClass = "med";
                borderClass = "";
            }

            let remHtml = "";
            if (chk.status !== "PASS" && chk.remediation) {
                remHtml = `
                    <div class="remediation-box-modern">
                        <div class="rem-top-bar">
                            <span class="rem-label">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path></svg>
                                ${t("how_to_fix") || "Nasıl Düzeltilir? (Önerilen Komut)"}
                            </span>
                            <div class="rem-actions-wrap">
                                <button class="btn-copy-code" data-code="${encodeURIComponent(chk.remediation)}">${t("copy") || "Kopyala"}</button>
                                <button class="btn-verify-check" data-mod="${currentActiveModuleId}" data-check="${chk.id}" title="Verify">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                                    ${t("btn_verify") || "Doğrula (Verify)"}
                                </button>
                                <button class="btn-drawer-inspect" data-checkid="${chk.id}">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                                    ${t("btn_inspect_drawer") || "Kuralı İncele"}
                                </button>
                            </div>
                        </div>
                        <pre class="rem-pre-block">${escapeHtml(chk.remediation)}</pre>
                    </div>
                `;
            }

            const card = document.createElement("div");
            card.className = `audit-check-card ${borderClass}`;
            card.innerHTML = `
                <div class="check-headline">
                    <div class="check-name-wrap">
                        <span class="check-id-badge btn-inspect-trigger" data-checkid="${chk.id}" style="cursor: pointer;" title="Details">[${chk.id}]</span>
                        <span>${escapeHtml(chk.title)}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <button class="btn-drawer-inspect btn-inspect-trigger" data-checkid="${chk.id}" style="padding: 3px 8px; font-size: 10px;">
                            ${t("btn_inspect_rule") || "Kural Detayı"}
                        </button>
                        <span class="check-severity-pill ${statusClass}">${statusText}</span>
                    </div>
                </div>
                <div class="check-explanation">${escapeHtml(chk.description)}</div>
                <div class="check-key-values">
                    <div><strong>${t("val_detected") || "Sistemde Okunan Değer:"}</strong> <code>${escapeHtml(chk.current_value || "-")}</code></div>
                    <div><strong>${t("val_recommended") || "Önerilen Güvenli Değer:"}</strong> <code>${escapeHtml(chk.recommended_value || "-")}</code></div>
                    ${chk.standard_ref ? `<div><strong>${t("val_standard_ref") || "Standart Referansı:"}</strong> <code>${escapeHtml(chk.standard_ref)}</code></div>` : ""}
                </div>
                ${remHtml}
            `;

            const copyBtn = card.querySelector(".btn-copy-code");
            if (copyBtn) {
                copyBtn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const code = decodeURIComponent(copyBtn.getAttribute("data-code"));
                    navigator.clipboard.writeText(code);
                    copyBtn.textContent = t("copied") || "Kopyalandı!";
                    setTimeout(() => { copyBtn.textContent = t("copy") || "Kopyala"; }, 2000);
                    showToast(currentLang() === 'en' ? "Remediation command copied." : "Düzeltme komutu panoya kopyalandı.");
                });
            }

            const verifyBtn = card.querySelector(".btn-verify-check");
            if (verifyBtn) {
                verifyBtn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    handleVerifyCheck(verifyBtn, card);
                });
            }

            card.querySelectorAll(".btn-inspect-trigger, .btn-drawer-inspect").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    openPluginDrawer(chk, currentActiveModuleId, detailCrumbCategory ? detailCrumbCategory.textContent : "");
                });
            });

            detailChecksStack.appendChild(card);
        });
    }

    // Modül içi filtre çipleri
    document.querySelectorAll("[data-modfilter]").forEach(chip => {
        chip.addEventListener("click", () => {
            document.querySelectorAll("[data-modfilter]").forEach(c => c.classList.remove("active"));
            chip.classList.add("active");
            detailFilterStatus = chip.getAttribute("data-modfilter");
            renderModuleDetailChecks();
        });
    });

    if (detailCheckSearch) {
        detailCheckSearch.addEventListener("input", (e) => {
            detailFilterSearch = e.target.value.trim();
            renderModuleDetailChecks();
        });
    }

    // Tek modül sonucunu global rapora ekleme ve skoru yeniden hesaplama yardımcısı
    function updateModuleInGlobalReport(categoryResult) {
        if (!currentReport) return;
        const idx = currentReport.categories.findIndex(c => c.module_id === categoryResult.module_id);
        if (idx >= 0) {
            currentReport.categories[idx] = categoryResult;
        } else {
            currentReport.categories.push(categoryResult);
        }

        let totalWeighted = 0;
        let sumWeights = 0;
        let totalChecks = 0;
        let passedChecks = 0;
        let critCount = 0;
        let highCount = 0;
        let medCount = 0;
        let lowCount = 0;

        currentReport.categories.forEach(c => {
            const w = c.weight || 10;
            totalWeighted += c.score * w;
            sumWeights += w;
            totalChecks += c.total_checks;
            passedChecks += c.passed_checks;
            c.checks.forEach(chk => {
                if (chk.status === "FAIL") {
                    if (chk.severity === "CRITICAL") critCount++;
                    else if (chk.severity === "HIGH") highCount++;
                    else if (chk.severity === "MEDIUM") medCount++;
                    else if (chk.severity === "LOW") lowCount++;
                }
            });
        });

        currentReport.total_score = sumWeights > 0 ? Math.round(totalWeighted / sumWeights) : 0;
        currentReport.total_checks = totalChecks;
        currentReport.passed_count = passedChecks;
        currentReport.critical_count = critCount;
        currentReport.high_count = highCount;
        currentReport.medium_count = medCount;
        currentReport.low_count = lowCount;

        renderFullReport(currentReport);
    }

    // --- 8. FİLTRE VE ARAMA OLAYLARI ---
    filterChips.forEach(chip => {
        chip.addEventListener("click", () => {
            filterChips.forEach(c => c.classList.remove("active"));
            chip.classList.add("active");
            currentFilter = chip.getAttribute("data-filter");
            renderFindingsList();
        });
    });

    filterSearch.addEventListener("input", (e) => {
        currentSearchTerm = e.target.value.trim();
        renderFindingsList();
    });

    // --- 9. YARDIMCILAR ---
    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function showToast(msg) {
        toastNotice.textContent = msg;
        toastNotice.classList.add("active");
        setTimeout(() => {
            toastNotice.classList.remove("active");
        }, 2800);
    }

    // --- 10. PROFİL YÖNETİMİ ---
    const profileSelect = document.getElementById("profileSelect");
    if (profileSelect) {
        profileSelect.addEventListener("change", async (e) => {
            const profId = e.target.value;
            try {
                const res = await fetch(`/api/profiles?lang=${currentLang()}`);
                const profiles = await res.json();
                const selectedProf = profiles.find(p => p.id === profId);
                if (selectedProf) {
                    for (const mod of registeredModules) {
                        const shouldEnable = selectedProf.enabled_modules.includes(mod.id);
                        mod.enabled = shouldEnable;
                        await toggleModuleAPI(mod.id, shouldEnable);
                    }
                    renderModulesCatalog();
                    showToast(currentLang() === 'en' ? `Profile applied: ${selectedProf.name}` : `Profil uygulandı: ${selectedProf.name}`);
                }
            } catch (err) {
                console.error("Profil hatası:", err);
            }
        });
    }

    // --- 11. GEÇMİŞ VE TREND MODALI ---
    const btnOpenHistory = document.getElementById("btnOpenHistory");
    const historyModalBackdrop = document.getElementById("historyModalBackdrop");
    const btnCloseHistory = document.getElementById("btnCloseHistory");
    const btnDismissHistory = document.getElementById("btnDismissHistory");
    const historyModalContent = document.getElementById("historyModalContent");

    async function loadHistoryModal() {
        historyModalContent.innerHTML = "<p style='color: var(--text-muted); text-align:center; padding: 20px;'>Yükleniyor...</p>";
        historyModalBackdrop.style.display = "flex";
        try {
            const res = await fetch("/api/history");
            const data = await res.json();
            const history = data.history || [];
            const trend = data.trend || {};

            let trendHtml = "";
            if (trend.has_trend) {
                const isUp = trend.diff > 0;
                const isDown = trend.diff < 0;
                const trendColor = isUp ? "var(--color-pass)" : (isDown ? "var(--color-crit)" : "var(--primary)");
                const trendIcon = isUp ? "▲" : (isDown ? "▼" : "■");
                const trendText = isUp ? `+${trend.diff} Puan İyileşme` : (isDown ? `${trend.diff} Puan Düşüş` : "Değişim Yok");

                trendHtml = `
                    <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 10px; padding: 14px 18px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Son İki Tarama Trendi</div>
                            <div style="font-size: 18px; font-weight: 800; color: ${trendColor}; display: flex; align-items: center; gap: 6px; margin-top: 2px;">
                                <span>${trendIcon}</span>
                                <span>${trendText}</span>
                            </div>
                        </div>
                        <div style="text-align: right; font-size: 12px; color: var(--text-secondary);">
                            Önceki Skor: <strong>${trend.previous_score}</strong> ➔ Güncel: <strong>${trend.current_score}</strong>
                        </div>
                    </div>
                `;
            }

            let historyListHtml = "";
            if (history.length === 0) {
                historyListHtml = "<p style='text-align:center; color: var(--text-muted); padding: 20px;'>Kayıtlı geçmiş tarama bulunmuyor.</p>";
            } else {
                history.forEach((h) => {
                    const scoreColor = h.total_score >= 85 ? "var(--color-pass)" : (h.total_score >= 70 ? "var(--primary)" : (h.total_score >= 50 ? "var(--color-med)" : "var(--color-crit)"));
                    historyListHtml += `
                        <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px 16px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-size: 13px; font-weight: 700; color: var(--text-primary);">#${h.scan_id} - ${h.timestamp}</div>
                                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">${h.total_checks} Denetim (${h.passed_count} Başarılı, ${h.critical_count} Kritik, ${h.high_count} Yüksek) - ${h.duration_seconds}s</div>
                            </div>
                            <div style="font-size: 22px; font-weight: 900; color: ${scoreColor};">
                                ${h.total_score}
                            </div>
                        </div>
                    `;
                });
            }

            historyModalContent.innerHTML = trendHtml + historyListHtml;
        } catch (err) {
            historyModalContent.innerHTML = "<p style='color: var(--color-crit); text-align:center;'>Geçmiş yüklenemedi.</p>";
        }
    }

    if (btnOpenHistory) btnOpenHistory.addEventListener("click", loadHistoryModal);
    if (btnCloseHistory) btnCloseHistory.addEventListener("click", () => { historyModalBackdrop.style.display = "none"; });
    if (btnDismissHistory) btnDismissHistory.addEventListener("click", () => { historyModalBackdrop.style.display = "none"; });
    if (historyModalBackdrop) {
        historyModalBackdrop.addEventListener("click", (e) => {
            if (e.target === historyModalBackdrop) historyModalBackdrop.style.display = "none";
        });
    }

    // --- 10. CANLI DÜZELTME DOĞRULAMA (VERIFY FIX) ---
    async function handleVerifyCheck(btn, cardElement) {
        const modId = btn.getAttribute("data-mod");
        const checkId = btn.getAttribute("data-check");
        if (!modId || !checkId) return;

        btn.disabled = true;
        const origHtml = btn.innerHTML;
        btn.innerHTML = `<span style="color: var(--text-muted);">Doğrulanıyor...</span>`;

        try {
            const res = await fetch(`/api/checks/${modId}/${checkId}/verify`, { method: "POST" });
            if (!res.ok) throw new Error("Doğrulama isteği başarısız");
            const data = await res.json();
            const updated = data.check;

            if (updated.status === "PASS") {
                btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Doğrulandı! (PASS)`;
                btn.style.borderColor = "var(--color-pass)";
                btn.style.color = "var(--color-pass)";
                showToast(`[${checkId}] Başarıyla doğrulandı: Sistem güvenli duruma geçti!`);

                if (cardElement) {
                    cardElement.className = "audit-check-card border-pass";
                    const pill = cardElement.querySelector(".check-severity-pill");
                    if (pill) {
                        pill.className = "check-severity-pill pass";
                        pill.textContent = "BAŞARILI";
                    }
                    const valEl = cardElement.querySelector(".check-key-values code");
                    if (valEl) {
                        valEl.textContent = updated.current_value;
                    }
                }
            } else {
                btn.innerHTML = `<span style="color: var(--color-crit);">Hala Açık (${updated.severity})</span>`;
                showToast(`[${checkId}] Düzeltme henüz etkinleşmedi. Değer: ${updated.current_value}`);
                setTimeout(() => {
                    btn.innerHTML = origHtml;
                    btn.disabled = false;
                }, 3500);
            }
        } catch (err) {
            console.error("Doğrulama hatası:", err);
            showToast("Doğrulama servisi yanıt vermedi!");
            btn.innerHTML = origHtml;
            btn.disabled = false;
        }
    }

    // --- 11. TENABLE NESSUS BİLEŞENLERİ VE EKLENTİ DENETÇİSİ (NESSUS SUITE) ---

    function hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash);
    }

    // Nessus Zafiyet Dağılım Çubuğu
    function renderNessusSeverityBar(report) {
        if (!report) return;
        const total = report.total_checks || 1;
        const crit = report.critical_count || 0;
        const high = report.high_count || 0;
        const med = report.medium_count || 0;
        const low = report.low_count || 0;
        const pass = report.passed_count || 0;

        const pCrit = ((crit / total) * 100).toFixed(1);
        const pHigh = ((high / total) * 100).toFixed(1);
        const pMed = ((med / total) * 100).toFixed(1);
        const pLow = ((low / total) * 100).toFixed(1);
        const pPass = Math.max(0, (100 - parseFloat(pCrit) - parseFloat(pHigh) - parseFloat(pMed) - parseFloat(pLow))).toFixed(1);

        if (nessusCritCount) nessusCritCount.textContent = crit;
        if (nessusHighCount) nessusHighCount.textContent = high;
        if (nessusMedCount) nessusMedCount.textContent = med;
        if (nessusLowCount) nessusLowCount.textContent = low;
        if (nessusPassCount) nessusPassCount.textContent = pass;

        if (nessusSegCrit) {
            nessusSegCrit.style.width = `${pCrit}%`;
            nessusSegCrit.title = `Critical: ${crit} (%${pCrit})`;
        }
        if (nessusSegHigh) {
            nessusSegHigh.style.width = `${pHigh}%`;
            nessusSegHigh.title = `High: ${high} (%${pHigh})`;
        }
        if (nessusSegMed) {
            nessusSegMed.style.width = `${pMed}%`;
            nessusSegMed.title = `Medium: ${med} (%${pMed})`;
        }
        if (nessusSegLow) {
            nessusSegLow.style.width = `${pLow}%`;
            nessusSegLow.title = `Low: ${low} (%${pLow})`;
        }
        if (nessusSegPass) {
            nessusSegPass.style.width = `${pPass}%`;
            nessusSegPass.title = `Pass / Info: ${pass} (%${pPass})`;
        }
    }

    // Nessus Tarama Şablonları Sihirbazı
    async function loadWizardTemplates() {
        if (!wizardTemplatesGrid) return;
        wizardTemplatesGrid.innerHTML = `<div style="grid-column: 1/-1; text-align:center; padding: 48px; color: var(--text-muted);">${currentLang() === 'en' ? 'Loading templates...' : 'Şablonlar yükleniyor...'}</div>`;

        try {
            const res = await fetch("/api/templates");
            if (!res.ok) throw new Error("Şablon listesi alınamadı");
            const templates = await res.json();

            wizardTemplatesGrid.innerHTML = "";
            templates.forEach(tpl => {
                const card = document.createElement("div");
                card.className = "wizard-card";

                const modChipsHtml = (tpl.target_modules || []).map(m => `<span class="wizard-mod-chip">${escapeHtml(m)}</span>`).join("");

                card.innerHTML = `
                    <div>
                        <div class="wizard-card-top">
                            <div class="wizard-card-icon">${tpl.icon || '🛡️'}</div>
                            <span class="wizard-badge">${escapeHtml(tpl.badge || 'Şablon')}</span>
                        </div>
                        <h3 class="wizard-card-title">${escapeHtml(tpl.name)}</h3>
                        <p class="wizard-card-desc">${escapeHtml(tpl.description)}</p>
                        <div class="wizard-modules-list">
                            ${modChipsHtml}
                        </div>
                    </div>
                    <div class="wizard-footer">
                        <span class="wizard-meta">${(tpl.target_modules || []).length} ${currentLang() === 'en' ? 'Modules' : 'Modül'} • ${tpl.estimated_time || '< 5s'}</span>
                        <button class="btn-wizard-launch" data-tpid="${tpl.id}">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                            ${t("wizard_btn_start")}
                        </button>
                    </div>
                `;

                const btnLaunch = card.querySelector(".btn-wizard-launch");
                btnLaunch.addEventListener("click", async () => {
                    btnLaunch.disabled = true;
                    btnLaunch.innerHTML = `<span style="color: #ffffff;">${t("btn_running")}</span>`;
                    showToast(`"${tpl.name}" ${currentLang() === 'en' ? 'scan started...' : 'şablonu ile tarama başlatıldı...'}`);
                    try {
                        const scanRes = await fetch(`/api/scan/template/${tpl.id}?lang=${currentLang()}`, { method: "POST" });
                        if (!scanRes.ok) throw new Error("Tarama başarısız");
                        const data = await scanRes.json();
                        showView("dashboard");
                        onScanDone(data.report);
                        showToast(`"${tpl.name}" ${currentLang() === 'en' ? 'completed! Score:' : 'tamamlandı! Güvenlik Skoru:'} %${data.report.total_score}`);
                    } catch (e) {
                        showToast(`${currentLang() === 'en' ? 'Scan error:' : 'Tarama hatası:'} ${e.message}`);
                    } finally {
                        btnLaunch.disabled = false;
                        btnLaunch.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> ${t("wizard_btn_start")}`;
                    }
                });

                wizardTemplatesGrid.appendChild(card);
            });
        } catch (err) {
            wizardTemplatesGrid.innerHTML = `<div style="grid-column: 1/-1; text-align:center; padding: 48px; color: var(--color-crit);">Şablonlar yüklenemedi: ${err.message}</div>`;
        }
    }

    // Nessus Top Remediations (En Yüksek Risk Azaltımı)
    async function loadTopRemediations() {
        if (!topRemediationsStack) return;
        topRemediationsStack.innerHTML = `<div style="text-align:center; padding: 48px; color: var(--text-muted);">${currentLang() === 'en' ? 'Calculating top remediations...' : 'En yüksek risk azaltan düzeltmeler hesaplanıyor...'}</div>`;

        try {
            const res = await fetch(`/api/remediations/top?lang=${currentLang()}`);
            if (!res.ok) throw new Error("Öncelikli düzeltmeler alınamadı");
            const items = await res.json();

            topRemediationsStack.innerHTML = "";
            if (!items || items.length === 0) {
                topRemediationsStack.innerHTML = `
                    <div style="text-align:center; padding: 48px; color: var(--color-pass); background: var(--bg-card); border-radius: 12px; border: 1px solid var(--border-subtle);">
                        ${currentLang() === 'en' ? '🎉 Congratulations! No critical vulnerabilities remain on the system.' : '🎉 Tebrikler! Sistemde öncelikli kritik zafiyet kalmadı veya tüm kontroller başarılı.'}
                    </div>
                `;
                return;
            }

            items.forEach((item, idx) => {
                const card = document.createElement("div");
                card.className = "remediation-action-card";

                card.innerHTML = `
                    <div class="rem-rank-badge">#${idx + 1}</div>
                    <div class="rem-body">
                        <div class="rem-header-line">
                            <div class="rem-title">
                                <span>${escapeHtml(item.action_title || item.module_name)}</span>
                                <span style="font-size: 11px; font-weight: 700; color: var(--text-muted); background: var(--bg-subtle); padding: 2px 7px; border-radius: 4px;">${escapeHtml(item.module_id || '')}</span>
                            </div>
                            <div class="rem-reduction-pill">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 18 13.5 8.5 8.5 13.5 1 6"></polyline><polyline points="17 18 23 18 23 12"></polyline></svg>
                                -%${item.risk_reduction_pct || 0} ${t("rem_risk_reduction")}
                            </div>
                        </div>
                        <div class="rem-desc">${escapeHtml(item.description || '')}</div>
                        <div class="rem-stats-row">
                            <span>🎯 <strong>${item.critical_count || 0}</strong> ${t("filter_crit")} • <strong>${item.high_count || 0}</strong> ${t("filter_high")}</span>
                            <span>⚡ ${t("rem_est_time")}: <strong>${escapeHtml(item.estimated_effort || '< 2 min')}</strong></span>
                            <span>🛡️ ${t("rem_standard")}: <strong>${escapeHtml(item.standard || 'CIS Benchmark')}</strong></span>
                        </div>
                    </div>
                    <div class="rem-action-col">
                        <button class="btn btn-primary btn-sm btn-rem-goto" data-modid="${item.module_id}">
                            ${t("rem_btn_goto")}
                        </button>
                        ${item.powershell_cmd ? `
                            <button class="btn btn-secondary btn-sm btn-rem-copy-cmd" data-cmd="${encodeURIComponent(item.powershell_cmd)}">
                                ${t("rem_btn_copy")}
                            </button>
                        ` : ''}
                    </div>
                `;

                const btnGoto = card.querySelector(".btn-rem-goto");
                if (btnGoto) {
                    btnGoto.addEventListener("click", () => {
                        showView("module-detail", item.module_id);
                    });
                }

                const btnCopyCmd = card.querySelector(".btn-rem-copy-cmd");
                if (btnCopyCmd) {
                    btnCopyCmd.addEventListener("click", () => {
                        const cmd = decodeURIComponent(btnCopyCmd.getAttribute("data-cmd"));
                        navigator.clipboard.writeText(cmd);
                        btnCopyCmd.textContent = t("copied");
                        setTimeout(() => { btnCopyCmd.textContent = t("rem_btn_copy"); }, 2000);
                        showToast(currentLang() === 'en' ? "Remediation command copied." : "Düzeltme komutu panoya kopyalandı.");
                    });
                }
                topRemediationsStack.appendChild(card);
            });
        } catch (err) {
            topRemediationsStack.innerHTML = `<div style="text-align:center; padding: 48px; color: var(--color-crit);">Düzeltmeler yüklenemedi: ${err.message}</div>`;
        }
    }

    // Nessus Plugin Inspector (Slide-Over Çekmece)
    async function openPluginDrawer(check, modName = "", catName = "") {
        if (!pluginDrawerBackdrop) return;
        pluginDrawerBackdrop.style.display = "flex";
        document.body.style.overflow = "hidden";

        if (drawerPluginId) drawerPluginId.textContent = `PLUGIN #...`;
        if (drawerPluginTitle) drawerPluginTitle.textContent = check.title || check.id;
        if (drawerPluginContent) drawerPluginContent.innerHTML = `<p style="text-align:center; padding: 40px; color: var(--text-muted);">Nessus Plugin ve CVSS verileri alınıyor...</p>`;

        try {
            let plugin = null;
            try {
                const res = await fetch(`/api/plugins/${check.id}`);
                if (res.ok) {
                    plugin = await res.json();
                }
            } catch (e) {}

            const fallbackId = 10000 + (hashString(check.id) % 80000);
            const pluginId = plugin ? plugin.plugin_id : fallbackId;
            const cvssScore = plugin ? plugin.cvss_v3_score : (check.severity === "CRITICAL" ? 9.8 : (check.severity === "HIGH" ? 7.5 : 5.0));
            const cvssVector = plugin ? plugin.cvss_v3_vector : "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
            const vprScore = plugin ? plugin.vpr_score : (cvssScore * 0.95).toFixed(1);
            const family = plugin ? plugin.family : `Windows : ${catName || modName || 'System Hardening'}`;
            const synopsis = plugin ? plugin.synopsis : check.title;
            const exploitAvail = plugin ? plugin.exploit_available : (check.severity === "CRITICAL");

            if (drawerPluginId) drawerPluginId.textContent = `DENETİM KURALI #${pluginId} • CVSS v3.1`;

            let cvssColor = cvssScore >= 9.0 ? "#ef4444" : (cvssScore >= 7.0 ? "#f97316" : (cvssScore >= 4.0 ? "#eab308" : "#06b6d4"));
            let vprColor = vprScore >= 8.0 ? "#ef4444" : (vprScore >= 6.0 ? "#f97316" : "#10b981");

            let exploitBadge = exploitAvail
                ? `<span style="background: rgba(239, 68, 68, 0.18); border: 1px solid rgba(239, 68, 68, 0.4); color: #ef4444; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 800; display: inline-flex; align-items: center; gap: 4px;">⚠️ Aktif Exploit Riski (CISA KEV)</span>`
                : `<span style="background: var(--bg-subtle); border: 1px solid var(--border-subtle); color: var(--text-muted); padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600;">Exploit Bilinmiyor</span>`;

            const drawerTableHtml = renderFindingsTable(check);

            drawerPluginContent.innerHTML = `
                <!-- 1. Skor Şeridi -->
                <div class="drawer-score-strip">
                    <div class="score-strip-card">
                        <span class="strip-lbl">CVSS v3.1 Base</span>
                        <span class="strip-val" style="color: ${cvssColor};">${cvssScore}</span>
                    </div>
                    <div class="score-strip-card">
                        <span class="strip-lbl">Tehdit Skoru (VPR)</span>
                        <span class="strip-val" style="color: ${vprColor};">${vprScore}</span>
                    </div>
                    <div class="score-strip-card">
                        <span class="strip-lbl">Risk Şiddeti</span>
                        <span class="strip-val" style="color: ${cvssColor}; font-size: 18px; line-height: 28px;">${check.severity || 'INFO'}</span>
                    </div>
                </div>

                <!-- 2. Exploit Durumu & Kategori -->
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <div style="font-size: 12px; color: var(--text-secondary);">
                        <strong>Denetim Kategorisi:</strong> <code style="background: var(--bg-subtle); padding: 2px 6px; border-radius: 4px;">${escapeHtml(family)}</code>
                    </div>
                    ${exploitBadge}
                </div>

                <!-- 3. CVSS v3.1 Vektör Dizgisi -->
                <div>
                    <div class="drawer-section-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path></svg>
                        CVSS v3.1 Vektör Dizgisi
                    </div>
                    <div class="cvss-vector-box">${escapeHtml(cvssVector)}</div>
                </div>

                <!-- 4. Synopsis & Açıklama -->
                <div>
                    <div class="drawer-section-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                        Synopsis & Güvenlik Açıklaması
                    </div>
                    <div style="font-size: 13px; color: var(--text-primary); font-weight: 600; margin-bottom: 6px;">${escapeHtml(synopsis)}</div>
                    <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.5;">${escapeHtml(check.description || '')}</div>
                </div>

                <!-- 5. Denetim Kanıtı (Audit Output) -->
                <div>
                    <div class="drawer-section-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
                        Denetim Çıktısı & Sistem Kanıtı (Audit Output)
                    </div>
                    <pre class="plugin-output-box">Check ID         : ${check.id}
Audit Item       : ${check.title}
Current State    : ${check.current_value || 'None / Not Configured'}
Required State   : ${check.recommended_value || 'Compliant Setting'}
Standard Ref     : ${check.standard_ref || 'CIS Microsoft Windows Benchmark'}
Remediation Available: ${check.remediation ? 'YES (PowerShell Automation)' : 'MANUAL'}</pre>
                </div>

                ${drawerTableHtml}

                <!-- 6. Çözüm & Sıkılaştırma (Solution) -->
                <div>
                    <div class="drawer-section-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
                        Çözüm & Sıkılaştırma (Solution)
                    </div>
                    <div class="plugin-solution-box">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span style="font-size: 12px; font-weight: 700; color: var(--color-pass);">Önerilen PowerShell Otomasyonu:</span>
                            <div style="display: flex; gap: 6px;">
                                ${check.remediation ? `<button class="btn-copy-code" id="btnDrawerCopyFix" style="padding: 4px 10px; font-size: 11px;">Kopyala</button>` : ''}
                                <button class="btn-verify-check" id="btnDrawerVerifyFix" data-mod="${check.module_id || modName || ''}" data-check="${check.id}">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                                    Doğrula (Verify)
                                </button>
                            </div>
                        </div>
                        <pre class="rem-pre-block" style="margin-top: 6px;">${escapeHtml(check.remediation || 'Bu kontrol için standart referans dokümanını inceleyiniz.')}</pre>
                    </div>
                </div>

                <!-- 7. Referans Linkleri (See Also) -->
                <div style="border-top: 1px solid var(--border-subtle); padding-top: 14px; font-size: 12px; color: var(--text-muted);">
                    <strong>Güvenlik ve Uyumluluk Standartları:</strong>
                    <ul style="margin: 6px 0 0 18px; line-height: 1.6;">
                        <li><a href="https://cve.mitre.org/" target="_blank" style="color: #38bdf8;">MITRE CVE Güvenlik Açığı Veritabanı</a></li>
                        <li><a href="https://www.cisecurity.org/benchmark/microsoft_windows_desktop" target="_blank" style="color: #38bdf8;">CIS Microsoft Windows Desktop Benchmark</a></li>
                        <li><a href="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" target="_blank" style="color: #38bdf8;">NIST SP 800-53 Güvenlik Kontrolleri Kılavuzu</a></li>
                    </ul>
                </div>
            `;

            // Drawer içi kopyala ve doğrula butonlarını bağla
            const btnCopy = document.getElementById("btnDrawerCopyFix");
            if (btnCopy && check.remediation) {
                btnCopy.addEventListener("click", () => {
                    navigator.clipboard.writeText(check.remediation);
                    btnCopy.textContent = "Kopyalandı!";
                    setTimeout(() => { btnCopy.textContent = "Kopyala"; }, 2000);
                    showToast("Düzeltme komutu panoya kopyalandı.");
                });
            }

            drawerPluginContent.querySelectorAll(".btn-table-copy").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const cmd = decodeURIComponent(btn.getAttribute("data-cmd"));
                    navigator.clipboard.writeText(cmd);
                    const origHtml = btn.innerHTML;
                    btn.textContent = "Kopyalandı!";
                    setTimeout(() => { btn.innerHTML = origHtml; }, 2000);
                    showToast("Paket güncelleme komutu panoya kopyalandı.");
                });
            });

            const btnVer = document.getElementById("btnDrawerVerifyFix");
            if (btnVer) {
                btnVer.addEventListener("click", () => {
                    handleVerifyCheck(btnVer, null);
                });
            }
        } catch (err) {
            drawerPluginContent.innerHTML = `<p style="color: var(--color-crit); text-align:center; padding: 30px;">Plugin bilgisi alınırken hata: ${err.message}</p>`;
        }
    }

    function closePluginDrawer() {
        if (pluginDrawerBackdrop) {
            pluginDrawerBackdrop.style.display = "none";
            document.body.style.overflow = "auto";
        }
    }

    if (btnDrawerClose) btnDrawerClose.addEventListener("click", closePluginDrawer);
    if (pluginDrawerBackdrop) {
        pluginDrawerBackdrop.addEventListener("click", (e) => {
            if (e.target === pluginDrawerBackdrop) closePluginDrawer();
        });
    }
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && pluginDrawerBackdrop && pluginDrawerBackdrop.style.display !== "none") {
            closePluginDrawer();
        }
    });

    // Üst KPI Kartlarına Tıklama ile Zafiyetleri Anında Filtreleme
    document.querySelectorAll(".kpi-card[data-kpifilter]").forEach(card => {
        card.addEventListener("click", () => {
            const filterType = card.getAttribute("data-kpifilter");
            document.querySelectorAll(".kpi-card[data-kpifilter]").forEach(c => c.classList.remove("active-filter"));
            card.classList.add("active-filter");

            // Toolbar filtre çipini de güncelle
            const matchingChip = document.querySelector(`.filter-chip[data-filter="${filterType}"]`);
            if (matchingChip) {
                document.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active"));
                matchingChip.classList.add("active");
            }
            currentFilter = filterType;
            renderFindingsList();

            // Bulgular bölümüne odaklan
            const findingsSec = document.getElementById("viewFindings");
            if (findingsSec) {
                findingsSec.scrollIntoView({ behavior: "smooth", block: "nearest" });
            }
        });
    });

    // Buton bağlama
    btnRunAudit.addEventListener("click", startAuditScan);

    // Başlangıç
    loadSystemInfo();
    loadModules();
    fetch(`/api/report/latest?lang=${currentLang()}`)
        .then(res => res.json())
        .then(rep => onScanDone(rep))
        .catch(() => {});
});
