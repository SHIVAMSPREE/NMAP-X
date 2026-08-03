document.addEventListener('DOMContentLoaded', () => {
    console.log('NMAP-X Reconnaissance Platform initialized.');

    // Highlight active route in sidebar
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPath || (currentPath === '/' && href === '/dashboard')) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    // Mobile navigation drawer toggle
    const toggleBtn = document.getElementById('mobile-menu-toggle');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    if (toggleBtn && sidebar && overlay) {
        const toggleMenu = () => {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('active');
        };

        toggleBtn.addEventListener('click', toggleMenu);
        overlay.addEventListener('click', toggleMenu);

        // Close mobile drawer when a nav link is clicked
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (sidebar.classList.contains('open')) {
                    sidebar.classList.remove('open');
                    overlay.classList.remove('active');
                }
            });
        });
    }

    // Update real-time uptime clock on navbar
    const timeDisplay = document.getElementById('navbar-time');
    if (timeDisplay) {
        const updateTime = () => {
            const now = new Date();
            timeDisplay.textContent = now.toUTCString().replace('GMT', 'UTC');
        };
        updateTime();
        setInterval(updateTime, 1000);
    }
});

// Logging Helper
function appendInstallationLog(msg) {
    const logElem = document.getElementById('installation-log');
    if (logElem) {
        const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
        logElem.textContent += `\n[${timestamp}] ${msg}`;
        logElem.scrollTop = logElem.scrollHeight;
    }
}

function clearInstallationLogs() {
    const logElem = document.getElementById('installation-log');
    if (logElem) {
        logElem.textContent = "Logs cleared.";
    }
}

// Single Tool Installation Handler
async function installSingleTool(toolKey) {
    return retryInstallTool(toolKey);
}

// Retry Tool Installation Handler
async function retryInstallTool(toolKey) {
    appendInstallationLog(`Initiating installation / verification for tool '${toolKey}'...`);

    const statusCell = document.getElementById(`status-cell-${toolKey}`);
    const dashStatusCell = document.getElementById(`dash-status-${toolKey}`);
    const msgCell = document.getElementById(`msg-cell-${toolKey}`);
    const dashMsgCell = document.getElementById(`dash-msg-${toolKey}`);
    const btn = document.getElementById(`btn-install-${toolKey}`);
    const dashBtn = document.getElementById(`dash-btn-${toolKey}`);

    const installingBadge = `
        <span style="color: var(--accent-red); font-weight: bold; padding: 2px 8px; border: 1px solid var(--accent-red); border-radius: 4px; background: rgba(255, 0, 60, 0.1);">
            <i class="fa-solid fa-spinner fa-spin"></i> INSTALLING
        </span>
    `;

    if (statusCell) statusCell.innerHTML = installingBadge;
    if (dashStatusCell) dashStatusCell.innerHTML = installingBadge;
    if (msgCell) msgCell.textContent = `Executing automated installer for ${toolKey}...`;
    if (dashMsgCell) dashMsgCell.textContent = `Executing automated installer for ${toolKey}...`;

    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Installing...'; }
    if (dashBtn) { dashBtn.disabled = true; dashBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Installing...'; }

    try {
        const resp = await fetch('/api/v1/tools/retry-install', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool: toolKey })
        });
        const data = await resp.json();

        if (data.command) appendInstallationLog(`Command: ${data.command}`);
        if (data.formatted_exit_code) appendInstallationLog(`Installer Exit Code: ${data.formatted_exit_code}`);
        if (data.output) appendInstallationLog(`Output:\n${data.output}`);

        const finalStatus = data.status || (data.success ? 'ONLINE' : 'INSTALL FAILED');
        const actMsg = data.actionable_message || data.error || data.output || 'Installation completed.';

        appendInstallationLog(`STATUS FOR '${toolKey}': ${finalStatus} — ${actMsg}`);
        updateToolUI(toolKey, finalStatus, data.path, data.version, actMsg);
        return data.success;
    } catch (err) {
        appendInstallationLog(`NETWORK / API ERROR installing '${toolKey}': ${err.message}`);
        updateToolUI(toolKey, 'INSTALL FAILED', null, null, `Network error: ${err.message}`);
        return false;
    }
}

// Sequential Batch Tool Installation
async function installAllMissingTools() {
    const tools = ['nmap', 'dnsmap', 'urlcrazy', 'whois', 'dnsrecon', 'dig', 'wafw00f', 'wget', 'nikto', 'requests', 'beautifulsoup4', 'lxml', 'rich'];
    appendInstallationLog("=== BATCH DEPENDENCY INSTALLATION INITIATED ===");

    const btnAll = document.getElementById('btn-install-all');
    const dashBtnAll = document.getElementById('btn-dashboard-install-all');

    if (btnAll) { btnAll.disabled = true; btnAll.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing Batch...'; }
    if (dashBtnAll) { dashBtnAll.disabled = true; dashBtnAll.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing Batch...'; }

    try {
        const resp = await fetch('/api/v1/tools/status');
        const data = await resp.json();
        const statuses = data.tool_statuses || {};

        let installedCount = 0;
        let skippedCount = 0;
        let failedCount = 0;

        for (const toolKey of tools) {
            const info = statuses[toolKey] || {};
            if (info.status === 'ONLINE') {
                appendInstallationLog(`Skipping '${toolKey}' (already ONLINE).`);
                skippedCount++;
                continue;
            }

            if (info.status === 'UNSUPPORTED ON OS') {
                appendInstallationLog(`Skipping '${toolKey}' (UNSUPPORTED ON OS - requires Linux/WSL).`);
                skippedCount++;
                continue;
            }

            appendInstallationLog(`Processing batch item: '${toolKey}'...`);
            const ok = await retryInstallTool(toolKey);
            if (ok) installedCount++; else failedCount++;
        }

        appendInstallationLog(`=== BATCH COMPLETED === Installed: ${installedCount}, Skipped/Unsupported: ${skippedCount}, Failed: ${failedCount}`);
    } catch (e) {
        appendInstallationLog(`Batch installation exception: ${e.message}`);
    } finally {
        if (btnAll) { btnAll.disabled = false; btnAll.innerHTML = '<i class="fa-solid fa-download"></i> Install All Missing Dependencies'; }
        if (dashBtnAll) { dashBtnAll.disabled = false; dashBtnAll.innerHTML = '<i class="fa-solid fa-download"></i> Install All Missing Tools'; }
    }
}

// Refresh tool statuses via API
async function refreshToolStatuses() {
    appendInstallationLog("Refreshing tool statuses...");
    try {
        const resp = await fetch('/api/v1/tools/check-all', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        const data = await resp.json();
        const statuses = data.tool_statuses || {};

        for (const [toolKey, info] of Object.entries(statuses)) {
            updateToolUI(toolKey, info.status, info.path, info.version, info.actionable_message);
        }
        appendInstallationLog("Tool statuses refreshed successfully.");
    } catch (err) {
        appendInstallationLog(`Failed to refresh tool statuses: ${err.message}`);
    }
}

// Helper to update DOM status elements across tables
function updateToolUI(toolKey, status, path, version, message) {
    const statusCell = document.getElementById(`status-cell-${toolKey}`);
    const dashStatusCell = document.getElementById(`dash-status-${toolKey}`);
    const msgCell = document.getElementById(`msg-cell-${toolKey}`);
    const dashMsgCell = document.getElementById(`dash-msg-${toolKey}`);
    const actionCell = document.getElementById(`action-cell-${toolKey}`);
    const dashActionCell = document.getElementById(`dash-action-${toolKey}`);

    let badgeHTML = '';
    if (status === 'ONLINE') {
        badgeHTML = `
            <span style="color: var(--success-green); font-weight: bold; padding: 2px 8px; border: 1px solid var(--success-green); border-radius: 4px; background: rgba(0, 255, 65, 0.1);">
                <i class="fa-solid fa-circle-check"></i> ONLINE
            </span>`;
    } else if (status === 'UNSUPPORTED ON CURRENT OS') {
        badgeHTML = `
            <span style="color: #a855f7; font-weight: bold; padding: 2px 8px; border: 1px solid #a855f7; border-radius: 4px; background: rgba(168, 85, 247, 0.1);">
                <i class="fa-solid fa-ban"></i> UNSUPPORTED ON OS
            </span>`;
    } else if (status === 'NOT INSTALLED') {
        badgeHTML = `
            <span style="color: var(--warning-amber); font-weight: bold; padding: 2px 8px; border: 1px solid var(--warning-amber); border-radius: 4px; background: rgba(255, 170, 0, 0.1);">
                <i class="fa-solid fa-triangle-exclamation"></i> NOT INSTALLED
            </span>`;
    } else if (status === 'INSTALLED BUT NOT ON PATH') {
        badgeHTML = `
            <span style="color: #3b82f6; font-weight: bold; padding: 2px 8px; border: 1px solid #3b82f6; border-radius: 4px; background: rgba(59, 130, 246, 0.1);">
                <i class="fa-solid fa-folder-open"></i> NOT ON PATH
            </span>`;
    } else if (status === 'PACKAGE INSTALLED BUT EXECUTABLE NOT FOUND') {
        badgeHTML = `
            <span style="color: #f97316; font-weight: bold; padding: 2px 8px; border: 1px solid #f97316; border-radius: 4px; background: rgba(249, 115, 22, 0.1);">
                <i class="fa-solid fa-file-excel"></i> EXE NOT FOUND
            </span>`;
    } else {
        badgeHTML = `
            <span style="color: var(--accent-red); font-weight: bold; padding: 2px 8px; border: 1px solid var(--accent-red); border-radius: 4px; background: rgba(255, 0, 60, 0.1);">
                <i class="fa-solid fa-circle-xmark"></i> ${status}
            </span>`;
    }

    if (statusCell) statusCell.innerHTML = badgeHTML;
    if (dashStatusCell) dashStatusCell.innerHTML = badgeHTML;

    const pathMsgHTML = (path ? `<div style="color: #fff; font-weight: 500;">${path}</div>` : '') +
                        `<div>${message || ''}</div>`;

    if (msgCell) msgCell.innerHTML = pathMsgHTML;
    if (dashMsgCell) dashMsgCell.innerHTML = pathMsgHTML;

    const actionHTML = (status === 'ONLINE') ?
        `<span style="color: var(--success-green); font-family: var(--font-mono); font-size: 0.8rem;"><i class="fa-solid fa-check"></i> Ready</span>` :
        `<button onclick="retryInstallTool('${toolKey}')" class="btn btn-primary" style="padding: 3px 8px; font-size: 0.78rem;" id="btn-install-${toolKey}">
            <i class="fa-solid fa-arrows-rotate"></i> Retry / Install
        </button>`;

    if (actionCell) actionCell.innerHTML = actionHTML;
    if (dashActionCell) dashActionCell.innerHTML = actionHTML;
}
