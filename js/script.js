/**
 * SecureScan - Web Application Security Risk Prioritization and Reporting System
 * Frontend Client Controller
 */

// Global state for current view
let currentFindings = [];
let activeScanId = null;

// Initialize on page load
document.addEventListener("DOMContentLoaded", function () {
    const pathname = window.location.pathname;

    // Determine current page
    if (pathname.endsWith("index.html") || pathname === "/" || pathname.endsWith("/")) {
        initIndexPage();
    } else if (pathname.includes("scan.html")) {
        initScanPage();
    } else if (pathname.includes("scanning.html")) {
        initScanningPage();
    } else if (pathname.includes("results.html")) {
        initResultsPage();
    } else if (pathname.includes("report.html")) {
        initReportPage();
    }
});


// -----------------------------------------------------------------------------
// Index Page Handler
// -----------------------------------------------------------------------------
function initIndexPage() {
    const startScanBtn = document.getElementById("startScanBtn");
    if (startScanBtn) {
        startScanBtn.addEventListener("click", function () {
            window.location.href = "scan.html";
        });
    }
}


// -----------------------------------------------------------------------------
// Scan Page Handler
// -----------------------------------------------------------------------------
function initScanPage() {
    // Check if target was previously saved
    const savedURL = localStorage.getItem("targetURL");
    const urlInput = document.getElementById("websiteURL");
    if (savedURL && urlInput && !urlInput.value) {
        urlInput.value = savedURL;
    }
}

async function startScan() {
    const urlInput = document.getElementById("websiteURL");
    const consentCheckbox = document.getElementById("authConsent");
    const zapFileInput = document.getElementById("zapFile");
    const scanBtn = document.getElementById("scanButton");

    const targetUrl = urlInput ? urlInput.value.trim() : "";

    if (!targetUrl) {
        alert("Please enter a valid website URL.");
        if (urlInput) urlInput.focus();
        return;
    }

    if (consentCheckbox && !consentCheckbox.checked) {
        alert("Authorization required: Please check the authorization consent box to confirm authorized testing / lab use.");
        consentCheckbox.focus();
        return;
    }

    // Save target URL
    localStorage.setItem("targetURL", targetUrl);

    // Prepare multipart form data
    const formData = new FormData();
    formData.append("target_url", targetUrl);
    formData.append("consent", "1");

    if (zapFileInput && zapFileInput.files.length > 0) {
        formData.append("zap_file", zapFileInput.files[0]);
    }

    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.textContent = "⏳ Submitting Security Scan...";
    }

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (response.ok && data.success) {
            localStorage.setItem("scanId", data.scan_id);
            window.location.href = `scanning.html?scan_id=${data.scan_id}`;
        } else {
            alert("Error initiating scan: " + (data.error || "Server error"));
            if (scanBtn) {
                scanBtn.disabled = false;
                scanBtn.textContent = "🔍 Start Security Scan";
            }
        }
    } catch (err) {
        console.error("Scan submission failed:", err);
        alert("Failed to connect to backend server. Make sure the Flask application is running.");
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.textContent = "🔍 Start Security Scan";
        }
    }
}


// -----------------------------------------------------------------------------
// Scanning Page Handler (Progress Simulation & Endpoint Polling)
// -----------------------------------------------------------------------------
function initScanningPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get("scan_id") || localStorage.getItem("scanId");
    const savedURL = localStorage.getItem("targetURL");

    const targetURLEl = document.getElementById("targetURL");
    if (targetURLEl && savedURL) {
        targetURLEl.textContent = savedURL;
    }

    if (!scanId) {
        // Fallback to fetch latest scan
        fetch("/api/scans/latest")
            .then(res => res.json())
            .then(data => {
                if (data && data.id) {
                    runScanSimulation(data.id);
                } else {
                    runScanSimulation(1);
                }
            })
            .catch(() => runScanSimulation(1));
    } else {
        runScanSimulation(scanId);
    }
}

function runScanSimulation(scanId) {
    activeScanId = scanId;
    const progressFill = document.getElementById("progressFill");
    const progressText = document.getElementById("progressText");
    const progressLabel = document.getElementById("progressStatusLabel");

    const steps = [
        { id: "step1", icon: "stepIcon1", percent: 25, label: "Connecting to application..." },
        { id: "step2", icon: "stepIcon2", percent: 55, label: "Checking security configuration..." },
        { id: "step3", icon: "stepIcon3", percent: 85, label: "Analyzing vulnerabilities & calculating risk..." },
        { id: "step4", icon: "stepIcon4", percent: 100, label: "Finalizing risk prioritized security report..." }
    ];

    let currentStepIndex = 0;

    const interval = setInterval(async () => {
        if (currentStepIndex < steps.length) {
            const step = steps[currentStepIndex];

            if (progressFill) progressFill.style.width = `${step.percent}%`;
            if (progressText) progressText.textContent = `${step.percent}%`;
            if (progressLabel) progressLabel.textContent = step.label;

            const stepEl = document.getElementById(step.id);
            const iconEl = document.getElementById(step.icon);

            if (stepEl) stepEl.classList.add("active");
            if (iconEl) iconEl.textContent = "✓";

            currentStepIndex++;
        } else {
            clearInterval(interval);
            // Verify backend status and redirect
            try {
                const res = await fetch(`/api/scan/${scanId}/status`);
                const data = await res.json();
                if (data.target_url) {
                    localStorage.setItem("targetURL", data.target_url);
                }
            } catch (e) {
                console.warn("Status fetch completed:", e);
            }

            setTimeout(() => {
                window.location.href = `results.html?scan_id=${scanId}`;
            }, 600);
        }
    }, 600);
}


// -----------------------------------------------------------------------------
// Results Page Handler (Findings API, Prioritization, Severity Chart, Modal)
// -----------------------------------------------------------------------------
async function initResultsPage() {
    const urlParams = new URLSearchParams(window.location.search);
    let scanId = urlParams.get("scan_id") || localStorage.getItem("scanId");

    if (!scanId) {
        try {
            const latestRes = await fetch("/api/scans/latest");
            if (latestRes.ok) {
                const latest = await latestRes.json();
                scanId = latest.id;
            }
        } catch (e) {
            console.error("No scans found:", e);
        }
    }

    if (!scanId) {
        console.warn("No active scan ID found.");
        return;
    }

    activeScanId = scanId;

    try {
        // 1. Fetch scan summary
        const summaryRes = await fetch(`/api/scan/${scanId}/summary`);
        if (summaryRes.ok) {
            const summary = await summaryRes.json();
            renderSummary(summary);
        }

        // 2. Fetch findings list
        const findingsRes = await fetch(`/api/scan/${scanId}/findings`);
        if (findingsRes.ok) {
            const findingsData = await findingsRes.json();
            currentFindings = findingsData.findings || [];
            renderFindingsTable(currentFindings);
        }
    } catch (err) {
        console.error("Failed to load results:", err);
    }
}

function renderSummary(summary) {
    const resultURL = document.getElementById("resultURL");
    if (resultURL && summary.target_url) {
        resultURL.textContent = summary.target_url;
    }

    const totalEl = document.getElementById("totalCount");
    const critEl = document.getElementById("critCount");
    const highEl = document.getElementById("highCount");
    const medEl = document.getElementById("medCount");
    const lowEl = document.getElementById("lowCount");

    if (totalEl) totalEl.textContent = summary.total_findings;
    if (critEl) critEl.textContent = summary.critical_count;
    if (highEl) highEl.textContent = summary.high_count;
    if (medEl) medEl.textContent = summary.medium_count;
    if (lowEl) lowEl.textContent = summary.low_count;

    // Update Overall Risk Badge
    const riskBadge = document.getElementById("riskBadge");
    const riskDescription = document.getElementById("riskDescription");

    if (riskBadge && summary.overall_risk_level) {
        riskBadge.textContent = summary.overall_risk_level;
        if (summary.overall_risk_level.includes("CRITICAL")) {
            riskBadge.style.background = "#dc2626";
            if (riskDescription) {
                riskDescription.textContent = "Critical security vulnerabilities detected! Exploitable flaws require immediate remediation.";
            }
        } else if (summary.overall_risk_level.includes("HIGH")) {
            riskBadge.style.background = "#ea580c";
            if (riskDescription) {
                riskDescription.textContent = "High-priority issues were detected. Immediate defensive action is strongly advised.";
            }
        } else if (summary.overall_risk_level.includes("MEDIUM")) {
            riskBadge.style.background = "#d97706";
            if (riskDescription) {
                riskDescription.textContent = "Moderate risk vulnerabilities detected. Implement defensive controls to prevent privilege escalation.";
            }
        } else {
            riskBadge.style.background = "#16a34a";
            if (riskDescription) {
                riskDescription.textContent = "Only low or informational issues detected. Maintain standard security hygiene.";
            }
        }
    }

    // Update Severity Distribution Chart Bars
    const total = summary.total_findings || 1;
    const barCrit = document.getElementById("barCritical");
    const barHigh = document.getElementById("barHigh");
    const barMed = document.getElementById("barMedium");
    const barLow = document.getElementById("barLow");

    if (barCrit) barCrit.style.width = `${(summary.critical_count / total) * 100}%`;
    if (barHigh) barHigh.style.width = `${(summary.high_count / total) * 100}%`;
    if (barMed) barMed.style.width = `${(summary.medium_count / total) * 100}%`;
    if (barLow) barLow.style.width = `${(summary.low_count / total) * 100}%`;

    const countCrit = document.getElementById("countCritical");
    const countHigh = document.getElementById("countHigh");
    const countMed = document.getElementById("countMedium");
    const countLow = document.getElementById("countLow");

    if (countCrit) countCrit.textContent = summary.critical_count;
    if (countHigh) countHigh.textContent = summary.high_count;
    if (countMed) countMed.textContent = summary.medium_count;
    if (countLow) countLow.textContent = summary.low_count;
}

function renderFindingsTable(findings) {
    const container = document.getElementById("vulnerabilityRows");
    if (!container) return;

    container.innerHTML = "";

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="table-row" style="text-align: center; padding: 20px; color: #64748b;">
                <span>No security vulnerabilities detected in the uploaded assessment report.</span>
            </div>
        `;
        return;
    }

    findings.forEach((f, idx) => {
        const severityClass = (f.severity || "Low").toLowerCase() + "-text";
        const row = document.createElement("div");
        row.className = "table-row table-row-clickable";
        row.style.gridTemplateColumns = "2fr 1.2fr 1fr 1fr";
        row.title = "Click to view remediation knowledge base and secure code fix";
        row.onclick = () => showRemediationModal(idx);

        row.innerHTML = `
            <div>
                <strong>#${f.priority_rank}. ${escapeHtml(f.alert_name)}</strong>
                <small style="display: block; color: #64748b; font-size: 12px; margin-top: 3px;">
                    ${f.param ? `Parameter: <code>${escapeHtml(f.param)}</code>` : "General endpoint issue"}
                </small>
            </div>
            <div>
                <span style="font-weight: bold; font-size: 13px;">${escapeHtml(f.owasp_category.split(" - ")[0])}</span>
                <small style="display: block; color: #64748b; font-size: 12px;">${escapeHtml(f.cwe_id)}</small>
            </div>
            <div>
                <strong>${f.risk_score}/25</strong>
                <small style="display: block; color: #64748b; font-size: 11px;">Impact: ${f.impact} &times; Likelihood: ${f.likelihood}</small>
            </div>
            <div>
                <span class="severity ${severityClass}">
                    ${f.severity}
                </span>
                <span style="display: inline-block; font-size: 11px; color: #2563eb; margin-left: 5px;">🔍 View Fix</span>
            </div>
        `;

        container.appendChild(row);
    });
}

function showRemediationModal(index) {
    const f = currentFindings[index];
    if (!f) return;

    const modal = document.getElementById("remediationModal");
    const titleEl = document.getElementById("modalTitle");
    const badgeEl = document.getElementById("modalSeverityBadge");
    const scoreEl = document.getElementById("modalRiskScore");
    const owaspEl = document.getElementById("modalOWASP");
    const cweEl = document.getElementById("modalCWE");
    const endpointEl = document.getElementById("modalEndpoint");
    const explEl = document.getElementById("modalExplanation");
    const impactEl = document.getElementById("modalImpact");
    const fixEl = document.getElementById("modalFix");
    const codeEl = document.getElementById("modalCode");

    if (titleEl) titleEl.textContent = `#${f.priority_rank}. ${f.alert_name}`;
    if (scoreEl) scoreEl.textContent = `Risk Score: ${f.risk_score}/25 (Impact: ${f.impact}/5 × Likelihood: ${f.likelihood}/5)`;
    if (owaspEl) owaspEl.textContent = f.owasp_category;
    if (cweEl) cweEl.textContent = `${f.cwe_id}: ${f.cwe_title}`;
    if (endpointEl) endpointEl.textContent = `${f.url} ${f.param ? `[Param: ${f.param}]` : ""}`;
    if (explEl) explEl.textContent = f.remediation_summary || f.description;
    if (impactEl) impactEl.textContent = f.remediation_impact || f.impact_reason;
    if (fixEl) fixEl.textContent = f.remediation_fix;
    if (codeEl) codeEl.textContent = f.secure_code_example || "# Consult security guidelines for safe implementation.";

    if (badgeEl) {
        badgeEl.textContent = f.severity.toUpperCase();
        if (f.severity === "Critical") badgeEl.style.background = "#dc2626";
        else if (f.severity === "High") badgeEl.style.background = "#ea580c";
        else if (f.severity === "Medium") badgeEl.style.background = "#d97706";
        else badgeEl.style.background = "#16a34a";
    }

    if (modal) modal.classList.add("active");
}

function closeRemediationModal() {
    const modal = document.getElementById("remediationModal");
    if (modal) modal.classList.remove("active");
}

function goToReport() {
    if (activeScanId) {
        window.location.href = `report.html?scan_id=${activeScanId}`;
    } else {
        window.location.href = "report.html";
    }
}


// -----------------------------------------------------------------------------
// Report Page Handler (Executive Summary, Vulnerability Table, Remediation, Export)
// -----------------------------------------------------------------------------
async function initReportPage() {
    const urlParams = new URLSearchParams(window.location.search);
    let scanId = urlParams.get("scan_id") || localStorage.getItem("scanId");

    if (!scanId) {
        try {
            const latestRes = await fetch("/api/scans/latest");
            if (latestRes.ok) {
                const latest = await latestRes.json();
                scanId = latest.id;
            }
        } catch (e) {
            console.error("No scans found:", e);
        }
    }

    if (!scanId) return;

    activeScanId = scanId;

    try {
        const res = await fetch(`/api/scan/${scanId}/report-data`);
        if (!res.ok) throw new Error("Report fetch error");

        const data = await res.json();
        renderReport(data);
    } catch (err) {
        console.error("Failed to render report:", err);
    }
}

function renderReport(data) {
    const scan = data.scan || {};
    const findings = data.findings || [];

    const reportURL = document.getElementById("reportURL");
    const reportTimestamp = document.getElementById("reportTimestamp");
    const reportExecSummary = document.getElementById("reportExecutiveSummary");

    if (reportURL && scan.target_url) reportURL.textContent = scan.target_url;
    if (reportTimestamp && scan.created_at) reportTimestamp.textContent = scan.created_at;
    if (reportExecSummary && data.executive_summary) reportExecSummary.textContent = data.executive_summary;

    const critEl = document.getElementById("reportCriticalCount");
    const highEl = document.getElementById("reportHighCount");
    const medEl = document.getElementById("reportMediumCount");
    const lowEl = document.getElementById("reportLowCount");

    if (critEl) critEl.textContent = scan.critical_count || 0;
    if (highEl) highEl.textContent = scan.high_count || 0;
    if (medEl) medEl.textContent = scan.medium_count || 0;
    if (lowEl) lowEl.textContent = scan.low_count || 0;

    // Render findings
    const container = document.getElementById("reportFindingsContainer");
    if (!container) return;

    container.innerHTML = "";

    if (findings.length === 0) {
        container.innerHTML = "<p>No vulnerabilities identified in this assessment report.</p>";
        return;
    }

    findings.forEach(f => {
        const severityClass = (f.severity || "Low").toLowerCase() + "-text";
        const findingCard = document.createElement("div");
        findingCard.className = "finding";

        findingCard.innerHTML = `
            <h3>
                #${f.priority_rank}. ${escapeHtml(f.alert_name)}
                <span class="${severityClass}" style="font-size: 14px; margin-left: 10px;">[${f.severity} - Risk Score: ${f.risk_score}/25]</span>
            </h3>

            <p style="font-size: 14px; color: #64748b;">
                <strong>OWASP Category:</strong> ${escapeHtml(f.owasp_category)} | 
                <strong>CWE:</strong> ${escapeHtml(f.cwe_id)}: ${escapeHtml(f.cwe_title)}
            </p>

            ${f.url ? `<p style="font-size: 14px; color: #475569;"><strong>Endpoint:</strong> <code>${escapeHtml(f.url)}</code> ${f.param ? `(Parameter: <code>${escapeHtml(f.param)}</code>)` : ""}</p>` : ""}

            <p style="margin-top: 10px;">
                <strong>Simple Explanation:</strong><br>
                ${escapeHtml(f.remediation_summary || f.description)}
            </p>

            <p style="margin-top: 10px;">
                <strong>Security Impact:</strong><br>
                ${escapeHtml(f.remediation_impact || f.impact_reason)}
            </p>

            <p style="margin-top: 10px;">
                <strong>Defensive Remediation Steps:</strong>
            </p>
            <div class="fix-box">${escapeHtml(f.remediation_fix)}</div>

            ${f.secure_code_example ? `
                <p style="margin-top: 10px;">
                    <strong>Secure Code Implementation Example:</strong>
                </p>
                <pre class="code-block"><code>${escapeHtml(f.secure_code_example)}</code></pre>
            ` : ""}
        `;

        container.appendChild(findingCard);
    });
}

function downloadStandaloneReport() {
    if (!activeScanId) {
        const urlParams = new URLSearchParams(window.location.search);
        activeScanId = urlParams.get("scan_id") || localStorage.getItem("scanId");
    }

    if (activeScanId) {
        window.location.href = `/api/scan/${activeScanId}/export-html`;
    } else {
        alert("No scan ID available for download.");
    }
}


// Utility function to escape HTML special characters
function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
