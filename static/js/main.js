const form = document.getElementById("scanForm");
const emailInput = document.getElementById("email");
const scanButton = document.getElementById("scanButton");
const pdfButton = document.getElementById("pdfButton");
const statusText = document.getElementById("statusText");
const scoreRing = document.getElementById("scoreRing");
const scoreValue = document.getElementById("scoreValue");
const riskLabel = document.getElementById("riskLabel");
const targetEmail = document.getElementById("targetEmail");
const lookupMessage = document.getElementById("lookupMessage");
const avatar = document.getElementById("avatar");
const breachCount = document.getElementById("breachCount");
const breachList = document.getElementById("breachList");
const recommendations = document.getElementById("recommendations");
const signalList = document.getElementById("signalList");

let lastEmail = "";

function setLoading(isLoading) {
    scanButton.disabled = isLoading;
    scanButton.textContent = isLoading ? "Scanning..." : "Scan";
    if (isLoading) {
        statusText.textContent = "Checking breach intelligence feeds...";
    }
}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "'": "&#39;",
        '"': "&quot;",
    }[char]));
}

function renderBreaches(breaches) {
    if (!breaches.length) {
        breachList.innerHTML = '<div class="empty-state">No public breaches were returned for this email.</div>';
        return;
    }

    breachList.innerHTML = breaches.map((breach) => {
        const dataClasses = (breach.DataClasses || []).slice(0, 5).map(escapeHtml).join(", ");
        return `
            <div class="breach-item">
                <div>
                    <strong>${escapeHtml(breach.Title || breach.Name)}</strong>
                    <span>${escapeHtml(breach.Domain || "Unknown domain")} · ${escapeHtml(breach.BreachDate || "Unknown date")}</span>
                </div>
                <p>${dataClasses || "Data classes not listed"}</p>
            </div>
        `;
    }).join("");
}

function renderRecommendations(items) {
    recommendations.innerHTML = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function renderSignals(items) {
    if (!items.length) {
        signalList.innerHTML = '<div class="empty-state">No free risk signals were returned.</div>';
        return;
    }

    signalList.innerHTML = items.map((item) => `
        <div class="signal-item ${escapeHtml(item.status)}">
            <div>
                <strong>${escapeHtml(item.label)}</strong>
                <span>+${escapeHtml(item.impact)} risk</span>
            </div>
            <p>${escapeHtml(item.detail)}</p>
        </div>
    `).join("");
}

function renderReport(data) {
    lastEmail = data.email;
    targetEmail.textContent = data.email;
    lookupMessage.textContent = data.lookup_message;
    avatar.src = data.gravatar;
    scoreRing.style.setProperty("--score", data.threat_score);
    scoreValue.textContent = data.threat_score;
    riskLabel.textContent = data.risk;
    riskLabel.className = `risk-pill ${data.risk.toLowerCase()}`;
    breachCount.textContent = `${data.breach_count} known ${data.breach_count === 1 ? "breach" : "breaches"}`;
    renderBreaches(data.breaches || []);
    renderRecommendations(data.recommendations || []);
    renderSignals(data.risk_signals || []);
    pdfButton.disabled = false;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = emailInput.value.trim();

    if (!email) {
        statusText.textContent = "Please enter an email address.";
        return;
    }

    setLoading(true);
    pdfButton.disabled = true;

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email }),
        });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Scan failed.");
        }

        renderReport(data);
        statusText.textContent = `Scan completed at ${data.scanned_at}.`;
    } catch (error) {
        statusText.textContent = error.message;
    } finally {
        setLoading(false);
    }
});

pdfButton.addEventListener("click", async () => {
    if (!lastEmail) return;

    pdfButton.disabled = true;
    pdfButton.textContent = "Building PDF...";

    try {
        const response = await fetch("/report/pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: lastEmail }),
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || "Could not create the PDF report.");
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `footprint-report-${lastEmail.replace("@", "-at-")}.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    } catch (error) {
        statusText.textContent = error.message;
    } finally {
        pdfButton.disabled = false;
        pdfButton.textContent = "Download PDF";
    }
});
