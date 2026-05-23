async function startScan() {
    const email = document.getElementById("email").value;
    const terminal = document.getElementById("terminal");

    terminal.innerHTML += "<p>[+] Connecting to intelligence feeds...</p>";

    const response = await fetch("/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ email })
    });

    const data = await response.json();

    document.getElementById("results").innerHTML = `
        <div class="result-card">
            <h2>Threat Report</h2>
            <p><strong>Email:</strong> ${data.email}</p>
            <p><strong>Threat Score:</strong> ${data.threat_score}</p>
            <p><strong>Risk:</strong> ${data.risk}</p>
            <img src="${data.gravatar}" width="120">
        </div>
    `;
}