// --------------------
// Persistent Scammer ID
// --------------------
let scammer_id = localStorage.getItem("scammer_id");

if (!scammer_id) {
    scammer_id = "scammer_" + Math.random().toString(36).substring(2, 10);
    localStorage.setItem("scammer_id", scammer_id);
}

// --------------------
// Add Chat Message
// --------------------
function addMessage(text, cls) {
    const messages = document.getElementById("messages");
    if (!messages) return;

    const div = document.createElement("div");
    div.className = cls;
    div.innerText = text;

    messages.appendChild(div);
    div.scrollIntoView({ behavior: "smooth" });
}

// --------------------
// Send Message
// --------------------
async function send() {
    const textarea = document.getElementById("msg");
    if (!textarea) return;

    const msg = textarea.value.trim();
    if (!msg) return;

    addMessage("Scammer: " + msg, "user");
    textarea.value = "";

    try {
        const res = await fetch("/api/honeypot", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scammer_id: scammer_id,
                message: msg
            })
        });

        if (!res.ok) {
            throw new Error("Server error");
        }

        const data = await res.json();

        addMessage("Victim: " + (data.reply || "..."), "bot");

        // Update Scam Type
        const typeBox = document.getElementById("type");
        if (typeBox) typeBox.innerText = data.scam_type || "-";

        // Update Risk
        updateRiskUI(data.risk_score || "LOW");

        // Update Persona
        const personaBox = document.getElementById("persona");
        if (personaBox) personaBox.innerText = data.persona || "-";

    } catch (err) {
        console.error("Frontend error:", err);
        addMessage("⚠️ System error. Please try again.", "bot");
    }
}

// --------------------
// Risk UI
// --------------------
function updateRiskUI(risk) {
    const box = document.getElementById("risk");
    if (!box) return;

    box.innerText = risk;
    box.className = "intel-box";

    if (risk === "HIGH") box.classList.add("high");
    else if (risk === "MEDIUM") box.classList.add("medium");
    else box.classList.add("low");
}

// --------------------
// Download Evidence
// --------------------
function downloadEvidence() {
    window.open("/api/download/evidence", "_blank");
}
