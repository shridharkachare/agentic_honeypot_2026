from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import os, sqlite3, uuid, re, csv
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from groq import Groq


# --------------------
# AI OUTPUT CLEANER
# --------------------
def clean_reply(text: str) -> str:
    if not text:
        return ""

    text = re.sub(r"\(.*?\)", "", text)
    text = re.sub(r"\*.*?\*", "", text)
    text = re.sub(r"\n{2,}", "\n", text)

    return text.strip()


# --------------------
# ENV
# --------------------
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY")
if not HONEYPOT_API_KEY:
    raise RuntimeError("❌ HONEYPOT_API_KEY not found")


if not GROQ_API_KEY:
    raise RuntimeError("❌ GROQ_API_KEY not found")

client = Groq(api_key=GROQ_API_KEY)

DB_FILE = "honeypot.db"
EVIDENCE_DIR = "evidence"
os.makedirs(EVIDENCE_DIR, exist_ok=True)

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)


# --------------------
# DATABASE
# --------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            scammer_id TEXT,
            timestamp TEXT,
            scammer_message TEXT,
            agent_reply TEXT,
            scam_type TEXT,
            risk_score TEXT,
            persona TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()


# --------------------
# AI AGENT (GROQ)
# --------------------
def ask_llm(message, history, persona, risk_score):
    tone = {
        "LOW": "curious and calm",
        "MEDIUM": "confused and cautious",
        "HIGH": "panicked and emotional"
    }.get(risk_score, "confused")

    system_prompt = f"""
You are an undercover scam-baiting victim.

PERSONA: {persona}
RISK LEVEL: {risk_score}

STRICT RULES:
- Write short, clear, direct replies (2–4 sentences max)
- NO emotions, NO stage directions
- DO NOT use brackets (), * *, or roleplay actions
- Sound like a normal, cautious person
- Ask only relevant follow-up questions
- Focus on extracting details (process, payment, identity)
- NEVER reveal you are AI
"""

    user_prompt = f"""
Conversation so far:
{history}

Scammer: "{message}"
Reply:
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=200
        )

        raw_reply = response.choices[0].message.content or ""
        return clean_reply(raw_reply)

    except Exception as e:
        print("⚠️ Groq error:", e)
        return "I’m not sure about this. Can you explain clearly what you want me to do?"


# --------------------
# SCAM DETECTION (UPDATED)
# --------------------
def detect_scam_type(message):
    msg = message.lower()

    # 🔐 PHISHING / URL SCAM (NEW)
    if (
        "http://" in msg or
        "https://" in msg or
        "www." in msg or
        any(k in msg for k in [
            "verify your account", "login to continue",
            "click the link", "secure link",
            "suspicious activity", "unusual activity",
            "confirm your identity", "reset password",
            "bank alert", "account security",
            ".xyz", ".ru", ".top", "link"
        ])
    ):
        return "Phishing Scam"

  # ---------------- OTP / Account Takeover ----------------
    if any(k in msg for k in [
        "otp", "one time password", "verification code",
        "kyc", "kyc update", "kyc pending",
        "account blocked", "account suspended",
        "verify now", "last chance", "within 24 hours"
    ]):
        return "OTP Scam"

    # ---------------- Payment / UPI Fraud ----------------
    if any(k in msg for k in [
        "upi", "gpay", "google pay", "phonepe", "paytm",
        "send money", "request money",
        "scan qr", "qr code",
        "refund", "cashback",
        "amount credited by mistake",
        "reverse payment"
    ]):
        return "Payment / UPI Fraud"

    # ---------------- Lottery / Prize Scam ----------------
    if any(k in msg for k in [
        "lottery", "winner", "won", "jackpot",
        "prize", "lucky draw", "congratulations",
        "claim your prize", "processing fee",
        "selected as winner"
    ]):
        return "Lottery Scam"

    # ---------------- Job Scam ----------------
    if any(k in msg for k in [
        "job", "salary", "interview",
        "work from home", "part time",
        "data entry", "typing job",
        "registration fee", "joining fee",
        "urgent hiring", "no experience required"
    ]):
        return "Job Scam"

    # ---------------- Tech Support Scam ----------------
    if any(k in msg for k in [
        "technical support", "tech support",
        "virus", "malware", "hacked",
        "windows security alert",
        "microsoft support",
        "anydesk", "teamviewer",
        "do not shut down"
    ]):
        return "Tech Support Scam"

    # ---------------- Romance / Honey Trap ----------------
    if any(k in msg for k in [
        "love", "relationship", "marriage",
        "trust me", "i care for you",
        "lonely", "emotional support",
        "video call", "send photo",
        "future together"
    ]):
        return "Romance Scam"

    # ---------------- Loan / Credit Scam ----------------
    if any(k in msg for k in [
        "loan", "instant loan", "quick loan",
        "pre approved loan",
        "credit card", "credit limit increased",
        "low interest", "processing fee",
        "cibil score"
    ]):
        return "Loan Scam"

    # ---------------- Investment / Crypto Scam ----------------
    if any(k in msg for k in [
        "investment", "crypto", "bitcoin",
        "trading", "share market",
        "double money", "profit guaranteed",
        "high returns", "forex",
        "daily income"
    ]):
        return "Investment Scam"

    # ---------------- Government / Police Impersonation ----------------
    if any(k in msg for k in [
        "police", "cbi", "income tax",
        "arrest", "arrest warrant",
        "court case", "legal action",
        "pan card", "aadhar",
        "customs department", "case registered"
    ]):
        return "Impersonation Scam"

    # ---------------- Courier / Delivery Scam ----------------
    if any(k in msg for k in [
        "parcel", "courier", "delivery",
        "fedex", "dhl", "blue dart",
        "customs hold", "address issue",
        "shipment blocked", "import duty"
    ]):
        return "Courier Scam"

    return "Unknown"


def detect_risk_score(msg):
    msg = msg.lower()
    if any(k in msg for k in [
        "otp", "urgent", "blocked", "arrest",
        "pay now", "click immediately"
    ]):
        return "HIGH"
    if any(k in msg for k in ["verify", "confirm", "update"]):
        return "MEDIUM"
    return "LOW"


def select_persona(scam_type, risk):
    if scam_type in ["OTP Scam", "Payment / UPI Fraud", "Phishing Scam"]:
        return "Panicked Bank Customer" if risk == "HIGH" else "Confused User"
    if scam_type == "Lottery Scam":
        return "Excited Lottery Winner"
    if scam_type == "Job Scam":
        return "Unemployed Job Seeker"
    if scam_type == "Romance Scam":
        return "Emotionally Vulnerable Individual"
    return "Everyday User"


# --------------------
# CSV EXPORT
# --------------------
def export_evidence_csv(record):
    path = os.path.join(EVIDENCE_DIR, "scam_evidence.csv")
    file_exists = os.path.exists(path)

    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=record.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)



# --------------------
# ROUTES (UNCHANGED)
# --------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
def admin():
    return render_template("admin.html")

@app.route("/api/admin/scams")
def admin_scams():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT scammer_id, timestamp, scam_type, persona, scammer_message, risk_score
        FROM messages
        ORDER BY timestamp DESC
    """)

    rows = cur.fetchall()
    conn.close()

    return jsonify([
        {
            "scammer_id": r[0],
            "timestamp": r[1],
            "scam_type": r[2],
            "persona": r[3],
            "message": r[4],
            "risk_score": r[5]
        }
        for r in rows
    ])

@app.route("/api/download/evidence")
def download_evidence():
    path = os.path.join(EVIDENCE_DIR, "scam_evidence.csv")
    if not os.path.exists(path):
        return jsonify({"error": "No evidence found"}), 404
    return send_file(path, as_attachment=True)


@app.route("/api/honeypot", methods=["POST"])
def honeypot():
    data = request.get_json(force=True)
    msg = data.get("message", "")
    scammer_id = data.get("scammer_id", "UNKNOWN")

    if not msg.strip():
        return jsonify({"reply": "Please send a message."})

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "SELECT scammer_message, agent_reply FROM messages WHERE scammer_id=?",
        (scammer_id,)
    )
    history = "".join(f"Scammer: {s}\nAgent: {a}\n" for s, a in cur.fetchall())

    scam_type = detect_scam_type(msg)
    risk = detect_risk_score(msg)
    persona = select_persona(scam_type, risk)
    reply = ask_llm(msg, history, persona, risk)

    export_evidence_csv({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scammer_id": scammer_id,
        "scam_type": scam_type,
        "risk_score": risk,
        "persona": persona,
        "message": msg
    })

    cur.execute("""
        INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(uuid.uuid4()),
        scammer_id,
        datetime.now(timezone.utc).isoformat(),
        msg,
        reply,
        scam_type,
        risk,
        persona
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "reply": reply,
        "scam_type": scam_type,
        "risk_score": risk,
        "persona": persona
    })

@app.route("/api/pdf/<scammer_id>")
def generate_pdf(scammer_id):
    file_path = os.path.join(EVIDENCE_DIR, f"{scammer_id}.pdf")

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT timestamp, scammer_message, agent_reply, scam_type, persona, risk_score
        FROM messages
        WHERE scammer_id=?
        ORDER BY timestamp
    """, (scammer_id,))

    rows = cur.fetchall()
    conn.close()

    if not rows:
        return jsonify({"error": "No records found for this scammer"}), 404

    c = canvas.Canvas(file_path, pagesize=A4)
    width, height = A4
    y = height - 50

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, f"Scammer ID: {scammer_id}")
    y -= 30

    c.setFont("Helvetica", 10)

    for r in rows:
        block = [
            f"Time: {r[0]}",
            f"Scam Type: {r[3]}",
            f"Persona: {r[4]}",
            f"Risk Level: {r[5]}",
            f"Scammer Message: {r[1]}",
            f"Victim Reply: {r[2]}",
            "-" * 80
        ]

        for line in block:
            if y < 60:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 50
            c.drawString(40, y, line)
            y -= 14

        y -= 10

    c.save()
    return send_file(file_path, as_attachment=True)

@app.route("/api/health", methods=["GET"])
def health_check():
    api_key = request.headers.get("x-api-key")

    if not api_key:
        return jsonify({
            "status": "error",
            "message": "API key missing"
        }), 401

    if api_key != HONEYPOT_API_KEY:
        return jsonify({
            "status": "error",
            "message": "Invalid API key"
        }), 403

    return jsonify({
        "status": "ok",
        "service": "Agentic Honeypot",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


# --------------------
# RUN
# --------------------
if __name__ == "__main__":
    print("🚀 Running at http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

