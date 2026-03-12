import streamlit as st
import re
import os
import json
import pytesseract
from PIL import Image

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="SchemeCheck",
    page_icon="🛡️",
    layout="wide",
)

# ─────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>

body {
    background: radial-gradient(circle at top, #0f172a, #020617);
    color: white;
}

/* Main container */
.block-container {
    padding-top: 2rem;
    max-width: 1200px;
}

/* Header */
.main-title {
    font-size: 42px;
    font-weight: 700;
    text-align: center;
    background: linear-gradient(90deg,#38bdf8,#22c55e);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.sub-title{
    text-align:center;
    color:#94a3b8;
    margin-bottom:30px;
}

/* Glass cards */
.card {
    background: rgba(15,23,42,0.65);
    border:1px solid rgba(255,255,255,0.08);
    border-radius:16px;
    padding:24px;
    backdrop-filter: blur(10px);
    margin-bottom:20px;
}

/* Buttons */
.stButton>button{
    width:100%;
    border-radius:12px;
    height:50px;
    font-size:16px;
    font-weight:600;
    background:#000000;
    border:none;
    color:white;
    transition:0.2s;
    
}

.stButton>button:hover{
    transform:scale(1.02);
    transition:0.2s;
    color: #38bdf8;
}

/* Text area */
textarea{
    border-radius:12px !important;
}

/* Fraud score box */

.score-box{
    padding:25px;
    border-radius:16px;
    text-align:center;
    font-size:24px;
    font-weight:700;
}

.safe{
background:#052e16;
color:#4ade80;
}

.warn{
background:#3f2f00;
color:#facc15;
}

.danger{
background:#3b0a0a;
color:#f87171;
}

/* Flag cards */

.flag{
background:#020617;
padding:14px;
border-radius:10px;
margin-bottom:10px;
border-left:4px solid #38bdf8;
font-size:14px;
}

/* stats */
.stat{
text-align:center;
padding:20px;
background:#020617;
border-radius:14px;
}

.stat-number{
font-size:28px;
font-weight:700;
}

</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# OFFICIAL DOMAINS
# ─────────────────────────────────────────────
OFFICIAL_DOMAINS = [
    "gov.in","nic.in","india.gov.in","mygov.in","pmjay.gov.in",
    "pfms.nic.in","uidai.gov.in","incometax.gov.in","epfindia.gov.in",
    "nrega.nic.in","scholarships.gov.in","digitalindia.gov.in","pib.gov.in",
    "passport.gov.in","irctc.co.in","rbi.org.in","sbi.co.in","npci.org.in",
]

# ─────────────────────────────────────────────
# INDIA STATES MAP DATA
# ─────────────────────────────────────────────
INDIA_STATES = [
    {"state":"Uttar Pradesh",  "lat":27.1,  "lon":80.0,  "scams":482},
    {"state":"Maharashtra",    "lat":19.75, "lon":75.7,  "scams":371},
    {"state":"Delhi",          "lat":28.70, "lon":77.10, "scams":339},
    {"state":"West Bengal",    "lat":22.98, "lon":87.85, "scams":298},
    {"state":"Rajasthan",      "lat":27.02, "lon":74.22, "scams":261},
    {"state":"Bihar",          "lat":25.09, "lon":85.31, "scams":247},
    {"state":"Gujarat",        "lat":22.25, "lon":71.19, "scams":214},
    {"state":"Madhya Pradesh", "lat":22.97, "lon":78.65, "scams":198},
    {"state":"Karnataka",      "lat":15.31, "lon":75.71, "scams":187},
    {"state":"Tamil Nadu",     "lat":11.12, "lon":78.66, "scams":163},
    {"state":"Telangana",      "lat":17.12, "lon":79.01, "scams":142},
    {"state":"Andhra Pradesh", "lat":15.91, "lon":79.74, "scams":128},
    {"state":"Jharkhand",      "lat":23.61, "lon":85.27, "scams":119},
    {"state":"Odisha",         "lat":20.94, "lon":85.09, "scams":107},
    {"state":"Haryana",        "lat":29.05, "lon":76.09, "scams":98},
    {"state":"Punjab",         "lat":31.14, "lon":75.34, "scams":88},
    {"state":"Assam",          "lat":26.20, "lon":92.93, "scams":76},
    {"state":"Kerala",         "lat":10.85, "lon":76.27, "scams":71},
    {"state":"Chhattisgarh",   "lat":21.27, "lon":81.86, "scams":64},
    {"state":"Uttarakhand",    "lat":30.06, "lon":79.01, "scams":43},
]

# ─────────────────────────────────────────────
# RULE ENGINE
# ─────────────────────────────────────────────
def extract_links(text):
    return re.findall(r"(https?://\S+|www\.\S+)", text)

def get_domain(url):
    url = re.sub(r"https?://", "", url).split("/")[0].split("?")[0]
    parts = url.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else url

def rule_based_analysis(message):
    flags = []
    msg = message.lower()

    urgency_words = ["urgent","last date","limited time","today only","act now",
                     "hurry","expire","immediately","deadline","final notice"]
    for w in urgency_words:
        if w in msg:
            flags.append({"type":"URGENCY_LANGUAGE","severity":"MEDIUM",
                          "detail":f'Urgency phrase: "{w}"',"source":"RULE ENGINE"})
            break

    sensitive = {
        "aadhaar":"Aadhaar number solicitation",
        "aadhar":"Aadhaar number solicitation",
        "bank account":"Bank account info request",
        "otp":"OTP solicitation — no legitimate service ever asks for OTP",
        "cvv":"Card CVV request",
        "password":"Password solicitation",
        "pan card":"PAN card request",
        "pan number":"PAN number request",
        "credit card":"Credit card detail request",
    }
    for kw, detail in sensitive.items():
        if kw in msg:
            flags.append({"type":"PERSONAL_DATA_HARVESTING","severity":"HIGH",
                          "detail":detail,"source":"RULE ENGINE"})

    if any(p in msg for p in ["share this with","forward to","send this to"]):
        flags.append({"type":"FORWARD_CHAIN_SCAM","severity":"HIGH",
                      "detail":"Chain-forwarding instruction — viral scam pattern","source":"RULE ENGINE"})

    reward_words = ["won","winner","lottery","prize","free cash","reward","selected","lucky draw"]
    for w in reward_words:
        if w in msg:
            flags.append({"type":"REWARD_BAIT","severity":"HIGH",
                          "detail":f'Reward-bait language: "{w}"',"source":"RULE ENGINE"})
            break

    gov_schemes = ["pm kisan","pmkisan","pm awas","pmay","jan dhan","ayushman",
                   "beti bachao","digital india","income tax department","epfo","ration card"]
    for g in gov_schemes:
        if g in msg:
            flags.append({"type":"SCHEME_IMPERSONATION","severity":"HIGH",
                          "detail":f'Government scheme name used: "{g}" — verify authenticity',"source":"RULE ENGINE"})
            break

    phones = re.findall(r"\b[6-9]\d{9}\b", message)
    if phones:
        flags.append({"type":"UNVERIFIED_PHONE_NUMBER","severity":"MEDIUM",
                      "detail":f"Mobile number(s) found: {', '.join(phones)} — verify on official site","source":"RULE ENGINE"})

    payment_words = ["transfer","send money","paytm","upi","gpay","phonepe","₹","rs."]
    if any(p in msg for p in payment_words):
        flags.append({"type":"PAYMENT_REQUEST","severity":"HIGH",
                      "detail":"Message contains payment or transfer instructions","source":"RULE ENGINE"})

    return flags

def link_analysis(message):
    flags = []
    links = extract_links(message)
    for link in links:
        domain = get_domain(link)
        is_official = any(domain.endswith(od) for od in OFFICIAL_DOMAINS)
        lookalike_patterns = [
            r"pmkisan[^\.]*\.(xyz|top|info|click|online|site|tk|ml|ga)",
            r"aadhaar[^\.]*\.(xyz|top|info|click|online)",
            r"sbi[^\.]*\.(xyz|top|info|click)",
            r"g[o0]v-in\.",
            r"india-gov\.",
        ]
        is_lookalike = any(re.search(p, link.lower()) for p in lookalike_patterns)
        if is_lookalike:
            flags.append({"type":"LOOKALIKE_DOMAIN","severity":"HIGH",
                          "detail":f"Typosquat / lookalike domain: {domain}","source":"DOMAIN SCAN"})
        elif not is_official:
            flags.append({"type":"SUSPICIOUS_LINK","severity":"HIGH",
                          "detail":f"Unverified domain: {domain} — not in GOI official list","source":"DOMAIN SCAN"})
        else:
            flags.append({"type":"VERIFIED_LINK","severity":"LOW",
                          "detail":f"Official domain confirmed: {domain}","source":"DOMAIN SCAN"})
    return flags

def compute_score(flags):
    score = 0
    for f in flags:
        if f.get("type") == "VERIFIED_LINK":
            score -= 10
            continue
        sev = f.get("severity","LOW")
        if sev == "HIGH":     score += 25
        elif sev == "MEDIUM": score += 12
        else:                 score += 5
    return max(0, min(100, score))

def derive_verdict(score):
    if score >= 70: return "SCAM"
    if score >= 40: return "SUSPICIOUS"
    return "LEGITIMATE"

def derive_scheme_type(flags, message):
    msg = message.lower()
    if "pmkisan" in msg or "pm kisan" in msg: return "PM Kisan Fraud"
    if "ayushman" in msg:                      return "Ayushman Bharat Fraud"
    if "aadhaar" in msg or "aadhar" in msg:    return "Fake Aadhaar Update Scam"
    if "lottery" in msg or "prize" in msg:     return "Lottery / Lucky Draw Scam"
    if "otp" in msg:                           return "OTP Phishing Attack"
    if any(f["type"] in ("SUSPICIOUS_LINK","LOOKALIKE_DOMAIN") for f in flags):
        return "Phishing Link Scam"
    if any(f["type"] == "PAYMENT_REQUEST" for f in flags):
        return "Payment / UPI Fraud"
    if any(f["type"] == "FORWARD_CHAIN_SCAM" for f in flags):
        return "Viral Chain Scam"
    return "Generic Government Scheme Fraud"

def build_summary(score, flags, message):
    verdict = derive_verdict(score)
    high_flags = [f for f in flags if f["severity"] == "HIGH"]
    if verdict == "SCAM":
        reasons = ", ".join(set(f["type"].replace("_"," ").title() for f in high_flags[:2]))
        return (f"This message shows strong indicators of a scam (fraud score {score}/100). "
                f"Key red flags: {reasons}. "
                f"Do NOT click any links or share personal information.")
    if verdict == "SUSPICIOUS":
        return (f"This message contains {len(flags)} suspicious signal(s). "
                f"Verify through official government portals before taking any action.")
    return ("No major fraud indicators detected. This message appears consistent with "
            "legitimate communications. Always verify by visiting the official website directly.")

def build_recommendation(verdict):
    if verdict == "SCAM":
        return "Do NOT respond or click any links. Block the sender and report to cybercrime.gov.in or call 1930."
    if verdict == "SUSPICIOUS":
        return "Do not share personal info. Call the official helpline or visit the official website directly."
    return "Message appears safe. Always navigate to official sites manually rather than clicking links."

# ─────────────────────────────────────────────
# OLLAMA AI LAYER
# ─────────────────────────────────────────────
def build_ollama_prompt(message, rule_flags, link_flags):
    pre_flags = rule_flags + link_flags
    pre_summary = (f"{len(pre_flags)} pre-detected flags: " +
                   ", ".join(f['type'] for f in pre_flags)) if pre_flags else "None detected yet"
    return f"""You are an expert Indian government scam detection AI.
A rule engine has already run on this message.
Pre-detection result: {pre_summary}

Analyse the message below and return ONLY valid JSON — no markdown, no extra text.

Message:
\"\"\"{message}\"\"\"

Return exactly this JSON structure:
{{
  "fraudScore": <integer 0-100>,
  "verdict": "<SCAM|SUSPICIOUS|LEGITIMATE>",
  "schemeType": "<e.g. PM Kisan Fraud / OTP Phishing / Lottery Scam>",
  "summary": "<2-3 sentence plain English explanation>",
  "recommendation": "<one clear action for the recipient>",
  "ai_flags": [
    {{"type": "<FLAG_TYPE>", "severity": "<HIGH|MEDIUM|LOW>", "detail": "<short explanation>"}}
  ]
}}"""

def analyze_with_ollama(message, rule_flags, link_flags, model_name):
    import ollama
    response = ollama.chat(
        model=model_name,
        messages=[{"role": "user", "content": build_ollama_prompt(message, rule_flags, link_flags)}]
    )
    raw = response["message"]["content"].strip()
    raw = re.sub(r"```(?:json)?", "", raw).replace("```", "").strip()
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(raw)

# ─────────────────────────────────────────────
# FULL HYBRID PIPELINE
# ─────────────────────────────────────────────
def full_analysis(message, use_ollama=False, model_name="llama3"):
    rule_flags = rule_based_analysis(message)
    link_flags = link_analysis(message)
    all_flags  = rule_flags + link_flags

    if use_ollama:
        try:
            ai = analyze_with_ollama(message, rule_flags, link_flags, model_name)
            for f in ai.get("ai_flags", []):
                f["source"] = f"OLLAMA ({model_name})"
                all_flags.append(f)
            return {
                "fraudScore":     ai.get("fraudScore",     compute_score(all_flags)),
                "verdict":        ai.get("verdict",        derive_verdict(compute_score(all_flags))),
                "schemeType":     ai.get("schemeType",     derive_scheme_type(all_flags, message)),
                "summary":        ai.get("summary",        build_summary(compute_score(all_flags), all_flags, message)),
                "recommendation": ai.get("recommendation", build_recommendation(derive_verdict(compute_score(all_flags)))),
                "flags":     all_flags,
                "rule_count": len(rule_flags),
                "link_count": len(link_flags),
                "ai_used":   True,
                "ai_model":  model_name,
            }
        except Exception as e:
            pass
    # Fallback — rule engine only
    score   = compute_score(all_flags)
    verdict = derive_verdict(score)
    return {
        "fraudScore":     score,
        "verdict":        verdict,
        "schemeType":     derive_scheme_type(all_flags, message),
        "summary":        build_summary(score, all_flags, message),
        "recommendation": build_recommendation(verdict),
        "flags":     all_flags,
        "rule_count": len(rule_flags),
        "link_count": len(link_flags),
        "ai_used":   False,
        "ai_model":  None,
    }

def score_color(s):
    if s > 70: return "#ff3b3b"
    if s > 40: return "#ffaa00"
    return "#00e676"

def risk_class(s):
    if s > 70: return "risk-high",   "🚨 HIGH RISK — LIKELY SCAM"
    if s > 40: return "risk-medium", "⚠️ SUSPICIOUS MESSAGE"
    return "risk-low",    "✅ LIKELY LEGITIMATE"

# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
st.markdown("""
<div class="header-banner">
  <h1>🛡️ SchemeCheck</h1>
  <p>GOVERNMENT SCAM DETECTION ENGINE &nbsp;|&nbsp; RULE ENGINE + DOMAIN SCANNER + OLLAMA AI &nbsp;|&nbsp; INDIA CYBER INTELLIGENCE &nbsp;|&nbsp; 100% OFFLINE</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# STATS BAR
# ─────────────────────────────────────────────
total = sum(s["scams"] for s in INDIA_STATES)
for col, num, label in zip(
    st.columns(4),
    [f"{total:,}", "20", "3-Layer", "Ollama AI"],
    ["Scams Tracked 2024", "States Monitored", "Detection Pipeline", "Local AI Engine"]
):
    col.markdown(
        f'<div class="stat-box"><div class="stat-num">{num}</div>'
        f'<div class="stat-label">{label}</div></div>',
        unsafe_allow_html=True
    )

st.markdown("<br>", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# SIDEBAR — OLLAMA SETTINGS
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ AI Engine Settings")
    st.markdown("---")

    use_ollama = st.toggle("🤖 Enable Ollama AI", value=True)

    ollama_model = st.selectbox(
        "Model",
        ["llama3", "llama3.2", "mistral", "gemma2", "phi3", "llama2"],
        index=0,
        help="Must be pulled first. Run: ollama pull llama3"
    )

    st.markdown("---")
    st.markdown("**Setup Ollama:**")
    st.code("ollama pull llama3\nollama serve", language="bash")
    st.caption("Download: ollama.com/download")

    st.markdown("---")
    if use_ollama:
        st.markdown('<div class="ai-badge">🟢 OLLAMA MODE</div>', unsafe_allow_html=True)
        st.caption(f"Model: `{ollama_model}`\nRuns fully offline on your machine.")
    else:
        st.markdown(
            '<div class="ai-badge" style="border-color:#ffaa00;color:#ffcc44">🟡 RULE ENGINE ONLY</div>',
            unsafe_allow_html=True
        )
        st.caption("AI disabled. Using rule engine + domain scanner only.")

# ─────────────────────────────────────────────
# MAIN LAYOUT
# ─────────────────────────────────────────────
left_col, right_col = st.columns([1, 1], gap="large")

with left_col:
    st.markdown("### 🔍 Analyse a Message")

    uploaded = st.file_uploader(
        "📸 Upload WhatsApp / SMS Screenshot (optional)",
        type=["png","jpg","jpeg"]
    )
    ocr_text = ""
    if uploaded:
        try:
            from PIL import Image
            import pytesseract
            ocr_text = pytesseract.image_to_string(Image.open(uploaded))
            st.success("✅ Text extracted from screenshot")
            with st.expander("View extracted text"):
                st.code(ocr_text)
        except ImportError:
            st.warning("Install `pytesseract` + `Pillow` to enable OCR.")

    init_val = st.session_state.pop("load_msg", ocr_text or "")
    message  = st.text_area(
        "Paste suspicious message text",
        value=init_val,
        height=190,
        placeholder="Paste any SMS, WhatsApp message, email, or URL here...",
    )
    analyse_btn = st.button("⚡ ANALYSE NOW", use_container_width=True)

    st.markdown("**Try a sample:**")
    SAMPLES = {
        "PM Kisan Fraud":  ("Congratulations! Your PM Kisan installment of ₹6000 is pending. "
                            "Update your Aadhaar at http://pmkisan-update.xyz/verify to receive payment. "
                            "Last date: today only! Share this with 10 friends."),
        "OTP Phishing":    ("Dear customer, your SBI account will be suspended. "
                            "Share your OTP 847291 with our agent on 9876543210 immediately."),
        "Lottery Scam":    ("You have been selected as winner in Digital India Lottery! "
                            "Claim ₹5,00,000 prize. Send your bank account number and PAN card. "
                            "Forward to 10 friends."),
        "Legit IRCTC":     ("Your IRCTC booking PNR 4523819076 is confirmed. Train 12951 | "
                            "Seat B2-34 | Dep 06:20 from NDLS on 15-Mar. "
                            "Check at https://www.irctc.co.in"),
    }
    scols = st.columns(2)
    for i, (label, text) in enumerate(SAMPLES.items()):
        if scols[i % 2].button(label, key=f"s{i}"):
            st.session_state["load_msg"] = text
            st.rerun()

with right_col:
    st.markdown("### 🗺️ Live Scam Activity Map — India")
    st.caption("State-wise scam message detections (2024 data)")

    try:
        import pydeck as pdk
        import pandas as pd

        df = pd.DataFrame(INDIA_STATES)

        heat_layer = pdk.Layer(
            "HeatmapLayer",
            data=df,
            get_position=["lon", "lat"],
            get_weight="scams",
            radiusPixels=70,
            intensity=1.2,
            threshold=0.1,
            pickable=True,   # allows hover interaction
        )

        view_state = pdk.ViewState(
            latitude=22.5937,
            longitude=78.9629,
            zoom=4.5,
            pitch=0
        )

        deck = pdk.Deck(
            layers=[heat_layer],
            initial_view_state=view_state,
            map_style="light",
            tooltip={
                "html": "<b>{state}</b><br/>Scam Rate: {scams}",
                "style": {
                    "backgroundColor": "black",
                    "color": "white",
                    "fontSize": "12px"
                }
            }
        )

        st.pydeck_chart(deck)

    except Exception as e:
        st.error("Map failed to load")
        st.write(e)
# ─────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────

# Persist message across reruns
if "current_message" not in st.session_state:
    st.session_state.current_message = ""

# Update stored message when user types
if message:
    st.session_state.current_message = message

run_msg = st.session_state.current_message.strip()

if analyse_btn:

    if not run_msg:
        st.warning("Please enter a message or upload a screenshot first.")

    else:
        st.markdown("---")
        st.markdown("## 📊 Detection Report")

        spinner_msg = (
            f"Running Ollama ({ollama_model}) + Rule Engine + Domain Scanner..."
            if use_ollama
            else "Running Rule Engine + Domain Scanner..."
        )

        with st.spinner(spinner_msg):
            result = full_analysis(
                run_msg,
                use_ollama=use_ollama,
                model_name=ollama_model
            )

        score = result["fraudScore"]
        r_cls, r_label = risk_class(score)
        color = score_color(score)
        flags = result["flags"]

        r1, r2 = st.columns([1, 1], gap="large")

        # LEFT PANEL
        with r1:
            st.markdown(
                f'<div class="risk-box {r_cls}">{r_label}</div>',
                unsafe_allow_html=True
            )

            if result["ai_used"]:
                st.markdown(
                    f'<div class="ai-badge">🤖 AI: OLLAMA {result["ai_model"].upper()}</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div class="ai-badge" style="border-color:#ffaa00;color:#ffcc44">⚙️ RULE ENGINE ONLY</div>',
                    unsafe_allow_html=True
                )

            st.markdown(f"**Fraud Score: {score}/100**")

            st.markdown(
                f"""
                <div class="score-bar-wrap">
                    <div class="score-bar-fill"
                         style="width:{score}%;background:{color}">
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(f"**Scheme Type:** `{result['schemeType']}`")
            st.markdown(f"**Verdict:** `{result['verdict']}`")
            st.markdown(f"> {result['summary']}")

            st.info(f"💡 **Recommendation:** {result['recommendation']}")

        # RIGHT PANEL
        with r2:
            st.markdown(f"**🚩 Flags Detected: {len(flags)}**")

            for flag in flags:
                sev = flag.get("severity", "LOW")
                ftype = flag.get("type", "")
                detail = flag.get("detail", "")
                source = flag.get("source", "ENGINE")

                sev_color = {
                    "HIGH": "#ff6b6b",
                    "MEDIUM": "#ffcc44",
                    "LOW": "#69ffb4"
                }.get(sev, "#ccc")

                st.markdown(
                    f"""
                    <div class="flag-card flag-{sev}">
                        <b style="color:{sev_color}">[{sev}]</b>
                        &nbsp;<code>{ftype}</code>
                        &nbsp;<small style="color:#3a6ea5">[{source}]</small><br>
                        <span style="font-size:12px;color:#8ab0cc">{detail}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            if not flags:
                st.success("No suspicious flags found.")

        # PIPELINE STATS
        st.markdown("---")

        p1, p2, p3 = st.columns(3)

        p1.markdown(
            f"""
            <div class="pipeline-box">
                ⚙️ RULE ENGINE<br><br>
                <span style="font-size:22px">{result["rule_count"]}</span><br>
                flags raised
            </div>
            """,
            unsafe_allow_html=True
        )

        p2.markdown(
            f"""
            <div class="pipeline-box">
                🌐 DOMAIN SCANNER<br><br>
                <span style="font-size:22px">{len(extract_links(run_msg))}</span><br>
                links checked
            </div>
            """,
            unsafe_allow_html=True
        )

        ai_label = (
            f"🤖 OLLAMA AI<br><br><span style='font-size:22px'>{score}/100</span><br>fraud score"
            if result["ai_used"]
            else f"📐 NLP HEURISTICS<br><br><span style='font-size:22px'>{score}/100</span><br>fraud score"
        )

        p3.markdown(
            f'<div class="pipeline-box">{ai_label}</div>',
            unsafe_allow_html=True
        )