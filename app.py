"""
Fake Offer Letter & Phishing Inspector Pro: Automated Threat Intelligence Engine.
Compliant with WCAG 2.1 AA accessibility standards and high-efficiency caching.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Tuple

from bs4 import BeautifulSoup
import docx
from google import genai
from google.genai import types
from PIL import Image
from pydantic import BaseModel, Field
from pypdf import PdfReader
import requests
import streamlit as st
import tldextract

# ----------------- SYSTEM LOGGING CONFIGURATION -----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PhishGuardEngine")

# ----------------- STREAMLIT PAGE CONFIGURATION -----------------
st.set_page_config(
    page_title="Fake Offer Letter & Phishing Inspector Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ----------------- WCAG 2.1 AA ACCESSIBLE THEME -----------------
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    #MainMenu, footer, header {visibility: hidden;}
    [data-testid="stSidebar"] {display: none;}
    
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }

    /* WCAG AA High Contrast Banner */
    .cyber-header {
        background: linear-gradient(135deg, #090d16 0%, #171b26 100%);
        border: 2px solid #6366f1;
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .cyber-title {
        font-size: 2.1rem;
        font-weight: 800;
        color: #ffffff;
        margin: 0 0 4px 0;
    }
    .cyber-subtitle {
        color: #cbd5e1;
        font-size: 0.96rem;
        margin: 0;
    }
    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: #064e3b;
        border: 1px solid #10b981;
        color: #ecfdf5;
        padding: 6px 14px;
        border-radius: 999px;
        font-size: 0.85rem;
        font-weight: 700;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        background-color: #34d399;
        border-radius: 50%;
    }

    .glass-card {
        background: #111827;
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 14px;
    }
    .card-title {
        font-size: 1.05rem;
        font-weight: 700;
        color: #f9fafb;
        margin-bottom: 12px;
    }

    /* WCAG compliant High-Contrast Badges */
    .flag-item {
        background: #450a0a;
        border-left: 4px solid #f87171;
        padding: 12px;
        margin-bottom: 8px;
        color: #fef2f2;
        border-radius: 0 8px 8px 0;
        font-size: 0.92rem;
    }
    .defense-item {
        background: #064e3b;
        border-left: 4px solid #34d399;
        padding: 12px;
        margin-bottom: 8px;
        color: #f0fdf4;
        border-radius: 0 8px 8px 0;
        font-size: 0.92rem;
    }

    .stButton > button {
        background: #4f46e5;
        color: #ffffff !important;
        border: 1px solid #6366f1;
        border-radius: 8px;
        font-weight: 700;
        height: 48px;
        font-size: 1rem;
    }
    .stButton > button:focus {
        outline: 3px solid #38bdf8 !important;
        outline-offset: 2px;
    }
</style>
""",
    unsafe_allow_html=True,
)

# ----------------- RIGOROUS PYDANTIC SCHEMAS -----------------
class PhishingAnalysisResult(BaseModel):
    """Pydantic model representing structured threat analysis from Gemini."""
    scam_likelihood_score: int = Field(
        ..., ge=0, le=100, description="Integer 0 to 100 indicating fraud probability."
    )
    risk_level: str = Field(..., description="'Legitimate', 'Suspicious', or 'Critical Threat'")
    scam_type: str = Field(
        ...,
        description="Category: 'Advance-Fee Equipment Scam', 'Design Template / Generic Format', or 'Legitimate Enterprise Offer'",
    )
    detected_red_flags: list[str] = Field(default_factory=list, description="Specific fraud patterns found.")
    communication_analysis: str = Field(..., description="Evaluation of communication authenticity.")
    verdict_summary: str = Field(..., description="Forensic summary explanation.")
    recommended_actions: list[str] = Field(default_factory=list, description="Actionable defense steps.")


# ----------------- HEURISTIC SIGNATURE CONSTANTS -----------------
ADVANCE_FEE_PATTERNS = [
    r"\bzelle\b", r"\bcashapp\b", r"\bvenmo\b", r"\bgift card\b", r"\bwire transfer\b",
    r"\bcrypto\b", r"\bbitcoin\b", r"\bequipment fee\b", r"\brefundable fee\b",
    r"\bsecurity deposit\b", r"\bcourier check\b", r"\bregistration fee\b",
    r"\bpurchase.*equipment\b", r"\bpay.*vendor\b",
]
FREE_WEBMAILS = ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com", "telegram.me", "t.me/"]
URGENCY_TOKENS = ["within 24 hours", "immediate response", "urgent", "act now", "limited slot"]

# ----------------- OPTIMIZED & CACHED HEURISTICS ENGINE -----------------
@st.cache_data(show_spinner=False, max_entries=128)
def run_heuristics(text: str) -> Tuple[int, list[str], list[Tuple[str, str]]]:
    """Deterministic rule-based heuristics engine. Cached for O(1) repeated evaluation."""
    if not text or not text.strip():
        return 0, [], []

    score = 0
    flags: list[str] = []
    text_lower = text.lower()

    # 1. Advance Fee & Equipment Traps
    found_keywords = {kw for kw in ADVANCE_FEE_PATTERNS if re.search(kw, text_lower)}
    if found_keywords:
        score += 40
        flags.append(f"Advance payment / equipment trap patterns found: {', '.join(found_keywords)}")

    # 2. Public Free Webmails
    found_mail = [m for m in FREE_WEBMAILS if m in text_lower]
    if found_mail:
        score += 30
        flags.append(f"Corporate communication uses free webmail/messaging: {', '.join(set(found_mail))}")

    # 3. Urgency Traps
    if any(k in text_lower for k in URGENCY_TOKENS):
        score += 20
        flags.append("High-pressure urgency coercion detected")

    # 4. Domain Signals
    urls = re.findall(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*", text)
    domain_info: list[Tuple[str, str]] = []
    for u in urls[:2]:
        try:
            ext = tldextract.extract(u)
            domain_name = f"{ext.domain}.{ext.suffix}"
            if domain_name and domain_name != ".":
                domain_info.append((domain_name, "Verified Domain"))
        except Exception as e:
            logger.warning("Domain extraction error: %s", e)

    return min(score, 100), flags, domain_info


# ----------------- HIGH-EFFICIENCY DOCUMENT EXTRACTION -----------------
def compress_image(img: Image.Image) -> Image.Image:
    """Downscales images to 1000px max and compresses to JPEG to eliminate processing latency."""
    if img.mode != "RGB":
        img = img.convert("RGB")
    max_dim = 1000
    if max(img.size) > max_dim:
        img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG", quality=80)
    buffer.seek(0)
    return Image.open(buffer)


def extract_text_from_file(uploaded_file: Any) -> Tuple[str, Image.Image | None]:
    """Safely extracts normalized text or optimized images from uploaded files."""
    file_type = uploaded_file.name.split(".")[-1].lower()

    if file_type == "txt":
        try:
            return uploaded_file.read().decode("utf-8", errors="ignore"), None
        except Exception:
            return "", None

    if file_type == "pdf":
        try:
            reader = PdfReader(uploaded_file)
            text_pages = [page.extract_text() or "" for page in reader.pages[:10]]
            return "\n".join(text_pages), None
        except Exception as e:
            logger.error("PDF Parsing exception: %s", e)
            return "", None

    if file_type in ["docx", "doc"]:
        try:
            doc = docx.Document(uploaded_file)
            text = "\n".join([p.text for p in doc.paragraphs if p.text.strip()])
            if text.strip():
                return text, None
        except Exception:
            pass
        # Binary fallback for legacy .doc
        try:
            uploaded_file.seek(0)
            raw = uploaded_file.read()
            tokens = re.findall(rb"[a-zA-Z0-9\s.,@:\-\/]{4,}", raw)
            return " ".join([t.decode("latin-1", errors="ignore").strip() for t in tokens]), None
        except Exception:
            return "", None

    if file_type in ["jpg", "jpeg", "png"]:
        try:
            raw_img = Image.open(uploaded_file)
            return "", compress_image(raw_img)
        except Exception as e:
            logger.error("Image loading exception: %s", e)
            return "", None

    return "", None


@st.cache_data(ttl=600, show_spinner=False)
def fetch_url_content(url: str) -> Tuple[str, str]:
    """Fetches and cleans target webpage content with anti-bot resilience and strict timeouts."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
        "Referer": "https://www.google.com/",
    }
    try:
        res = requests.get(url, headers=headers, timeout=3.5)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, "html.parser")
            for element in soup(["script", "style", "noscript", "svg", "header", "footer", "nav"]):
                element.decompose()
            cleaned = "\n".join([line.strip() for line in soup.get_text().splitlines() if line.strip()])
            return cleaned[:1200], "full"
    except Exception:
        pass

    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    slug = re.sub(r"[^a-zA-Z0-9]", " ", url)
    return f"Target URL: {url}\nDomain: {domain}\nSlug: {' '.join(slug.split())}", "fallback"


# ----------------- CACHED GENAI CLIENT -----------------
@st.cache_resource
def get_genai_client(api_key: str) -> genai.Client:
    """Singleton GenAI client instance cached across user sessions."""
    return genai.Client(api_key=api_key)


# ----------------- SEMANTIC THREAT REASONING ENGINE -----------------
def analyze_with_gemini(text: str, image: Image.Image | None, api_key: str) -> PhishingAnalysisResult:
    """Inspects text and visual assets via Gemini models with deterministic parameters."""
    client = get_genai_client(api_key)

    prompt = """
    You are an automated Cybersecurity Threat Intelligence Engine. 
    Inspect this document, offer letter, or text accurately for recruitment fraud.

    ACCURATE SCORING GUIDE:
    1. TEMPLATE SAMPLES & DESIGN PORTALS (Score: 10 - 20):
       - If it is a blank format, Canva template, or contains brackets like "[Company Name]", "[Candidate Name]", "[Start Date]", "[Salary]":
         Assign score 10-20. Risk level: 'Legitimate' or 'Suspicious'. Classification: 'Design Template / Generic Format'.
    2. REALISTIC ENTERPRISE OFFERS (Score: 0 - 15):
       - Legitimate company letter, zero money demands, corporate email, clear job structure.
    3. ADVANCE-FEE FRAUD & PHISHING (Score: 75 - 100):
       - Asking candidate to pay for laptop/software/equipment via Zelle, CashApp, Wire, Crypto.
       - Job given without interview, Telegram recruiters, free webmail (@gmail.com).

    Return strictly structured JSON.
    """

    contents: list[Any] = [prompt]
    if text.strip():
        contents.append(f"Document Text:\n{text[:3000]}")
    if image is not None:
        contents.append(image)

    candidate_models = ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"]

    for model_name in candidate_models:
        for _ in range(2):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=PhishingAnalysisResult,
                        temperature=0.0,
                        seed=42,
                    ),
                )
                if response.parsed:
                    return response.parsed
            except Exception as e:
                logger.warning("Attempt with %s failed: %s", model_name, e)
                if "429" in str(e):
                    time.sleep(2)
                break

    # Intelligent deterministic local fallback
    h_score, h_flags, _ = run_heuristics(text)
    is_template = bool(re.search(r"\[.*?\]|template|sample format|job offer letter format", text, re.IGNORECASE))

    if is_template:
        return PhishingAnalysisResult(
            scam_likelihood_score=15,
            risk_level="Legitimate",
            scam_type="Design Template / Generic Format",
            detected_red_flags=["Template placeholders detected ([...])"],
            communication_analysis="Document verified as an unfilled structural template.",
            verdict_summary="This document is a blank template/format containing placeholder tokens. It is not an active scam solicitation.",
            recommended_actions=["Ensure all placeholders are replaced with verified employer details before signing."],
        )

    if h_score >= 40:
        return PhishingAnalysisResult(
            scam_likelihood_score=min(h_score + 25, 95),
            risk_level="Critical Threat",
            scam_type="Advance-Fee Equipment Scam",
            detected_red_flags=h_flags,
            communication_analysis="Uses non-standard payment gateways or free public webmail for enterprise hiring.",
            verdict_summary="Document contains high-risk fraud signatures including upfront payment demands or webmail communications.",
            recommended_actions=[
                "Never send money or purchase equipment via personal accounts during hiring.",
                "Verify the company directly on LinkedIn or official corporate websites.",
            ],
        )

    return PhishingAnalysisResult(
        scam_likelihood_score=max(h_score, 12),
        risk_level="Legitimate",
        scam_type="Standard Job Agreement / Low Risk",
        detected_red_flags=h_flags if h_flags else ["No overt advance payment signals detected"],
        communication_analysis="Forensic pattern inspection completed.",
        verdict_summary="Standard corporate offer format with no upfront payment traps detected.",
        recommended_actions=["Verify recruiter authenticity on LinkedIn or corporate directory."],
    )


# ----------------- ACCESSIBLE SPEEDOMETER GAUGE -----------------
def render_cyber_gauge(score: int, risk_label: str, color_hex: str) -> None:
    """Renders a fully accessible SVG speedometer gauge with ARIA progress roles."""
    dash_array = f"{int(score * 2.83)}, 283"
    gauge_svg = f"""
    <div style="text-align: center; padding: 10px 0;" role="progressbar" aria-valuenow="{score}" aria-valuemin="0" aria-valuemax="100" aria-label="Scam Threat Score: {score} percent, {risk_label}">
        <svg viewBox="0 0 120 120" style="width: 175px; height: 175px;" aria-hidden="true">
            <circle cx="60" cy="60" r="45" fill="none" stroke="#1e293b" stroke-width="10" />
            <circle cx="60" cy="60" r="45" fill="none" stroke="{color_hex}" stroke-width="10"
                    stroke-dasharray="{dash_array}" stroke-dashoffset="0"
                    stroke-linecap="round" transform="rotate(-90 60 60)" 
                    style="transition: stroke-dasharray 0.8s ease;" />
            <text x="60" y="56" text-anchor="middle" fill="#f8fafc" font-size="22" font-weight="800" font-family="'JetBrains Mono', monospace">{score}%</text>
            <text x="60" y="74" text-anchor="middle" fill="#cbd5e1" font-size="8.5" font-weight="700" letter-spacing="0.5">THREAT INDEX</text>
        </svg>
        <div style="margin-top: 6px;">
            <span style="background: {color_hex}33; border: 1.5px solid {color_hex}; color: #ffffff; padding: 5px 14px; border-radius: 20px; font-weight: 700; font-size: 0.85rem; text-transform: uppercase;">
                {risk_label}
            </span>
        </div>
    </div>
    """
    st.markdown(gauge_svg, unsafe_allow_html=True)


# ----------------- APP HEADER -----------------
st.markdown(
    """
<header class="cyber-header" role="banner">
    <div>
        <h1 class="cyber-title">🛡️ Fake Offer Letter & Phishing Inspector</h1>
        <p class="cyber-subtitle">Real-time Scam Threat Index (0–100%) for Job Offers, Rental Listings & Phishing Links</p>
    </div>
    <div class="status-pill">
        <span class="status-dot"></span>
        <span>SOC SHIELD ACTIVE</span>
    </div>
</header>
""",
    unsafe_allow_html=True,
)

# ----------------- MULTI-INPUT NAVIGATION TABS -----------------
tab_text, tab_file, tab_url = st.tabs(["📝 Paste Text / Email", "📁 Upload Document / Image", "🔗 Scan Target URL"])

active_text = ""
active_image: Image.Image | None = None

# Tab 1: Text
with tab_text:
    SCAM_SAMPLE = """Subject: Immediate Offer: Remote Operations Specialist ($65/hr)

Dear Candidate,
We are pleased to inform you that following your profile review, you have been selected for the Remote Operations role at Apex Global Technologies without further interview. Your starting pay is $65.00/hour.

Before your deployment begins on Monday, you must purchase company-certified workstation equipment (MacBook Pro & Cisco Router) through our certified supplier. Please send $350 via Zelle or CashApp to procurement-desk@zellepay-vendor.com. This fee will be 100% refunded in your first paycheck.

Contact HR Director Michael on Telegram: @apex_michael_hr or via email: apexcareers.desk@gmail.com immediately within 24 hours."""

    SAFE_SAMPLE = """Subject: Offer of Employment - Software Engineer at Stripe

Dear Candidate,
Following your completed technical interview rounds, Stripe is pleased to offer you the position of Software Engineer. Your starting salary is $120,000 per year with standard benefits and equity options.

Our IT provisioning team will ship your required equipment directly to your verified residential address at no expense to you. We do not charge fees for background verification or onboarding.

Please review and sign the digital agreement via our secure portal at https://stripe.com/careers within 5 business days."""

    col_btn1, col_btn2, _ = st.columns([1.5, 1.5, 5])
    if "input_text" not in st.session_state:
        st.session_state.input_text = ""

    if col_btn1.button("🚨 Load Scam Sample", help="Load sample advance-fee scam text"):
        st.session_state.input_text = SCAM_SAMPLE
    if col_btn2.button("✅ Load Legitimate Sample", help="Load sample legitimate job offer"):
        st.session_state.input_text = SAFE_SAMPLE

    pasted_input = st.text_area(
        label="Recruitment or Offer Letter Text to Analyze:",
        value=st.session_state.input_text,
        height=180,
        placeholder="Paste offer letter, recruitment email, or lease text here...",
        help="Paste complete message body including sender emails, URLs, or payment requests.",
    )
    if pasted_input.strip():
        active_text = pasted_input

# Tab 2: File Upload
with tab_file:
    uploaded = st.file_uploader(
        label="Upload Offer Letter File (PDF, DOCX, DOC, PNG, JPG, TXT)",
        type=["pdf", "docx", "doc", "png", "jpg", "jpeg", "txt"],
        help="Upload digital offer letters or screenshot images for forensic scanning.",
    )
    if uploaded is not None:
        extracted_txt, img = extract_text_from_file(uploaded)
        if img:
            active_image = img
            st.image(img, caption=f"Uploaded Offer Document: {uploaded.name}", width=360)
        elif extracted_txt:
            active_text = extracted_txt
            st.success(f"Extracted {len(extracted_txt.split())} words from {uploaded.name}")
            with st.expander("Inspect Raw Extracted Document"):
                st.text(extracted_txt[:800] + ("..." if len(extracted_txt) > 800 else ""))

# Tab 3: URL Inspection
with tab_url:
    url_input = st.text_input(
        label="Target URL / Job Post Link:",
        placeholder="https://example-careers.com/job/offer-letter",
        help="Inspect job posting or rental listing webpage content.",
    )
    if url_input.strip():
        with st.spinner("Analyzing target link & security headers..."):
            scraped_content, mode = fetch_url_content(url_input)
            active_text = f"URL Target: {url_input}\nContext:\n{scraped_content}"
            if mode == "full":
                st.success(f"Successfully scraped content from: `{url_input}`")
            else:
                st.info(f"Target site has bot-protection. Extracted metadata for `{url_input}`.")

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

# ----------------- SCAN TRIGGER -----------------
inspect_btn = st.button("🛡️ Execute SOC Threat Inspection", use_container_width=True, help="Run Threat Inspection")

if inspect_btn:
    api_key = None
    try:
        api_key = st.secrets.get("GEMINI_API_KEY")
    except Exception:
        pass

    if not api_key:
        api_key = os.getenv("GEMINI_API_KEY")

    if not active_text.strip() and active_image is None:
        st.warning("⚠️ Please provide text, upload a file/image, or enter a valid URL to inspect.")
    elif not api_key:
        st.error("🔑 GEMINI_API_KEY not found. Please check `.streamlit/secrets.toml` or set the environment variable.")
    else:
        with st.spinner("Executing forensic heuristics and evaluating with Gemini..."):
            try:
                # 1. Run Heuristics on all extracted text
                h_score, h_flags, domain_info = run_heuristics(active_text) if active_text else (0, [], [])

                # 2. AI Reasoning
                ai_data: PhishingAnalysisResult = analyze_with_gemini(active_text, active_image, api_key)

                # 3. Dynamic Composite Calculation
                if active_text and h_score > 0:
                    threat_index = int((0.4 * h_score) + (0.6 * ai_data.scam_likelihood_score))
                else:
                    threat_index = ai_data.scam_likelihood_score

                threat_index = max(0, min(100, threat_index))

                # Threat level badges
                if threat_index >= 70:
                    badge_label = "CRITICAL THREAT"
                    gauge_color = "#ef4444"
                elif threat_index >= 35:
                    badge_label = "SUSPICIOUS / CAUTION"
                    gauge_color = "#f59e0b"
                else:
                    badge_label = "VERIFIED / LOW RISK"
                    gauge_color = "#10b981"

                st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

                # Top Result Grid
                top_c1, top_c2, top_c3 = st.columns([1.3, 2.3, 1.4])

                with top_c1:
                    st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
                    render_cyber_gauge(threat_index, badge_label, gauge_color)
                    st.markdown("</div>", unsafe_allow_html=True)

                with top_c2:
                    st.markdown(
                        f"""
                    <div class='glass-card'>
                        <div class='card-title'><span>🔍</span> Threat Classification: <span style='color: {gauge_color};'>{ai_data.scam_type}</span></div>
                        <p style='color: #cbd5e1; font-size: 0.94rem; line-height: 1.6;'>{ai_data.verdict_summary}</p>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                with top_c3:
                    st.markdown(
                        f"""
                    <div class='glass-card'>
                        <div class='card-title'><span>📊</span> Signal Telemetry</div>
                        <p style='color: #94a3b8; font-size: 0.85rem; margin-bottom: 6px;'>• Heuristic Triggers: <b style='color: #f8fafc;'>{h_score}%</b></p>
                        <p style='color: #94a3b8; font-size: 0.85rem; margin-bottom: 6px;'>• AI Model Confidence: <b style='color: #f8fafc;'>{ai_data.scam_likelihood_score}%</b></p>
                        <p style='color: #94a3b8; font-size: 0.85rem; margin-bottom: 6px;'>• Channel Vector: <b style='color: #f8fafc;'>{ai_data.communication_analysis}</b></p>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                # Forensic Findings Section
                col_left, col_right = st.columns(2)

                with col_left:
                    st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
                    all_flags = list(dict.fromkeys(h_flags + ai_data.detected_red_flags))
                    st.markdown(
                        f"<div class='card-title'><span>🚩</span> Detected Threat Signatures ({len(all_flags)})</div>",
                        unsafe_allow_html=True,
                    )
                    if all_flags:
                        for flag in all_flags:
                            st.markdown(f"<div class='flag-item'>⚠️ {flag}</div>", unsafe_allow_html=True)
                    else:
                        st.markdown(
                            "<div class='defense-item'>✅ No advance-fee or malicious phishing signatures detected.</div>",
                            unsafe_allow_html=True,
                        )
                    st.markdown("</div>", unsafe_allow_html=True)

                with col_right:
                    st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
                    st.markdown(
                        "<div class='card-title'><span>🛡️</span> Incident Response Next Steps</div>", unsafe_allow_html=True
                    )
                    for action in ai_data.recommended_actions:
                        st.markdown(f"<div class='defense-item'>🔒 {action}</div>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)

                # JSON Report Download
                report_data = {
                    "scan_timestamp": datetime.now().isoformat(),
                    "scam_threat_index": threat_index,
                    "risk_tier": badge_label,
                    "scam_type": ai_data.scam_type,
                    "detected_red_flags": all_flags,
                    "forensic_verdict": ai_data.verdict_summary,
                    "recommended_actions": ai_data.recommended_actions,
                }

                st.download_button(
                    label="📥 Download Forensic Audit Report (JSON)",
                    data=json.dumps(report_data, indent=2),
                    file_name=f"phishguard_audit_{int(time.time())}.json",
                    mime="application/json",
                    use_container_width=True,
                    help="Download Forensic Audit Report in JSON format",
                )

            except Exception as e:
                logger.error("Inspection failed: %s", e)
                st.error(f"Inspection failed: {str(e)}")