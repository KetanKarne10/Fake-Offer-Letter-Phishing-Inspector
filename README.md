# 🛡️ PhishGuard SOC: Fake Offer Letter & Phishing Inspector

> An AI-driven cybersecurity scanner that detects fraudulent employment offers, rental advance-fee traps, and deposit phishing schemes across text, documents, images, and URLs. Built with **Google Gemini API** and deterministic heuristic engines.

---

## 📌 Problem Statement & Challenge
Job seekers and renters lose millions annually to fake appointment letters, pay-for-equipment phishing, and deposit schemes that bypass standard email spam filters.

**The Challenge:** Create a single-page security scanner that parses job offer text or URLs, checks domain indicators and payment demand red flags, and calculates a dynamic **Scam Threat Index (0–100%)**.

---

## ✨ Key Features
- **Dynamic Scam Threat Index (0–100%):** A composite scoring engine blending heuristic indicators with deep semantic reasoning.
- **Multimodal Input Ingestion:**
  - **Raw Text & Emails:** Instant inspection of pasted recruitment communications and offer letters[cite: 1].
  - **Documents & Files:** Supports PDF, DOCX, legacy DOC, and plain text files with automatic fallback extraction[cite: 9].
  - **Image Forensics:** Ingests document screenshots and letter scans with auto-compression downscaling for rapid AI analysis[cite: 15].
  - **URL & Link Scanner:** Scrapes job postings and career links with bot-protection handling and domain extraction[cite: 14].
- **Dual-Engine Threat Analysis:**
  - **Deterministic Heuristic Track (40% Weight):** Regex pattern matching for non-standard payment gateways (Zelle, CashApp, Wire, Crypto) and public webmail spoofing (@gmail.com, @yahoo.com)[cite: 1].
  - **Google Gemini Reasoner (60% Weight):** Evaluates psychological coercion, lack of legitimate interview protocols, and advance-equipment fraud using strict JSON schema output[cite: 1].
- **Incident Response & Audit Export:** One-click JSON export providing forensic audit logs and immediate defensive steps for targets.
- **Modern SOC Glassmorphic UI:** Cyber HUD interface featuring real-time circular threat speedometer gauges and telemetry breakdown.

---

## 🧠 Threat Index Formulation

The **Scam Threat Index** is computed dynamically through a weighted formulation[cite: 1]:

$$\text{Threat Index} = \min(100, (0.4 \times \text{Heuristic Score}) + (0.6 \times \text{Gemini AI Score}))$$

| Score Range | Threat Tier | Description |
| :--- | :--- | :--- |
| **0% – 34%** | 🟢 **Verified / Low Risk** | Standard enterprise onboarding, zero monetary demands, corporate domain alignment. |
| **35% – 69%** | 🟡 **Suspicious / Caution** | Unverified communication channels, missing interview stages, or unconfirmed domains. |
| **70% – 100%** | 🔴 **Critical Scam Threat** | Advance payment demands (laptops/supplies), overpayment check scams, or identity phishing[cite: 1]. |

---

## 🛠️ Tech Stack
- **Framework:** Streamlit (Python)[cite: 1]
- **AI Model:** Google Gemini API (`google-genai` SDK)[cite: 1]
- **Document & File Parsers:** `pypdf`, `python-docx`, `Pillow`[cite: 9]
- **Web Intelligence:** `beautifulsoup4`, `requests`, `tldextract`
- **Schema Validation:** `pydantic`

---

## 🚀 Local Setup & Installation

### 1. Clone the Repository
```bash
git clone [https://github.com/](https://github.com/)<your-username>/<repo-name>.git
cd <repo-name>