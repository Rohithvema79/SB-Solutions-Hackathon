import os
import re
import smtplib
import requests
from io import BytesIO
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import streamlit as st
from pathspec import PathSpec
import google.generativeai as genai
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Load .env
load_dotenv()

# Local imports
from scanner.parsers import parse_requirements_txt
from scanner.osv_client import OSVClient
from scanner.secret_rules import scan_text as scan_secrets, SKIP_DIRS
from scanner.config_rules import scan_text as scan_configs
from scanner.scorer import score_findings
from scanner.utils import extract_zip_to_memory, is_text_path

def get_latest_version(pkg_name: str) -> str:
    try:
        resp = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("info", {}).get("version", "latest")
    except Exception:
        pass
    return "latest"

st.set_page_config(page_title="Cyber Health Audit Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ Cyber Health Audit Agent")
st.markdown("Perform an automated **security health check** and get one-line fixes to secure your app.")

col1, col2 = st.columns(2)
req_file = col1.file_uploader("Upload requirements.txt", type=["txt", "in"])
zip_file = col2.file_uploader("Upload Project ZIP", type=["zip"])

st.markdown("### 📧 Enter mail id to send or receive report")
user_email = st.text_input("Enter your email", placeholder="youremail@example.com")

# ------------------------------------------------------------
# Step 1: Parse requirements
# ------------------------------------------------------------
items = []
unpinned_detected = False
if req_file:
    text = req_file.read().decode("utf-8", errors="ignore")
    unpinned_detected = any(
        not re.search(r"[=<>!~]{1,2}", line)
        and line.strip()
        and not line.strip().startswith("#")
        for line in text.splitlines()
    )
    items = parse_requirements_txt(text)
    st.caption(f"Parsed {len(items)} dependencies from requirements.txt")

# ------------------------------------------------------------
# Step 2: ZIP Scanning
# ------------------------------------------------------------
secret_findings, config_findings = [], []
gitignore_patterns = []
zip_bytes = None
zip_name = "project"

if zip_file:
    zip_name = os.path.splitext(zip_file.name)[0]
    zip_bytes = zip_file.read()
    try:
        files = extract_zip_to_memory(zip_bytes)
    except Exception as e:
        st.error(f"❌ Could not read ZIP file: {e}")
        st.stop()

    for path, data in files:
        if path.endswith(".gitignore"):
            gitignore_patterns = data.decode("utf-8", errors="ignore").splitlines()
            break

    spec = PathSpec.from_lines("gitwildmatch", gitignore_patterns)
    count_scanned = 0
    for path, data in extract_zip_to_memory(zip_bytes):
        if spec.match_file(path):
            continue
        if not is_text_path(path) or any(p in SKIP_DIRS for p in path.split("/")):
            continue
        text = data.decode("utf-8", errors="ignore")
        secret_findings.extend(scan_secrets(path, text))
        config_findings.extend(scan_configs(path, text))
        count_scanned += 1
    st.caption(f"Scanned {count_scanned} files (respecting .gitignore).")

if unpinned_detected:
    st.warning(
        "⚠️ Your requirements.txt doesn’t specify versions. "
        "Pip will install latest versions automatically. "
        "Please upload your project ZIP for full security check."
    )

# ------------------------------------------------------------
# Generate button
# ------------------------------------------------------------
if st.button("🚀 Generate Cyber Health Score"):
    if unpinned_detected and not zip_file:
        st.error("❌ Please upload your project ZIP file for a full scan.")
    else:
        with st.spinner("🔍 Running full security audit..."):
            vuln_flat = []
            if items:
                try:
                    client = OSVClient()
                    batch = client.query_batch(items)
                    vuln_flat = client.flatten_vulns(batch)
                except Exception as e:
                    st.warning(f"OSV.dev lookup failed ({e})")

            # 🔹 Add PyPI version lookup to each package
            for v in vuln_flat:
                v["recommended_version"] = get_latest_version(v["package"])

            result = score_findings(vuln_flat, secret_findings, config_findings)
            score = result.get("score", 0)

        st.subheader("🚨 Findings (Quick Summary)")
        if not (vuln_flat or secret_findings or config_findings):
            st.success("✅ No major issues found — your app looks secure!")
        else:
            for v in vuln_flat:
                current_ver = v.get("version", "unknown")
                recommended = v.get("recommended_version", "latest")
                st.markdown(
                    f"⚠️ **{v['package']}** version **{current_ver}** is outdated — "
                    f"upgrade to **{recommended}** or later."
                )
            for s in secret_findings:
                st.markdown(f"🔑 Hardcoded secret found in `{s['path']}` — move it to `.env`.")
            for c in config_findings:
                st.markdown(f"🛠️ {c['desc']} ({c['path']}) — {c['fix']}")

        st.metric("Cyber Health Score", f"{score}/100")
        st.progress(score / 100.0)

        # --------------------------------------------------------
        # Gemini Deep Scan
        # --------------------------------------------------------
        gemini_output = ""
        if zip_bytes:
            st.divider()
            st.subheader("🤖 Gemini 2.0 Flash Deep Security Audit")

            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                st.error("❌ Gemini API key not found in .env")
            else:
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel("gemini-2.0-flash")
                file_texts = []
                for path, data in extract_zip_to_memory(zip_bytes):
                    if not is_text_path(path) or any(p in SKIP_DIRS for p in path.split("/")):
                        continue
                    text = data.decode("utf-8", errors="ignore")
                    if len(text) < 200000:
                        file_texts.append(f"### File: {path}\n{text}")
                joined_text = "\n\n".join(file_texts[:10])
                prompt = f"""
You are a cybersecurity auditor.
Analyze these files for:
- Hardcoded secrets or credentials
- Unsafe configuration (DEBUG=True, open CORS)
- Misplaced .env files
- Weak passwords or tokens
Provide a summary and one-line fixes.

Files:
{joined_text}
"""
                with st.spinner("🤖 Gemini is analyzing your project..."):
                    try:
                        response = model.generate_content(prompt)
                        gemini_output = response.text.strip()
                        st.markdown(gemini_output)
                    except Exception as e:
                        st.error(f"Gemini analysis failed: {e}")
                        gemini_output = f"Gemini analysis failed: {e}"

        # --------------------------------------------------------
        # Generate PDF Report
        # --------------------------------------------------------
        pdf_buffer = BytesIO()
        pdf = canvas.Canvas(pdf_buffer, pagesize=letter)
        pdf.setTitle(f"{zip_name}_Report")

        text_object = pdf.beginText(40, 750)
        text_object.setFont("Helvetica", 11)
        text_object.textLine(f"Cyber Health Report - {zip_name}")
        text_object.textLine(f"Score: {score}/100")
        text_object.textLine("-" * 90)
        text_object.textLine("")

        text_object.textLine("## Vulnerability Findings:")
        if not vuln_flat:
            text_object.textLine("✅ None detected")
        else:
            for v in vuln_flat:
                current_ver = v.get("version", "unknown")
                recommended = v.get("recommended_version", "latest")
                text_object.textLine(f"⚠️ {v['package']} {current_ver} → upgrade to {recommended} or later.")

        text_object.textLine("")
        text_object.textLine("## Secret Findings:")
        if not secret_findings:
            text_object.textLine("✅ None detected")
        else:
            for s in secret_findings:
                text_object.textLine(f"🔑 {s['path']} — move secrets to .env")

        text_object.textLine("")
        text_object.textLine("## Configuration Findings:")
        if not config_findings:
            text_object.textLine("✅ None detected")
        else:
            for c in config_findings:
                text_object.textLine(f"🛠️ {c['desc']} ({c['path']}) — {c['fix']}")

        text_object.textLine("")
        text_object.textLine("🤖 Gemini Deep Audit Summary:")
        text_object.textLines(gemini_output[:1500] if gemini_output else "No AI audit output available.")
        pdf.drawText(text_object)
        pdf.showPage()
        pdf.save()

        pdf_buffer.seek(0)
        pdf_bytes = pdf_buffer.read()

        st.session_state["pdf_report"] = pdf_bytes
        st.session_state["pdf_name"] = f"{zip_name}_Report.pdf"

        st.download_button(
            label="📥 Download Cyber Health Report (PDF)",
            data=pdf_bytes,
            file_name=f"{zip_name}_Report.pdf",
            mime="application/pdf"
        )

# ------------------------------------------------------------
# Email Send Button
# ------------------------------------------------------------
if "pdf_report" in st.session_state and user_email:
    if st.button("📧 Send Report to My Email"):
        try:
            sender = os.getenv("EMAIL_SENDER")
            password = os.getenv("EMAIL_PASSWORD")

            if not sender or not password:
                st.error("❌ Missing EMAIL_SENDER or EMAIL_PASSWORD in .env file.")
            else:
                msg = MIMEMultipart()
                msg["From"] = sender
                msg["To"] = user_email
                msg["Subject"] = f"{st.session_state['pdf_name']} - Cyber Health Report"
                msg.attach(MIMEText("Please find attached your Cyber Health Report (PDF).", "plain"))

                pdf_attachment = MIMEApplication(st.session_state["pdf_report"], _subtype="pdf")
                pdf_attachment.add_header('Content-Disposition', 'attachment', filename=st.session_state["pdf_name"])
                msg.attach(pdf_attachment)

                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(sender, password)
                    server.send_message(msg)

                st.success(f"📩 Report successfully sent to {user_email}")
                print(f"✅ Email sent successfully to {user_email}")

        except smtplib.SMTPAuthenticationError:
            st.error("❌ Gmail authentication failed. Please use a Google App Password.")
        except Exception as e:
            st.error(f"❌ Email sending failed: {e}")
            print(f"❌ Email sending failed: {e}")
