import os
import re
import smtplib
import zipfile
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

# Load environment variables (e.g., API keys, email credentials)
load_dotenv()

# Increase max file upload size for Streamlit
os.environ["STREAMLIT_SERVER_MAX_UPLOAD_SIZE"] = "500"

# Import custom scanner modules for vulnerability and configuration analysis
from scanner.parsers import parse_requirements_txt
from scanner.osv_client import OSVClient
from scanner.secret_rules import scan_text as scan_secrets, SKIP_DIRS
from scanner.config_rules import scan_text as scan_configs
from scanner.scorer import score_findings
from scanner.utils import extract_zip_to_memory, is_text_path

# Streamlit UI setup
st.set_page_config(page_title="Cyber Health Audit Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ Cyber Health Audit Agent")
st.markdown("Perform an automated **security health check** and get one-line fixes to secure your app.")

# File upload sections
col1, col2 = st.columns(2)
req_file = col1.file_uploader("Upload requirements.txt", type=["txt", "in"])
uploaded_files = col2.file_uploader(
    "Upload Project (ZIP or Folder)",
    type=None,
    accept_multiple_files=True,
    help="Upload your project as a ZIP or select multiple files to simulate a folder upload (limit: 500MB)."
)

# User email input
st.markdown("### Enter mail id to send or receive report")
user_email = st.text_input("Enter your email", placeholder="youremail@example.com")


# Fetches the latest version of a Python package from PyPI.
def get_latest_version(pkg_name: str) -> str:
    try:
        resp = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("info", {}).get("version", "latest")
    except Exception:
        pass
    return "latest"



# Function: combine_files_to_zip
# Combines multiple uploaded files into an in-memory ZIP file for scanning.
def combine_files_to_zip(files):
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        for file in files:
            zf.writestr(file.name, file.read())
    zip_buffer.seek(0)
    return zip_buffer



# Step 1: Parse requirements.txt

items = []
unpinned_detected = False
if req_file:
    text = req_file.read().decode("utf-8", errors="ignore")

    # Detect if any dependencies are unpinned (no version specified)
    unpinned_detected = any(
        not re.search(r"[=<>!~]{1,2}", line)
        and line.strip()
        and not line.strip().startswith("#")
        for line in text.splitlines()
    )

    # Parse dependencies into structured list
    items = parse_requirements_txt(text)
    st.caption(f"Parsed {len(items)} dependencies from requirements.txt")



# Step 2: Extract and scan uploaded project files

secret_findings, config_findings = [], []
gitignore_patterns = []
zip_bytes = None
zip_name = "project"

if uploaded_files:
    # Handle ZIP upload vs multiple file upload
    if len(uploaded_files) == 1 and uploaded_files[0].name.endswith(".zip"):
        zip_name = os.path.splitext(uploaded_files[0].name)[0]
        zip_bytes = uploaded_files[0].read()
    else:
        zip_name = "uploaded_folder"
        combined_zip = combine_files_to_zip(uploaded_files)
        zip_bytes = combined_zip.read()

    # Extract all files into memory
    try:
        files = extract_zip_to_memory(zip_bytes)
    except Exception as e:
        st.error(f"Could not read uploaded files: {e}")
        st.stop()

    # Check for .gitignore to skip ignored files
    for path, data in files:
        if path.endswith(".gitignore"):
            gitignore_patterns = data.decode("utf-8", errors="ignore").splitlines()
            break

    spec = PathSpec.from_lines("gitwildmatch", gitignore_patterns)
    count_scanned = 0

    # Scan all project files for secrets and insecure configs
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



# Step 3: Warning for unpinned dependencies

if unpinned_detected:
    st.warning(
        "⚠ Your requirements.txt doesn’t specify versions. "
        "Pip will install latest versions automatically. "
        "Please upload your project ZIP/folder for full security check."
    )



# Step 4: Run the complete audit when button is clicked

if st.button("Generate Cyber Health Score"):
    if unpinned_detected and not uploaded_files:
        st.error("Please upload your project folder/ZIP for a full scan.")
    else:
        with st.spinner("Running full security audit..."):
            vuln_flat = []
            if items:
                try:
                    client = OSVClient()
                    batch = client.query_batch(items)
                    vuln_flat = client.flatten_vulns(batch)
                except Exception as e:
                    st.warning(f"OSV.dev lookup failed ({e})")

            # Add recommended version info for each package
            for v in vuln_flat:
                v["recommended_version"] = get_latest_version(v["package"])

            # Combine all findings into a score
            result = score_findings(vuln_flat, secret_findings, config_findings)
            score = result.get("score", 0)

        # Display results in Streamlit
        st.subheader("Findings (Quick Summary)")
        if not (vuln_flat or secret_findings or config_findings):
            st.success("No major issues found — your app looks secure!")
        else:
            for v in vuln_flat:
                current_ver = v.get("version", "unknown")
                recommended = v.get("recommended_version", "latest")
                st.markdown(
                    f"⚠ **{v['package']}** version **{current_ver}** is outdated — "
                    f"upgrade to **{recommended}** or later."
                )
            for s in secret_findings:
                st.markdown(f"Hardcoded secret found in `{s['path']}` — move it to `.env`.")
            for c in config_findings:
                st.markdown(f"🛠️ {c['desc']} ({c['path']}) — {c['fix']}")

        st.metric("Cyber Health Score", f"{score}/100")
        st.progress(score / 100.0)



        # Step 5: Gemini Deep Security Audit (AI Analysis)

        gemini_output = ""
        if zip_bytes:
            st.divider()
            st.subheader("Gemini 2.0 Flash Deep Security Audit")

            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                st.error("Gemini API key not found in .env")
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
                with st.spinner("Gemini is analyzing your project..."):
                    try:
                        response = model.generate_content(prompt)
                        gemini_output = response.text.strip()
                        st.markdown(gemini_output)
                    except Exception as e:
                        st.error(f"Gemini analysis failed: {e}")
                        gemini_output = f"Gemini analysis failed: {e}"



        # Step 6: Generate PDF Report

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
            text_object.textLine("None detected")
        else:
            for v in vuln_flat:
                current_ver = v.get("version", "unknown")
                recommended = v.get("recommended_version", "latest")
                text_object.textLine(f"⚠️ {v['package']} {current_ver} → upgrade to {recommended} or later.")

        text_object.textLine("")
        text_object.textLine("## Secret Findings:")
        if not secret_findings:
            text_object.textLine("None detected")
        else:
            for s in secret_findings:
                text_object.textLine(f"🔑 {s['path']} — move secrets to .env")

        text_object.textLine("")
        text_object.textLine("## Configuration Findings:")
        if not config_findings:
            text_object.textLine("None detected")
        else:
            for c in config_findings:
                text_object.textLine(f"🛠️ {c['desc']} ({c['path']}) — {c['fix']}")

        text_object.textLine("")
        text_object.textLine("Gemini Deep Audit Summary:")
        text_object.textLines(gemini_output[:1500] if gemini_output else "No AI audit output available.")
        pdf.drawText(text_object)
        pdf.showPage()
        pdf.save()

        pdf_buffer.seek(0)
        pdf_bytes = pdf_buffer.read()

        st.session_state["pdf_report"] = pdf_bytes
        st.session_state["pdf_name"] = f"{zip_name}_Report.pdf"

        # PDF download button
        st.download_button(
            label="Download Cyber Health Report (PDF)",
            data=pdf_bytes,
            file_name=f"{zip_name}_Report.pdf",
            mime="application/pdf"
        )



# Step 7: Send report via email

if "pdf_report" in st.session_state and user_email:
    if st.button("Send Report to My Email"):
        try:
            sender = os.getenv("EMAIL_SENDER")
            password = os.getenv("EMAIL_PASSWORD")

            if not sender or not password:
                st.error("Missing EMAIL_SENDER or EMAIL_PASSWORD in .env file.")
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

                st.success(f"Report successfully sent to {user_email}")
                print(f"Email sent successfully to {user_email}")

        except smtplib.SMTPAuthenticationError:
            st.error("Gmail authentication failed. Please use a Google App Password.")
        except Exception as e:
            st.error(f"Email sending failed: {e}")
            print(f"Email sending failed: {e}")
