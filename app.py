import os
import json
import hashlib
import uuid
from datetime import datetime
from flask import Flask, request, render_template, redirect, flash, send_from_directory
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import requests
import urllib3
from werkzeug.utils import secure_filename

# ── Suppress SSL warnings for local MobSF ──────────────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── MobSF config ────────────────────────────────────────────────────────────
# Start MobSF first, then grab the API key from http://127.0.0.1:8000
# (shown on the MobSF home page after login)
MOBSF_URL = "http://127.0.0.1:8000"
API_KEY = os.environ.get("MOBSF_API_KEY")



UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
ALLOWED_EXTENSIONS = {"apk"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "cybersecurity-project"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024


# ── Helpers ─────────────────────────────────────────────────────────────────

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()


def unique_filename(original_name):
    """Prefix with a UUID so two APKs with the same name don't collide."""
    base = secure_filename(original_name)
    return f"{uuid.uuid4().hex}_{base}"


# ── Analysis functions ───────────────────────────────────────────────────────

def run_static_analysis(apk_path):
    """
    Upload the APK to MobSF, trigger a scan, then fetch the full JSON report.
    Returns a structured dict with the most useful fields.
    """
    if not API_KEY:
        return {
            "status": "failed",
            "reason": (
                "MobSF API key not configured. "
                "Set environment variable MOBSF_API_KEY to the key shown on MobSF home page (after login). "
                f"MobSF URL: {MOBSF_URL}"
            ),
        }

    headers = {"Authorization": API_KEY}

    try:
        # 1. Upload
        with open(apk_path, "rb") as apk_file:
            upload_resp = requests.post(
                f"{MOBSF_URL}/api/v1/upload",
                files={"file": (os.path.basename(apk_path), apk_file, "application/octet-stream")},
                headers=headers,
                timeout=60,
            )
        upload_resp.raise_for_status()
        upload_data = upload_resp.json()
        file_hash = upload_data.get("hash")

        if not file_hash:
            return {"status": "failed", "reason": f"Upload failed: {upload_data}"}

        # 2. Scan
        scan_resp = requests.post(
            f"{MOBSF_URL}/api/v1/scan",
            data={"hash": file_hash, "re_scan": 0},
            headers=headers,
            timeout=120,
        )
        scan_resp.raise_for_status()

        # 3. Fetch full JSON report (contains all findings)
        report_resp = requests.post(
            f"{MOBSF_URL}/api/v1/report_json",
            data={"hash": file_hash},
            headers=headers,
            timeout=60,
        )
        report_resp.raise_for_status()
        report_data = report_resp.json()

        # Extract the most relevant fields
        permissions = report_data.get("permissions", {})
        dangerous_perms = [
            p for p, v in permissions.items()
            if isinstance(v, dict) and v.get("status", "").lower() == "dangerous"
        ] if isinstance(permissions, dict) else []

        manifest_analysis = report_data.get("manifest_analysis", {})
        manifest_issues = []
        if isinstance(manifest_analysis, dict):
            for severity in ("high", "warning", "info"):
                for item in manifest_analysis.get(severity, []):
                    manifest_issues.append({
                        "severity": severity.upper(),
                        "title": item.get("title", ""),
                        "description": item.get("description", ""),
                    })

        code_analysis = report_data.get("code_analysis", {})
        code_issues = []
        if isinstance(code_analysis, dict):
            findings = code_analysis.get("findings", {})
            for rule_id, finding in findings.items():
                code_issues.append({
                    "rule": rule_id,
                    "severity": finding.get("metadata", {}).get("severity", ""),
                    "description": finding.get("metadata", {}).get("description", ""),
                    "files_count": len(finding.get("files", [])),
                })

        return {
            "status": "success",
            "hash": file_hash,
            "app_name": report_data.get("app_name", "N/A"),
            "package_name": report_data.get("package_name", "N/A"),
            "version_name": report_data.get("version_name", "N/A"),
            "min_sdk": report_data.get("min_sdk", "N/A"),
            "target_sdk": report_data.get("target_sdk", "N/A"),
            "security_score": report_data.get("security_score", "N/A"),
            "average_cvss": report_data.get("average_cvss", "N/A"),
            "dangerous_permissions": dangerous_perms,
            "manifest_issues": manifest_issues[:10],   # top 10
            "code_issues": code_issues[:10],            # top 10
            "trackers": report_data.get("trackers", {}).get("detected_trackers", 0),
        }

    except requests.exceptions.ConnectionError:
        return {
            "status": "failed",
            "reason": "Cannot connect to MobSF. Make sure MobSF is running at " + MOBSF_URL,
        }
    except Exception as e:
        return {"status": "failed", "reason": str(e)}


def run_api_tests(apk_path):
    """
    Basic checks on the APK itself rather than a hardcoded external URL.
    Looks for hardcoded URLs/IPs inside the APK binary.
    """
    findings = []
    severity = "Low"

    try:
        with open(apk_path, "rb") as f:
            content = f.read()

        # Look for http:// endpoints (not https)
        import re
        http_urls = re.findall(rb"http://[a-zA-Z0-9./_?=&%-]{5,80}", content)
        unique_http = list({u.decode(errors="ignore") for u in http_urls})[:10]

        if unique_http:
            findings.append({
                "issue": "Plaintext HTTP endpoints found in APK",
                "detail": unique_http,
            })
            severity = "High"

        # Look for hardcoded IPs
        ips = re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
        unique_ips = list({ip.decode() for ip in ips
                           if not ip.startswith(b"127.") and not ip.startswith(b"0.")})[:10]
        if unique_ips:
            findings.append({
                "issue": "Hardcoded IP addresses found in APK",
                "detail": unique_ips,
            })
            if severity == "Low":
                severity = "Medium"

        if not findings:
            findings.append({"issue": "No obvious plaintext endpoints or hardcoded IPs found", "detail": []})

        return {"status": "completed", "severity": severity, "findings": findings}

    except Exception as e:
        return {"status": "failed", "reason": str(e), "severity": "Unknown", "findings": []}


def generate_report(filename, sha256_hash, static, dynamic, api):
    report = {
        "timestamp": str(datetime.now()),
        "file_name": filename,
        "sha256": sha256_hash,
        "static_analysis": static,
        "dynamic_analysis": dynamic,
        "api_testing": api,
    }

    # Use the unique filename (without path) as the report base name
    base = os.path.splitext(filename)[0]
    report_name = f"{base}_report.json"
    report_path = os.path.join(REPORT_FOLDER, report_name)

    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    return report, report_name


def generate_pdf_report(report, filename):
    base = os.path.splitext(filename)[0]
    pdf_name = f"{base}_report.pdf"
    pdf_path = os.path.join(REPORT_FOLDER, pdf_name)

    doc = SimpleDocTemplate(pdf_path)
    styles = getSampleStyleSheet()
    elements = []

    def h(text, style="Heading2"):
        elements.append(Paragraph(text, styles[style]))
        elements.append(Spacer(1, 8))

    def body(text):
        safe = str(text).replace("<", "&lt;").replace(">", "&gt;")
        elements.append(Paragraph(safe, styles["BodyText"]))
        elements.append(Spacer(1, 6))

    # Title
    elements.append(Paragraph("Mobile Security Scan Report", styles["Title"]))
    elements.append(Spacer(1, 20))

    # File info
    h("File Information")
    body(f"File Name: {report['file_name']}")
    body(f"SHA256: {report['sha256']}")
    body(f"Scanned: {report['timestamp']}")
    elements.append(Spacer(1, 12))

    # Static analysis
    h("Static Analysis")
    sa = report["static_analysis"]
    if sa.get("status") == "success":
        rows = [
            ["App Name", sa.get("app_name", "N/A")],
            ["Package", sa.get("package_name", "N/A")],
            ["Version", sa.get("version_name", "N/A")],
            ["Security Score", str(sa.get("security_score", "N/A"))],
            ["Avg CVSS", str(sa.get("average_cvss", "N/A"))],
            ["Trackers Detected", str(sa.get("trackers", "N/A"))],
            ["Dangerous Permissions", str(len(sa.get("dangerous_permissions", [])))],
        ]
        t = Table(rows, colWidths=[160, 300])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#111827"), colors.HexColor("#1f2937")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 10))

        if sa.get("manifest_issues"):
            body("Top Manifest Issues:")
            for issue in sa["manifest_issues"][:5]:
                body(f"  [{issue['severity']}] {issue['title']}")
    else:
        body(f"Status: {sa.get('status')} — {sa.get('reason', sa.get('error', ''))}")

    elements.append(Spacer(1, 12))

    # Dynamic analysis
    h("Dynamic Analysis")
    da = report["dynamic_analysis"]
    body(f"Status: {da.get('status', 'N/A')}")
    if da.get("reason"):
        body(f"Reason: {da['reason']}")

    elements.append(Spacer(1, 12))

    # API testing
    h("API / Network Testing")
    api = report["api_testing"]
    body(f"Status: {api.get('status', 'N/A')}  |  Severity: {api.get('severity', 'N/A')}")
    for finding in api.get("findings", []):
        body(f"• {finding['issue']}")
        if finding.get("detail"):
            for d in finding["detail"][:5]:
                body(f"    - {d}")

    doc.build(elements)
    return pdf_name


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    if "apk" not in request.files:
        flash("No file uploaded")
        return redirect("/")

    file = request.files["apk"]

    if file.filename == "":
        flash("No file selected")
        return redirect("/")

    if not allowed_file(file.filename):
        flash("Only APK files are allowed")
        return redirect("/")

    # Use a unique name so different APKs never overwrite each other
    filename = unique_filename(file.filename)
    apk_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(apk_path)

    sha256_hash = calculate_sha256(apk_path)

    static_result = run_static_analysis(apk_path)

    dynamic_result = {
        "status": "skipped",
        "reason": "Dynamic analysis requires a connected Android device / emulator with Frida.",
    }

    api_result = run_api_tests(apk_path)

    report, report_name = generate_report(filename, sha256_hash, static_result, dynamic_result, api_result)

    pdf_name = generate_pdf_report(report, filename)

    return render_template(
        "result.html",
        report=report,
        report_name=report_name,
        pdf_name=pdf_name,
    )


@app.route("/download/<path:filename>")
def download(filename):
    """Serve JSON and PDF reports for download."""
    return send_from_directory(
        os.path.abspath(REPORT_FOLDER),
        filename,
        as_attachment=True,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
