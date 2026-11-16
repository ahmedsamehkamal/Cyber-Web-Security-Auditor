from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import socket

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber Web Auditor v2.0</title>
    <style>
        body { font-family: 'Segoe UI', Arial; background: #0b1120; color: #f8fafc; display: flex; justify-content: center; padding-top: 40px; }
        .card { background: #1e293b; padding: 30px; border-radius: 14px; width: 480px; box-shadow: 0 15px 35px rgba(0,0,0,0.6); border: 1px solid #334155; }
        h2 { margin-top: 0; color: #38bdf8; }
        .search-box { display: flex; gap: 10px; }
        input { flex: 1; padding: 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: white; outline: none; }
        button { padding: 12px 20px; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; }
        button:hover { background: #2563eb; }
        .result { background: #0f172a; padding: 18px; border-radius: 10px; margin-top: 20px; line-height: 1.9; border: 1px solid #334155; }
        .score { font-size: 18px; font-weight: bold; padding: 8px 12px; border-radius: 6px; display: inline-block; margin-bottom: 10px; }
        .btn-download { background: #10b981; width: 100%; margin-top: 15px; }
        .btn-download:hover { background: #059669; }
    </style>
</head>
<body>
<div class="card">
    <h2>🛡️ Cyber Web Security Auditor v2.0</h2>
    <form method="GET" class="search-box">
        <input type="text" name="url" placeholder="Enter domain (e.g., google.com)" required>
        <button type="submit">Scan</button>
    </form>
    <div class="result" id="reportBox">{RESULT}</div>
    {DOWNLOAD_BTN}
</div>

<script>
function downloadReport() {
    const text = document.getElementById("reportBox").innerText;
    const blob = new Blob([text], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "Security_Audit_Report.txt";
    link.click();
}
</script>
</body>
</html>
"""

def check_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((ip, port))
    s.close()
    return "OPEN 🟢" if result == 0 else "CLOSED 🔴"

class SecurityDashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        target_list = query.get("url", [""])
        target = target_list[0].strip() if target_list else ""
        
        report = "Enter a website domain above to run a full Security & Port Audit."
        download_btn = ""

        if target:
            clean_domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            try:
                ip = socket.gethostbyname(clean_domain)
                req = urllib.request.urlopen(f"https://{clean_domain}", timeout=4)
                headers = req.headers
                
                score = 0
                if "X-Frame-Options" in headers:
                    x_frame = "✅ Protected (Anti-Clickjacking)"
                    score += 50
                else:
                    x_frame = "❌ Vulnerable (Missing X-Frame-Options)"

                if "Strict-Transport-Security" in headers:
                    hsts = "✅ Enabled (HSTS Enforced)"
                    score += 50
                else:
                    hsts = "⚠️ Weak (Missing HSTS)"

                p80 = check_port(ip, 80)
                p443 = check_port(ip, 443)
                p21 = check_port(ip, 21)

                score_color = "#10b981" if score == 100 else ("#f59e0b" if score == 50 else "#ef4444")
                
                report = f"""
                <div class="score" style="background: {score_color}22; color: {score_color}; border: 1px solid {score_color};">
                    Security Score: {score}%
                </div><br>
                <b>🎯 Target Domain:</b> {clean_domain}<br>
                <b>🌐 Server IP:</b> {ip}<br>
                <hr style="border-color: #334155;">
                <b>🛡️ Security Headers:</b><br>
                • Frame Protection: {x_frame}<br>
                • HTTPS Strict: {hsts}<br>
                <hr style="border-color: #334155;">
                <b>🔌 Open Ports Audit:</b><br>
                • Port 80 (HTTP): {p80}<br>
                • Port 443 (HTTPS): {p443}<br>
                • Port 21 (FTP): {p21}
                """
                download_btn = '<button class="btn-download" onclick="downloadReport()">📥 Download Client Report (.txt)</button>'
            except Exception as e:
                report = f"❌ Scan Failed: {e}"

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        page = HTML_PAGE.replace("{RESULT}", report).replace("{DOWNLOAD_BTN}", download_btn)
        self.wfile.write(page.encode("utf-8"))

    def log_message(self, format, *args):
        pass

print("[*] Cyber Web Auditor v2.0 is LIVE on http://localhost:9000")
HTTPServer(("127.0.0.1", 9000), SecurityDashboard).serve_forever()
