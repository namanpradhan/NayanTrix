import os
import stat
import re
import requests
import time
import subprocess
from datetime import datetime
from flask import Flask, request, render_template, jsonify
import pyclamd

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = '/tmp/uploads/'
VT_API_KEY = 'f15c77d934f968082e55bef19a5f12a5e4cd18d28f2935296c3c51522ff49068'
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma3:1b"

# Setup upload folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ClamAV setup
try:
    cd = pyclamd.ClamdUnixSocket()
    cd.ping()  # Ensure ClamAV is running
except Exception as e:
    cd = None
    print(f"[ERROR] ClamAV initialization failed: {e}")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or request.files['file'].filename == '':
        return render_template('report.html',
                               result="⚠️ No file selected.",
                               ai_explanation="",
                               filename="N/A",
                               current_time=get_timestamp())

    file = request.files['file']
    filename = sanitize_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    # Restrict file permissions
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    clamav_result = scan_with_clamav(file_path)

    if "clean" in clamav_result.lower():
        vt_result = scan_with_virustotal(file_path)
        result = f"{clamav_result}<br><br>{vt_result}"
    else:
        result = f"{clamav_result}<br><br>⚠️ VirusTotal Scan Skipped (infection found locally)."

    ai_explanation = explain_with_ollama(result)

    try:
        os.remove(file_path)
    except Exception as e:
        print(f"[WARN] Failed to delete uploaded file: {e}")

    return render_template('report.html',
                           result=result,
                           ai_explanation=ai_explanation,
                           filename=filename,
                           current_time=get_timestamp())

def scan_with_clamav(file_path):
    try:
        if not cd:
            return "⚠️ ClamAV service is not available. Please start the ClamAV daemon."
        result = cd.scan_file(os.path.abspath(file_path))
        if result:
            return f"🚨 <strong>File is INFECTED!</strong><br>Details:<br><pre>{result}</pre>"
        return "✅ <strong>File is clean.</strong> No malware detected by ClamAV."
    except Exception as e:
        return f"⚠️ ClamAV scan error: {e}"

def scan_with_virustotal(file_path):
    try:
        with open(file_path, 'rb') as f:
            headers = {'x-apikey': VT_API_KEY}
            response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                files={'file': f},
                headers=headers
            )

        if response.status_code != 200:
            return f"❌ VirusTotal upload error: {response.text}"

        file_id = response.json()['data']['id']
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'

        # Wait for analysis to complete
        for _ in range(30):
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_data = analysis_response.json()
            if analysis_data['data']['attributes']['status'] == 'completed':
                stats = analysis_data['data']['attributes']['stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)

                result = (
                    f"🔍 <strong>VirusTotal Report:</strong><br>"
                    f"Detected by <strong>{malicious}</strong> engines<br>"
                    f"{suspicious} suspicious, {harmless} harmless, {undetected} undetected<br><br>"
                )

                flagged = [
                    f"{engine}: {res.get('result')}"
                    for engine, res in analysis_data['data']['attributes']['results'].items()
                    if res.get('category') == 'malicious'
                ]

                if flagged:
                    result += "<strong>Flagged by:</strong><br><pre>" + "\n".join(flagged) + "</pre>"
                else:
                    result += "✅ No malicious engines detected."

                return result
            time.sleep(3)

        return "⚠️ VirusTotal scan timed out. Please try again."

    except Exception as e:
        return f"❌ VirusTotal scan failed: {e}"

def explain_with_ollama(scan_results):
    try:
        prompt = (
            "Explain this antivirus scan result in simple terms. "
            "Highlight any security threats, possible malware type, and suggest safety actions. "
            f"\n\nScan Report:\n{scan_results}"
        )

        response = requests.post(
            OLLAMA_ENDPOINT,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_ctx": 2048}
            }
        )

        if response.status_code == 200:
            return response.json().get("response", "⚠️ AI returned an empty response.")
        else:
            error_msg = response.json().get("error", "Unknown API error.")
            print(f"[ERROR] Ollama response {response.status_code}: {error_msg}")
            return f"⚠️ AI Error: {error_msg}"
    except Exception as e:
        print(f"[ERROR] Ollama communication failed: {e}")
        return "⚠️ AI Analysis Unavailable - Contact Admin."

@app.route('/system-check')
def system_check():
    checks = {
        'ollama_running': False,
        'model_loaded': False,
        'api_accessible': False
    }

    try:
        result = subprocess.run(['systemctl', 'is-active', 'ollama'], capture_output=True)
        checks['ollama_running'] = result.stdout.decode().strip() == 'active'

        result = subprocess.run(['ollama', 'list'], capture_output=True)
        checks['model_loaded'] = OLLAMA_MODEL.split(':')[0] in result.stdout.decode()

        response = requests.get(f'{OLLAMA_ENDPOINT.replace("/generate", "")}/tags', timeout=5)
        checks['api_accessible'] = response.status_code == 200

    except Exception as e:
        checks['error'] = str(e)

    return jsonify(checks)

def sanitize_filename(filename):
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if __name__ == '__main__':
    app.run(debug=True)
