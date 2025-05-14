import os
import stat
import re
import requests
import time
import subprocess
import logging
from datetime import datetime
from flask import Flask, request, render_template, jsonify
import pyclamd
import yara

# Initialize Flask app
app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = '/tmp/uploads/' if os.name != 'nt' else os.path.join(os.getcwd(), 'uploads')
VT_API_KEY = 'f15c77d934f968082e55bef19a5f12a5e4cd18d28f2935296c3c51522ff49068'
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma3:1b"
ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'pdf', 'doc', 'docx', 'zip', 'rar', 'tar', 'gz', '7z', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 
    'mp3', 'wav', 'flac', 'mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'html', 'css', 'js', 'json', 'xml', 'csv', 
    'txt', 'md', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'psd', 'ai', 'eps', 'svg', 'ttf', 'otf', 'woff', 'woff2', 
    'apk', 'ipa', 'tar.gz', 'pkg', 'deb', 'rpm', 'iso', 'dmg', 'bin', 'cue', 'vmdk', 'vmx', 'sql', 'db', 'bak', 
    'pem', 'cer', 'crt', 'pfx', 'key', 'csr', 'conf', 'ini', 'log', 'bak', 'mpg', 'webp', 'eot', 'woff2', 'bin', 
    'md5', 'sha256', 'pub', 'pem', 'p7s', 'csh', 'sh', 'bat', 'msi', 'jar', 'py', 'rb', 'php', 'pl', 'lua', 'go', 
    'scala', 'swift', 'r', 'mat', 'h5', 'yaml', 'yml', 'bz2', 'xz', 'zst', 'tgz', 'lzma', 'xz', 'rpm', 'deb', 'dmg',
}


# Setup
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Logger setup
logging.basicConfig(level=logging.INFO)

# ClamAV setup
try:
    if os.name == 'nt':
        cd = pyclamd.ClamdNetworkSocket()
    else:
        cd = pyclamd.ClamdUnixSocket()
    cd.ping()
except Exception as e:
    cd = None
    logging.error(f"ClamAV initialization failed: {e}")

# Routes
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

    if not allowed_file(filename):
        return render_template('report.html',
                               result="⚠️ Invalid file type uploaded.",
                               ai_explanation="",
                               filename=filename,
                               current_time=get_timestamp())

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    # Run ClamAV scan first
    clamav_result = scan_with_clamav(file_path)
    if "clean" not in clamav_result.lower():
        return render_template('report.html',
                               result=clamav_result,
                               ai_explanation="AI is not available due to an infection.",
                               filename=filename,
                               current_time=get_timestamp())

    # If ClamAV passed, proceed to VirusTotal
    vt_result = scan_with_virustotal(file_path)
    if "scan timed out" in vt_result.lower():
        vt_result = "⚠️ VirusTotal scan timed out. Please try again."

    # After VirusTotal, run YARA scan
    yara_result = scan_with_yara(file_path)

    # Now run AI analysis after all scans are done
    result = f"{clamav_result}<br><br>{vt_result}<br><br>{yara_result}"
    ai_explanation = explain_with_ollama(result)

    try:
        os.remove(file_path)
    except Exception as e:
        logging.warning(f"Failed to delete uploaded file: {e}")

    return render_template('report.html',
                           result=result,
                           ai_explanation=ai_explanation,
                           filename=filename,
                           current_time=get_timestamp())

# Scanners
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


def scan_with_yara(file_path):
    try:
        yara_rules_path = os.path.join(os.path.dirname(__file__), "malware_rules.yar")
        if not os.path.exists(yara_rules_path):
            return "⚠️ YARA rules file not found."
        rules = yara.compile(filepath=yara_rules_path)
        matches = rules.match(file_path)
        if matches:
            matches_str = "\n".join(str(match) for match in matches)
            return f"🚨 <strong>YARA Match Found:</strong><br><pre>{matches_str}</pre>"
        return "✅ <strong>No YARA matches.</strong> File appears safe."
    except Exception as e:
        return f"⚠️ YARA scan error: {e}"


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

        for i in range(30):
            logging.info(f"Waiting for VT result... Attempt {i+1}/30")
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

                result += f"<br><a href='https://www.virustotal.com/gui/file/{file_id}' target='_blank'>View full report on VirusTotal</a>"
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
            return response.json().get("response", "⚠️ AI returned an empty response.").strip()
        else:
            error_msg = response.json().get("error", "Unknown API error.")
            return f"⚠️ AI Error: {error_msg}"
    except Exception as e:
        return "⚠️ AI Analysis Unavailable - Contact Admin."


@app.route('/system-check')
def system_check():
    checks = {
        'ollama_running': False,
        'model_loaded': False,
        'api_accessible': False
    }

    try:
        if os.name == 'nt':
            checks['ollama_running'] = True
        else:
            result = subprocess.run(['systemctl', 'is-active', 'ollama'], capture_output=True)
            checks['ollama_running'] = result.stdout.decode().strip() == 'active'

        result = subprocess.run(['ollama', 'list'], capture_output=True)
        checks['model_loaded'] = OLLAMA_MODEL.split(':')[0] in result.stdout.decode()

        response = requests.get(f'{OLLAMA_ENDPOINT.replace("/generate", "")}/tags', timeout=5)
        checks['api_accessible'] = response.status_code == 200
    except Exception as e:
        checks['error'] = str(e)

    return jsonify(checks)

# Utility functions
def sanitize_filename(filename):
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == '__main__':
    app.run(debug=True, port=5001)
