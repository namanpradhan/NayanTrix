import os
import stat
import re
import requests
import time
from datetime import datetime
from flask import Flask, request, render_template
import pyclamd

app = Flask(__name__)

# Upload folder
UPLOAD_FOLDER = '/tmp/uploads/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 🔐 VirusTotal API Key (your key)
VT_API_KEY = 'f15c77d934f968082e55bef19a5f12a5e4cd18d28f2935296c3c51522ff49068'

# ClamAV setup
cd = pyclamd.ClamdUnixSocket()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template('report.html', result="No file selected.", filename="N/A", current_time=get_timestamp())

    file = request.files['file']
    if file.filename == '':
        return render_template('report.html', result="No file selected.", filename="N/A", current_time=get_timestamp())

    if file:
        filename = sanitize_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        # Scan with ClamAV
        clamav_result = scan_with_clamav(file_path)

        # If clean, scan with VirusTotal
        if "clean" in clamav_result.lower():
            vt_result = scan_with_virustotal(file_path)
            result = f"{clamav_result}<br><br>{vt_result}"
        else:
            result = f"{clamav_result}<br><br>VirusTotal Scan Skipped."

        try:
            os.remove(file_path)
        except Exception as e:
            print(f"Error deleting file: {e}")

        return render_template('report.html', result=result, filename=filename, current_time=get_timestamp())

def scan_with_clamav(file_path):
    try:
        cd.ping()
        abs_path = os.path.abspath(file_path)
        result = cd.scan_file(abs_path)
        if result:
            return f"🚨 <strong>File is INFECTED!</strong><br>Details:<br><pre>{result}</pre>"
        return "✅ <strong>File is clean.</strong> No malware detected by Basic Scanner."
    except Exception as e:
        return f"⚠️ Error scanning file with ClamAV: {e}"

def scan_with_virustotal(file_path):
    try:
        files = {'file': open(file_path, 'rb')}
        headers = {'x-apikey': VT_API_KEY}
        upload_url = 'https://www.virustotal.com/api/v3/files'
        response = requests.post(upload_url, files=files, headers=headers)

        if response.status_code != 200:
            return f"❌ Error uploading to VirusTotal: {response.text}"
        
        file_id = response.json()['data']['id']
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'

        for _ in range(30):
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_data = analysis_response.json()
            status = analysis_data['data']['attributes']['status']
            if status == 'completed':
                stats = analysis_data['data']['attributes']['stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)

                details = (
                    f"🔍 <strong>NayanTrix Scan Result:</strong><br>"
                    f"Detected by <strong>{malicious}</strong> engines<br>"
                    f"{suspicious} suspicious, {harmless} harmless, {undetected} undetected<br><br>"
                )

                engines = []
                for engine, result in analysis_data['data']['attributes']['results'].items():
                    if result.get('category') == 'malicious':
                        engines.append(f"{engine}: {result.get('result')}")

                if engines:
                    details += "<strong>Engines that flagged the file:</strong><br><pre>" + "\n".join(engines) + "</pre>"
                else:
                    details += "✅ No malicious engines detected."

                return details

            time.sleep(3)

        return "⚠️ NayanTrix scan timed out. Try again later."

    except Exception as e:
        return f"❌ NayanTrix scan error: {e}"

def sanitize_filename(filename):
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', filename)

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if __name__ == '__main__':
    app.run(debug=True)
