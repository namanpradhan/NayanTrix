import os
import stat
import re
import requests
import time
import hashlib
import logging
from datetime import datetime
from flask import Flask, request, render_template, jsonify
import pyclamd
import yara
from requests.auth import HTTPBasicAuth

# Initialize Flask app
app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = '/tmp/uploads/' if os.name != 'nt' else os.path.join(os.getcwd(), 'uploads')
VT_API_KEY = 'ADD-Your-API'
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma3:1b"
HYBRID_API_KEY = 'ADD-Your-API'
HYBRID_API_SECRET = 'ADD-Your-API'
METADEFENDER_API_KEY = 'ADD-Your-API'

ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'pdf', 'doc', 'docx', 'zip', 'rar', 'tar', 'gz', '7z',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'mp3', 'wav', 'flac', 'mp4',
    'mkv', 'avi', 'mov', 'wmv', 'flv', 'html', 'css', 'js', 'json', 'xml',
    'csv', 'txt', 'md', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'psd', 'ai',
    'eps', 'svg', 'ttf', 'otf', 'woff', 'woff2', 'apk', 'ipa', 'tar.gz', 'pkg',
    'deb', 'rpm', 'iso', 'dmg', 'bin', 'cue', 'vmdk', 'vmx', 'sql', 'db', 'bak',
    'pem', 'cer', 'crt', 'pfx', 'key', 'csr', 'conf', 'ini', 'log', 'mpg',
    'webp', 'eot', 'md5', 'sha256', 'pub', 'p7s', 'csh', 'sh', 'bat', 'msi',
    'jar', 'py', 'rb', 'php', 'pl', 'lua', 'go', 'scala', 'swift', 'r', 'mat',
    'h5', 'yaml', 'yml', 'bz2', 'xz', 'zst', 'tgz', 'lzma'
}

# Setup
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Logger
logging.basicConfig(level=logging.INFO)

# ClamAV
try:
    cd = pyclamd.ClamdNetworkSocket() if os.name == 'nt' else pyclamd.ClamdUnixSocket()
    cd.ping()
except Exception as e:
    cd = None
    logging.error(f"ClamAV not available: {e}")

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Upload and scan
@app.route('/upload', methods=['POST'])
def upload_file():
    scan_type = request.form.get('scan_type', 'basic')
    
    if 'file' not in request.files or request.files['file'].filename == '':
        return render_template('report.html', 
                             result="⚠️ No file selected.",
                             ai_explanation="", 
                             filename="N/A",
                             file_size="N/A",
                             file_type="N/A",
                             sha256="N/A",
                             current_time=get_timestamp())

    file = request.files['file']
    filename = sanitize_filename(file.filename)

    if not allowed_file(filename):
        return render_template('report.html', 
                             result="⚠️ Invalid file type uploaded.",
                             ai_explanation="", 
                             filename=filename,
                             file_size="N/A",
                             file_type="N/A",
                             sha256="N/A",
                             current_time=get_timestamp())

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    # Get file metadata
    file_size = os.path.getsize(file_path)
    file_type = filename.split('.')[-1].upper() if '.' in filename else 'UNKNOWN'
    sha256 = calculate_sha256(file_path)

    # Perform scans based on type
    if scan_type == 'basic':
        result = perform_basic_scan(file_path)
    else:
        result = perform_advanced_scan(file_path)

    ai_explanation = explain_with_ollama(result)

    try:
        os.remove(file_path)
    except Exception as e:
        logging.warning(f"Could not delete file: {e}")

    return render_template('report.html',
                         result=result,
                         ai_explanation=ai_explanation,
                         filename=filename,
                         file_size=file_size,
                         file_type=file_type,
                         sha256=sha256,
                         current_time=get_timestamp())

def perform_basic_scan(file_path):
    """Perform basic scan with ClamAV and YARA"""
    results = []
    
    # ClamAV scan
    clamav_result = scan_with_clamav(file_path)
    results.append(clamav_result)
    
    # YARA scan
    yara_result = scan_with_yara(file_path)
    results.append(yara_result)
    
    return "<br><br>".join(results)

def perform_advanced_scan(file_path):
    """Perform comprehensive scan with all engines"""
    results = []
    
    # Basic scans first
    results.append(perform_basic_scan(file_path))
    
    # Additional scans
    vt_result = scan_with_virustotal(file_path)
    hybrid_result = scan_with_hybrid_analysis(file_path)
    metadefender_result = scan_with_metadefender(file_path)
    
    results.extend([vt_result, hybrid_result, metadefender_result])
    return "<br><br>".join(results)

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Scanner functions
def scan_with_clamav(file_path):
    try:
        if not cd:
            return "⚠️ ClamAV service unavailable."
        
        start_time = time.time()
        result = cd.scan_file(os.path.abspath(file_path))
        scan_time = time.time() - start_time
        
        if result:
            return f"🚨 <strong>ClamAV Detected Malware! (Scan time: {scan_time:.2f}s)</strong><br><pre>{result}</pre>"
        return f"✅ <strong>ClamAV: No threats found. (Scan time: {scan_time:.2f}s)</strong>"
    except Exception as e:
        return f"⚠️ ClamAV error: {e}"

def scan_with_yara(file_path):
    try:
        yara_path = os.path.join(os.path.dirname(__file__), "malware_rules.yar")
        if not os.path.exists(yara_path):
            return "⚠️ YARA rules file missing."
        
        start_time = time.time()
        rules = yara.compile(filepath=yara_path)
        matches = rules.match(file_path)
        scan_time = time.time() - start_time
        
        if matches:
            return f"🚨 <strong>YARA Match: (Scan time: {scan_time:.2f}s)</strong><br><pre>{matches}</pre>"
        return f"✅ <strong>YARA: No matches found. (Scan time: {scan_time:.2f}s)</strong>"
    except Exception as e:
        return f"⚠️ YARA error: {e}"

def scan_with_virustotal(file_path):
    try:
        headers = {'x-apikey': VT_API_KEY}
        
        # Upload file
        with open(file_path, 'rb') as f:
            response = requests.post('https://www.virustotal.com/api/v3/files',
                                   headers=headers, 
                                   files={'file': f},
                                   timeout=30)
        
        if response.status_code != 200:
            return f"❌ VirusTotal upload failed: {response.text}"
        
        file_id = response.json()['data']['id']
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
        
        # Check analysis results with timeout
        timeout = 60  # 1 minute timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = requests.get(analysis_url, headers=headers, timeout=30).json()
            status = result['data']['attributes']['status']
            
            if status == 'completed':
                stats = result['data']['attributes']['stats']
                return (f"🔍 <strong>VirusTotal Results:</strong><br>"
                        f"Malicious: {stats['malicious']}<br>"
                        f"Suspicious: {stats['suspicious']}<br>"
                        f"Undetected: {stats['undetected']}<br>"
                        f"<a href='https://www.virustotal.com/gui/file/{file_id}' target='_blank'>View Full Report</a>")
            
            time.sleep(5)
        
        return "⚠️ VirusTotal scan timed out (1 minute). Results may still be processing."
    except requests.exceptions.Timeout:
        return "⚠️ VirusTotal connection timed out."
    except Exception as e:
        return f"❌ VirusTotal scan failed: {e}"

def scan_with_hybrid_analysis(file_path):
    try:
        url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
        auth = HTTPBasicAuth(HYBRID_API_KEY, HYBRID_API_SECRET)
        headers = {'User-Agent': 'Falcon Sandbox'}
        
        with open(file_path, 'rb') as f:
            response = requests.post(url, 
                                   auth=auth, 
                                   headers=headers, 
                                   files={'file': f},
                                   data={'environment_id': 300},
                                   timeout=30)
        
        if response.status_code != 200:
            return f"❌ Hybrid Analysis submission failed: {response.text}"
        
        sha256 = response.json().get('sha256')
        summary_url = f'https://www.hybrid-analysis.com/api/v2/report/{sha256}/summary'
        
        # Check results with timeout
        timeout = 60  # 1 minute timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = requests.get(summary_url, auth=auth, headers=headers, timeout=30)
            
            if result.status_code == 200 and result.json().get('verdict'):
                verdict = result.json()['verdict']
                score = result.json().get('threat_score', 'N/A')
                return (f"🔬 <strong>Hybrid Analysis:</strong><br>"
                        f"Verdict: {verdict}<br>"
                        f"Threat Score: {score}<br>"
                        f"<a href='https://www.hybrid-analysis.com/sample/{sha256}' target='_blank'>View Report</a>")
            
            time.sleep(5)
        
        return "⚠️ Hybrid Analysis timed out (1 minute). Results may still be processing."
    except requests.exceptions.Timeout:
        return "⚠️ Hybrid Analysis connection timed out."
    except Exception as e:
        return f"⚠️ Hybrid Analysis error: {e}"

def scan_with_metadefender(file_path):
    try:
        headers = {'apikey': METADEFENDER_API_KEY}
        
        # Upload file
        with open(file_path, 'rb') as f:
            response = requests.post('https://api.metadefender.com/v4/file', 
                                   headers=headers, 
                                   files={'file': f},
                                   timeout=30)
        
        if response.status_code != 200:
            return f"❌ MetaDefender upload failed: {response.text}"
        
        data_id = response.json()['data_id']
        result_url = f'https://api.metadefender.com/v4/file/{data_id}'
        
        # Check results with timeout
        timeout = 60  # 1 minute timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = requests.get(result_url, headers=headers, timeout=30)
            
            if result.status_code == 200 and result.json().get('scan_results', {}).get('scan_all_result_a'):
                results = result.json()['scan_results']
                return (f"🧪 <strong>MetaDefender:</strong><br>"
                        f"Result: {results['scan_all_result_a']}<br>"
                        f"Detection Ratio: {results['total_detected_avs']}/{results['total_avs']}<br>"
                        f"<a href='https://metadefender.opswat.com/results#!/file/{data_id}/regular/overview' target='_blank'>View Full Report</a>")
            
            time.sleep(5)
        
        return "⚠️ MetaDefender timed out (1 minute). Results may still be processing."
    except requests.exceptions.Timeout:
        return "⚠️ MetaDefender connection timed out."
    except Exception as e:
        return f"❌ MetaDefender scan failed: {e}"

def explain_with_ollama(result_text):
    try:
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": f"Analyze this antivirus report and summarize the findings in simple terms:\n{result_text}",
            "stream": False
        }
        response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=30)
        return response.json().get('response', "⚠️ AI analysis not available.")
    except Exception as e:
        return f"⚠️ AI analysis error: {e}"

# Utility functions
def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', name)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Start the app
if __name__ == '__main__':
    app.run(debug=True)