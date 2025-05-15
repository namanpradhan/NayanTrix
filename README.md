# 🛡️ NayanTrix - Advanced Multi-Engine Malware Scanner

**NayanTrix** is an Ai-Powered , web-based virus scanner built with Python and Flask. It integrates ClamAV for fast local malware detection, VirusTotal, MetaDefender, and Hybrid Analysis for multi-engine cloud scanning, and YARA for advanced pattern matching. What sets NayanTrix apart is its built-in NayanTrix AI, which provides human-readable explanations of scan results — helping users understand threats and take informed action.

---

## 🚀 Features

⚡ Multi-engine scanning: Local (ClamAV) + Cloud APIs (VirusTotal, MetaDefender, Hybrid Analysis)

🔍 YARA scanning: Advanced pattern matching with custom rules

🧠 NayanTrix AI: Explains results using LLMs for easy understanding

📄 Comprehensive reports: Detection breakdown, scan metadata, and AI insights

🌐 Modern web interface: Flask-powered with responsive, sleek UI

🔐 Secure file handling: Temporary storage, permission controls, and system checks

🧪 Real-time status: Verifies scanning engines and AI availability



---

## 🧱 Technologies Used

Backend: Python 3, Flask

Scanning: ClamAV (via pyClamd), VirusTotal API, MetaDefender API, Hybrid Analysis API, YARA

Frontend: HTML5, CSS3, JavaScript

AI: Ollama (Gemma 3B/1B or LLaMA 2 via local models)



---

## 🧰 Requirements

Python 3.6+

ClamAV (clamd) installed and running

YARA installed

VirusTotal API Key

MetaDefender API Key

Hybrid Analysis API credentials

Git


---

## 🧪 Setup Instructions

### 1. Clone the Repository

```
git clone https://github.com/namanpradhan/NayanTrix.git
cd NayanTrix 

```
### 2. Create a Virtual Environment
```
sudo apt install python3 python3-pip
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# OR
venv\Scripts\activate     # Windows
```
### 3. Install Python Dependencies
```
pip install -r requirements.txt
```
### 4. Set Up ClamAV

Linux (Debian/Ubuntu):
```
sudo apt update
sudo apt install clamav clamav-daemon
sudo freshclam
sudo systemctl start clamav-daemon
```
### If you Get Any error Follow these Steps: 
```
sudo systemctl stop clamav-freshclam
sudo chown -R clamav:clamav /var/log/clamav
sudo chmod -R 755 /var/log/clamav
sudo freshclam
sudo systemctl start clamav-freshclam
```
Ensure clamd is running. Check with:
```
ps aux | grep clamd
```
macOS:
```
brew install clamav
```

Windows:
Download and install ClamAV for Windows


### 5. AI Setup 

```
chmod +x setup.sh
./setup.sh
```
### 6. Add Your VirusTotal API Key

In app.py, replace the placeholder key:
```
VIRUS_TOTAL_API_KEY = 'YOUR_API_KEY_HERE'
METADEFENDER_API_KEY = 'YOUR_API_KEY'
HYBRID_ANALYSIS_API_KEY = 'YOUR_API_KEY'
HYBRID_ANALYSIS_SECRET = 'YOUR_SECRET'

```
### 7.Run
```
python app.py 
```
