# 🛡️ NayanTrix - AI-Powered Web Antivirus Scanner

**NayanTrix** is a cutting-edge, AI-enhanced web-based virus scanner built using Python and Flask. It integrates ClamAV for fast local malware detection and VirusTotal API for multi-engine cloud scanning. What sets NayanTrix apart is its built-in NayanTrix AI, which provides clear, human-readable explanations of scan results — helping users understand potential threats and how to respond.

---

## 🚀 Features

-⚡ Dual-engine scanning: Local (ClamAV) + Cloud (VirusTotal)

-🧠 NayanTrix AI: Explains scan results in simple, actionable language

-📄 Detailed malware reporting with detection breakdown

-🌐 Modern web interface built with Flask + responsive UI

-🛡️ Secure file handling and permission management

-🧪 Real-time system checks for scanning engines and AI readiness

---

## 🧱 Technologies Used

- **Backend**: Python, Flask
- **Scanning**: ClamAV via pyClamd, VirusTotal Public API
- **Frontend**: HTML5, CSS3, JavaScript
- **Styling**: Custom CSS + modern design patterns

---

## 🧰 Requirements

- Python 3.6+
- ClamAV installed and running (`clamd`)
- A VirusTotal API Key (free-tier works)
- Git

---

## 🧪 Setup Instructions

### 1. Clone the Repository

```
git clone https://github.com/namanpradhan/NayanTrix.git
cd NayanTrix 

```
### 2. Create a Virtual Environment
```
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


### 5. AI Setup (e.g., for Ollama + LLaMA/Gemma Support)

```
chmod +x setup.sh
./setup.sh
```
### 6. Add Your VirusTotal API Key

In app.py, replace the placeholder key:
```
VIRUS_TOTAL_API_KEY = 'YOUR_API_KEY_HERE'
```
### 7.Run
```
Python app.py 
```
