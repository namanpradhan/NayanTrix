# 🛡️ NayanTrix - Advanced Web-Based Virus Scanner

**NayanTrix** is a modern, dual-engine web antivirus solution that allows users to upload and scan files using both **ClamAV** (for local scanning) and **VirusTotal API** (for cloud-based scanning). Built using **Python**, **Flask**, and modern UI design, NayanTrix combines speed and reliability with detailed malware reporting.

---

## 🚀 Features

- 🔎 **Local Virus Scanning** with ClamAV
- ☁️ **Cloud-Based Detection** using VirusTotal API
- 📊 **Detailed Scan Reports** with timestamps and detection summaries
- 🎨 **Modern UI** with background images and responsive layout
- 🧹 **Auto-Cleans Up Uploaded Files** after scan

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
### 5. Add Your VirusTotal API Key

In app.py, replace the placeholder key:
```
VIRUS_TOTAL_API_KEY = 'YOUR_API_KEY_HERE'
```
### 6.Run
```
Python app.py 
```
