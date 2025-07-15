🔐 Network Packet Sniffer & Threat Detector
A full-stack network monitoring system that captures live packets, analyzes them using a trained ML model, flags suspicious traffic, and displays threat logs in a sleek React dashboard. Built using Python, Scapy, Flask, SQLite, and React.

🚀 Features
📡 Live Packet Sniffing with Scapy

🧠 ML-based Traffic Classification (benign vs suspicious)

🌐 GeoIP Lookup of attacker IPs (country + city)

🛡️ VirusTotal API Integration for malicious IP detection

💾 PCAP Export for offline Wireshark analysis

🧱 SQLite Logging of detected threats

🌍 React Frontend with auto-refresh & real-time threat log table

⚙️ Flask REST API to manage sniffer, logs, and exports

📂 Project Structure

├── backend/
│   ├── predictor.py          # Packet sniffer + ML prediction logic
│   ├── app.py                # Flask API
│   ├── threat_log.db         # SQLite DB storing threats
│   ├── model/                # Trained model + encoders
│   ├── MMDB/                 # GeoLite2 IP database
├── frontend/
│   ├── src/App.js            # React app
│   ├── src/App.css           # UI styling
├── output/                   # Auto-exported PCAP files
├── packet_dataset.csv        # Training data
├── README.md


🛠️ Tech Stack
Backend: Python, Scapy, Scikit-learn, Flask, SQLite, GeoIP2
Frontend: React.js, JavaScript, HTML, CSS
APIs: VirusTotal, GeoLite2 (MaxMind)

🔧 Setup Instructions
1. Clone the Repo
git clone https://github.com/yourusername/network-sniffer.git
cd network-sniffer

3. Backend Setup

cd backend
pip install -r requirements.txt
python app.py
Make sure to place your GeoLite2-City.mmdb file in the MMDB/ folder.

3. Frontend Setup
cd frontend
npm install
npm start
App runs at: http://localhost:3000
Backend API runs at: http://localhost:5000

📊 Sample Log Entry
ID	Source IP	Destination IP	Reason	Country	City
47	104.18.32.47	192.168.0.106	ML: Suspicious pattern	United States	Des Moines

✅ To Do / Improvements
Add real-time charts (threat count over time)

IP filtering or search bar

Blacklist/whitelist manager

Telegram/Discord alert integration
