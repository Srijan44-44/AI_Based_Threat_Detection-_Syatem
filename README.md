🚀 Network Traffic Monitoring & AI-Based Threat Detection
A Python-based system that captures TCP, UDP, HTTP, HTTPS, ARP, ICMP, DNS packets, extracts packet details, and uses AI (Isolation Forest) to classify packets as Safe or Threat.

📌 Features
✔️ Live Packet Capture → Captures real-time network traffic
✔️ Supports IPv4 & IPv6 → Extracts both IPv4 and IPv6 addresses
✔️ Detects Multiple Protocols → TCP, UDP, HTTPS, ARP, ICMP, DNS
✔️ AI-Based Threat Detection → Uses Machine Learning (Isolation Forest)
✔️ Automatic Threat Classification → Flags packets as "Threat" or "Safe"
✔️ Saves Data in CSV Format → Analyzes traffic logs for security monitoring

🛠 Installation
Ensure you have Python installed, then install dependencies:
pip install -r requirements.txt



🚀 Usage
1️⃣ Run the script to start live packet capture:
python final.py


2️⃣ The script will:
- Capture packets for 40 seconds
- Extract IPs, protocols, and content details
- Classify packets using AI
- Save results in a CSV file (network_traffic_TIMESTAMP.csv)
3️⃣ Open the CSV file to view classified traffic:
- "Threat" → Possibly malicious or suspicious
- "Safe" → Normal network activity

🖥 System Requirements
- OS: Windows, macOS, Linux
- Python: 3.7+
- Dependencies: PyShark, Pandas, Scikit-Learn

🔍 Example Output
| No. | Time | Source IP | Destination IP | Protocol | Length | Info | Threat Classification | 
| 1 | 12:05:34.123 | 192.168.1.10 | 172.217.164.110 | TCP | 55 | TLS Handshake | Safe | 
| 2 | 12:05:36.543 | 2401:4900:45a4::f1 | 2607:f8b0:4000::200e | HTTPS | 122 | Encrypted Session | Threat | 
| 3 | 12:05:38.678 | 192.168.1.15 | 8.8.8.8 | DNS | 74 | DNS Query: google.com | Safe | 



⚠️ Important Notes
- Requires admin/root privileges for live packet capture. Run with:
- Windows: Right-click Command Prompt → Run as Administrator
- Linux/macOS: Use sudo python final.py
- Some packets may appear as "Encrypted or Unreadable Data", especially TLS/HTTPS traffic.
- Modify the script to adjust packet timeout or protocol filters.


