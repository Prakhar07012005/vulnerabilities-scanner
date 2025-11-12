# 🛡️ Network Security Scanner

███████╗███╗ ██╗███████╗████████╗██╗ ██╗ █████╗ ██████╗ ██╔════╝████╗ ██║██╔════╝╚══██╔══╝██║ ██║██╔══██╗██╔══██╗ █████╗ ██╔██╗ ██║███████╗ ██║ ██║ █╗ ██║███████║██████╔╝ ██╔══╝ ██║╚██╗██║╚════██║ ██║ ██║███╗██║██╔══██║██╔═══╝ ███████╗██║ ╚████║███████║ ██║ ╚███╔███╔╝██║ ██║██║ ╚══════╝╚═╝ ╚═══╝╚══════╝ ╚═╝ ╚══╝╚══╝ ╚═╝


> **A Python-based tool to scan networks, discover hosts, analyze open ports, detect services, and highlight potential vulnerabilities.**  
> Built with a focus on **clarity, modularity, and real-world impact**.

---

## 🚀 Badges
![Python](https://img.shields.io/badge/python-3.10-blue.svg)  
![License](https://img.shields.io/badge/license-MIT-green.svg)  
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)  

---

## 🔎 How It Works (Step by Step)

1. **Target Input**  
   - User provides IP/domain/subnet → validated by `ipaddress`.  

2. **Host Discovery**  
   - ICMP/ARP requests via `scapy`.  
   - Active hosts added to scan list.  

3. **Port Scanning**  
   - TCP/UDP probes via `socket`.  
   - Multi-threading (`concurrent.futures`) speeds up scanning.  

4. **Service Detection**  
   - Banner grabbing with `socket` + `requests`.  
   - Services & versions identified.  

5. **Vulnerability Checks**  
   - Rule-based detection (default ports, weak services).  
   - Extendable with CVE API queries.  

6. **Report Generation**  
   - JSON/HTML reports via `json`, `jinja2`, `pandas`.  
   - Console output styled with `rich` + `colorama`.  

---

## 📚 Libraries Used
- **Networking:** `socket`, `scapy`, `ipaddress`  
- **Performance:** `threading`, `concurrent.futures`, `asyncio`  
- **Data Handling:** `json`, `pandas`, `jinja2`  
- **User Experience:** `argparse`, `colorama`, `rich`, `tabulate`  
- **Optional Enhancements:** `requests`, `logging`  

---

## ⚙️ Installation
```bash
git clone https://github.com/your-username/network-security-scanner.git
cd network-security-scanner
pip install -r requirements.txt

python scanner.py --target 192.168.1.1
python scanner.py --target 192.168.1.0/24
python scanner.py --target 192.168.1.1 --ports 22,80,443
python scanner.py --target 192.168.1.1 --output report.html

📂 Project Structure
network-security-scanner/
│── scanner.py          # Main script
│── modules/            # Scanning logic
│── reports/            # Generated reports
│── requirements.txt    # Dependencies
│── README.md           # Documentation
│── images/             # Screenshots
📸 Screenshots
Scanner Running

Sample Report

🔮 Future Enhancements
🌐 Web-based dashboard with interactive visualizations

📈 Real-time monitoring with glowing trails

🔐 CVE database integration

⚡ Faster multi-threaded scanning

👨‍💻 About Me
Hi, I’m Prakhar 👋

B.Tech IT (Graduating June 2026)

Passionate about robust logic, clean code, and scalable dashboards

Exploring opportunities in network security, backend engineering, and government tech roles

📫 Connect with me on LinkedIn or check out my other projects on GitHub.

🔒 Disclaimer
This tool is intended only for ethical security testing and learning purposes. Unauthorized use on networks without permission is illegal.
