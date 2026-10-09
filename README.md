# 🛡️ AI-Powered Automated Threat Detection & Real-Time Anomaly Analysis in Encrypted Network Traffic

An enterprise-grade **Encrypted Traffic Analytics (ETA)** and **Security Operations Center (SOC)** defense platform. Analyzes high-speed encrypted channels (**TLS 1.2 / TLS 1.3, HTTPS, SSH, DNS-over-HTTPS, and Tor**) in real-time **without payload decryption** or breaking privacy/encryption integrity.

---

## 🌟 Key Features

1. **Dual-Stage AI Detection Engine**:
   - **Unsupervised Anomaly Detection (Isolation Forest)**: Calibrated against normal TLS baseline traffic to detect zero-day anomalies, unknown evasive protocols, and outlier sessions.
   - **Supervised Encrypted Threat Classifier (Random Forest Ensemble)**: Multi-class classifier trained on statistical flow behaviors, distinguishing:
     * `BENIGN_WEB`: Standard HTTPS browsing (Google, GitHub, Microsoft 365, Wikipedia).
     * `BENIGN_STREAMING`: Video/Audio conferencing and media streams (Netflix, Zoom, YouTube).
     * `C2_BEACONING`: Command & Control heartbeat polling (Cobalt Strike Malleable C2, Sliver, Metasploit HTTPS).
     * `DATA_EXFILTRATION`: Stealth outbound encrypted exfiltration (S3 bucket dumps, Mega, unauthorized VPS uploads).
     * `TOR_PROXY_TUNNEL`: Tor onion routing circuits and multi-hop obfuscated proxy tunnels.
     * `DOH_DATA_TUNNEL`: DNS-over-HTTPS covert data exfiltration and DGA beaconing.
     * `TLS_DDOS_FLOOD`: High-rate TLS handshake exhaustion and SSL flood attacks.

2. **Sequence & Cryptographic Telemetry (26 Features)**:
   - **Sequence of Packet Lengths and Times (SPLT)**: Captures packet length dynamics, bimodal ACK-to-MTU ratios, and directional flow patterns.
   - **Producer-Consumer Ratio (PCR)**: Computes byte asymmetry: $\text{PCR} = \frac{\text{Bytes}_{fwd} - \text{Bytes}_{bwd}}{\text{Bytes}_{fwd} + \text{Bytes}_{bwd}} \in [-1.0, 1.0]$.
   - **Inter-Arrival Time (IAT) Jitter Analysis**: Detects automated heartbeat beaconing ($\text{Jitter} < 0.15$).
   - **JA3 / JA4 Fingerprinting**: Hashes ClientHello SSLVersion, Ciphers, Extensions, Elliptic Curves, and EC Formats to match known adversary tools.
   - **Shannon Entropy Analysis**: Detects Domain Generation Algorithms (DGA) and base32/hex encrypted DNS tunneling subdomains.

3. **Explainable AI (XAI)**:
   - Generates transparent, human-auditable reasoning for every flagged flow (e.g. *"Periodic Beaconing Heartbeat detected: IAT Jitter = 0.04; JA3 matched Cobalt Strike profile"*).

4. **Automated SOAR Mitigation & Response**:
   - Live IP Quarantine registry.
   - Instant dynamic firewall rule generation (`netsh advfirewall` for Windows and `iptables` for Linux).
   - Direct mapping to the **MITRE ATT&CK Framework** (T1071.001, T1041, T1090.003, T1071.004, T1498.001).

5. **Benchmark Datasets & Model Retraining Studio**:
   - Built-in real-world security benchmark datasets (CTU-13 Botnet TLS, CIRA-CIC-DoH Tunneling, ISCX Tor/VPN, Enterprise Baseline, Master Unified ETA).
   - Attack-specific PCAPs for every threat category.
   - Interactive model evaluation with confusion matrices and per-class classification reports.
   - Live model retraining and custom CSV dataset ingestion.

6. **Multi-Mode Operations**:
   - **⚡ Real-Time Live Traffic Stream**: Interactive real-time streaming with one-click attack injection buttons.
   - **📁 PCAP / PCAPNG Forensics**: Ingestion of real packet captures with TCP flow reconstruction and TLS ClientHello extraction.
   - **📊 Benchmark Datasets & Model Training Lab**: Data explorer, correlation heatmaps, model evaluation, and retraining.
   - **🧪 Interactive Sandbox**: Parameter tuning to test anomaly sensitivity and edge cases.
   - **🛡️ Active Defense Console**: One-click IP blocking and perimeter rule deployment.

---

## 📊 Built-In Security Benchmark Datasets

| Dataset | Records | Focus & Categories | Origin / Citation |
| :--- | :---: | :--- | :--- |
| **Master Unified ETA Benchmark** | `7,000` | All 7 Classes (Benign Web/Media, C2, Exfil, Tor, DoH, DDoS) | Aggregated ETA Consortium |
| **CTU-13 Botnet TLS & C2** | `3,500` | Cobalt Strike, Emotet, TrickBot, Neris C2 vs Benign | CTU University / Stratosphere IPS |
| **CIRA-CIC-DoH Encrypted Tunneling** | `3,200` | Covert DNS2TCP, Iodine, dnscat2 data exfiltration vs DoH | University of New Brunswick / CIRA |
| **ISCX Tor & VPN Obfuscation** | `3,000` | Tor Onion Routing circuits, SSL VPN tunnels vs native HTTPS | UNB Institute for Cybersecurity (ISCX) |
| **Enterprise TLS 1.3 Clean Baseline** | `2,500` | Microsoft 365, Google Workspace, GitHub, Zoom, AWS API | Corporate Perimeter Telemetry |

### 📁 Pre-Generated Attack PCAP Captures
The `datasets/pcaps/` folder includes raw `.pcap` capture files ready for one-click forensics:
- `c2_cobaltstrike_beacon.pcap`
- `data_exfiltration_tls.pcap`
- `tor_onion_proxy.pcap`
- `doh_covert_tunnel.pcap`
- `benign_enterprise_tls.pcap`

---

## 🚀 Quick Start Guide

### 1. Requirements & Dependencies
Ensure Python 3.10+ is installed. The required packages are:
- `streamlit`
- `scikit-learn`
- `pandas`
- `numpy`
- `scapy`
- `plotly`
- `joblib`

### 2. Run the Cyber Defense Dashboard
Launch the interactive Streamlit SOC dashboard:
```powershell
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### 3. Run Automated Tests
Execute the unit and integration test suite (8 tests covering detection, feature extraction, datasets, and PCAPs):
```powershell
python test_detection.py
```

---

## 📁 Repository Structure

```
AI_Threat_Detection/
├── core/
│   ├── __init__.py
│   ├── tls_fingerprint.py       # JA3 hashing, signature lookup, Shannon entropy & DGA scoring
│   ├── feature_extractor.py     # 26-feature extraction engine (SPLT, PCR, IAT, Jitter, Entropy)
│   ├── ai_engine.py             # Isolation Forest + Random Forest classifier + XAI engine
│   ├── dataset_manager.py       # Dataset catalog, data synthesis, model evaluation & retraining
│   ├── traffic_generator.py     # Real-time traffic stream generator & attack injector
│   ├── pcap_analyzer.py         # Scapy PCAP/PCAPNG parser & flow reconstructor
│   └── mitigation_engine.py     # Automated SOAR rules, firewall synthesis, MITRE ATT&CK mapping
├── datasets/                    # Benchmark datasets & raw network captures
│   ├── master_unified_eta.csv   # 7,000 flow benchmark dataset
│   ├── ctu13_botnet_tls.csv     # CTU-13 Botnet TLS & C2 dataset
│   ├── cira_cic_doh_tunneling.csv # CIRA-CIC-DoH covert tunneling dataset
│   ├── iscx_tor_vpn.csv         # ISCX Tor & VPN obfuscation dataset
│   ├── enterprise_tls_baseline.csv # Legitimate corporate baseline dataset
│   └── pcaps/                   # Pre-generated attack PCAPs for forensic testing
│       ├── c2_cobaltstrike_beacon.pcap
│       ├── data_exfiltration_tls.pcap
│       ├── tor_onion_proxy.pcap
│       ├── doh_covert_tunnel.pcap
│       └── benign_enterprise_tls.pcap
├── app.py                       # Streamlit SOC Command Center Dashboard
├── test_detection.py            # Complete test suite (8 tests covering all modules)
├── sample_traffic.pcap          # Combined sample capture for instant PCAP forensic testing
└── README.md                    # Project documentation
```

---

## 📊 MITRE ATT&CK Threat Mapping

| Threat Category | Severity | MITRE Tactic | Technique ID | Technique Name |
| :--- | :---: | :--- | :--- | :--- |
| **C2 Beaconing** | `CRITICAL` | Command & Control | T1071.001 | Web Protocols (TLS/HTTPS) |
| **Data Exfiltration** | `CRITICAL` | Exfiltration | T1041 | Exfiltration Over C2 / Web Channel |
| **Tor Proxy Tunnel** | `HIGH` | Defense Evasion | T1090.003 | Multi-hop Proxy (Tor / Onion Routing) |
| **DoH Data Tunnel** | `HIGH` | Command & Control | T1071.004 | DNS over HTTPS Covert Channel |
| **TLS DDoS Flood** | `MEDIUM` | Impact | T1498.001 | Network Denial of Service: Direct Flood |
| **Benign Web / Media**| `BENIGN` | None | N/A | Clean Encrypted Enterprise Traffic |
