
# T-Pot Honeypot: Real-Time Attack Detection in Azure

## Author
Wilton Lizardo

---

## 🛡️ Project Overview

This project explores the deployment of **T-Pot**, a multi-honeypot platform, on **Microsoft Azure** to capture and analyze real-world cyberattacks. Using T-Pot’s integrated **ELK stack (Elasticsearch, Logstash, Kibana)** and tools like **Suricata** and **CyberChef**, we were able to gain actionable threat intelligence by simulating a vulnerable cloud environment.

---

## 🎯 Goals

- Develop hands-on skills in honeypot deployment and attack analysis.
- Detect and classify cyberattacks in real-time.
- Gain insights into threat vectors, malicious IPs, and commonly targeted services.
- Learn how to monitor and visualize attacks using T-Pot’s tools.

---

## 🧪 Methodology

### 🔧 Environment Setup

- **Platform**: Microsoft Azure
- **VM OS**: Ubuntu 22.04 LTS
- **Specs**: 4 vCPUs, 16GB RAM, 256GB SSD
- **Honeypot System**: T-Pot 24.04.1

### 🌐 Network Configuration

- **NSG Settings**:
  - Port 22 (SSH): Allowed (restricted to personal IP)
  - Ports 1–65535: Temporarily allowed (to simulate open attack surface)

---

## 📥 Installation Steps

1. **Create VM** in Azure with required specs.
2. **Open Putty**, SSH into the server use VM IP and Port 22.
3. **Update System**:
   ```bash
   sudo apt update
   ```
4. **Clone T-Pot**:
   ```bash
   git clone https://github.com/telekom-security/tpotce
   ```
5. **Install T-Pot**:
   ```bash
   cd tpotce
   sudo ./install.sh
   ```
6. **Select installation type** (e.g., Hive)
7. **Set username and password**
8. **Restart VM**
9. **Access T-Pot Web UI**:
   ```
   https://<VM-IP>:64297
   ```

---

## 📊 T-Pot Features Used

- **Kibana** – Attack data dashboards
- **Elasticvue** – Elasticsearch viewer
- **CyberChef** – Data forensics
- **Spiderfoot** – OSINT analysis
- **Attack Map** – Real-time global attack visualization

---

## 🔍 Observations & Key Findings

### 🔥 Attack Volume (15 Hours of Monitoring)

- **Total Attacks**: 70,000+
- **Top Honeypots Attacked**:
  - Cowrie (SSH): 12,000+
  - Honeytrap: 7,000+
  - Dionaea: Malware collection
- **Top Ports Attacked**: 50995, 58000, 20256, 81
- **Top Attacking Countries**: USA, UK, Brazil, Hong Kong
- **Top ASNs**: OVH SAS, Google Cloud, DigitalOcean, ENTEL Chile

### 🧠 Suricata IDS Alerts

- Exploits detected: Nmap, SMB exploits (EternalBlue), DoublePulsar
- Old CVEs still being exploited: CVE-2002-001, CVE-2019-119

---

## 👥 Attacker Behavior Analysis

- **Common Usernames**: `root`, `admin`, `postgres`, `docker`, `gitlab-runner`
- **Common Passwords**: `123456`, `password`, `admin123`, `qwerty123`, `!QAZ@WSX`
- **Major Sources**: Cloud infrastructure abused for automated attacks
- **Attack Type**: Mostly opportunistic and automated scanning

---

## 🔒 Security Recommendations

1. **Restrict Exposure**:
   - Disable public access to SSH, SMB, SIP, RDP unless required.
   - Use VPN/Bastion host.

2. **Strengthen Credentials**:
   - Use SSH keys, enforce MFA.
   - Disable password login where possible.

3. **Enable Intrusion Detection**:
   - Use Suricata or Fail2Ban.
   - Send logs to SIEM (Azure Sentinel, Wazuh, etc.)

4. **Patch Regularly**:
   - Mitigate known CVEs.
   - Harden RDP/SIP services.

5. **Leverage Threat Intelligence**:
   - Block known malicious ASNs.
   - Use geo-blocking, rate-limiting, and automated responses.

---

## 📌 Conclusion

This project demonstrated the feasibility and value of using T-Pot in Azure to:
- Simulate vulnerable services
- Capture real-world threats
- Visualize and analyze attacker behavior

It emphasizes that **public-facing systems are always under threat**, and proactive defenses like honeypots, IDS, and threat intelligence are essential for any cybersecurity strategy.

---

## 📎 Resources

- T-Pot GitHub: [https://github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce)
- Elastic Stack: [https://www.elastic.co/](https://www.elastic.co/)
- Suricata IDS: [https://suricata.io/](https://suricata.io/)
